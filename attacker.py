#!/usr/bin/env python3

import argparse, os, random, sys, time
from scapy.all import IP, TCP, send, conf, RandShort

SRC = "127.0.0.2"  # spoofed attacker IP (ensure this alias exists)
# DST will be set dynamically later
# DST is localhost if I run it manually
## other wise I can the ip address of this machine I am not running 
# ───────── Utility: Validate IP Format ─────────
def is_valid_ip(ip_str):
    parts = ip_str.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        n = int(part)
        if n < 0 or n > 255:
            return False
    return True

if not is_valid_ip(SRC):
    print(f"Error: Attacker IP {SRC} is not valid.")
    sys.exit(1)

# Packet Helpers 
def send_syn(port, dst):
    pkt = IP(src=SRC, dst=dst) / TCP(sport=RandShort(), dport=port, flags="S")
    send(pkt, verbose=False)

def send_flags(flagstr, dst):
    pkt = IP(src=SRC, dst=dst) / TCP(sport=RandShort(), dport=80, flags=flagstr)
    send(pkt, verbose=False)

def send_ack_psh(dst):
    # Simulate normal traffic: ACK and PSH flags
    pkt = IP(src=SRC, dst=dst) / TCP(sport=RandShort(), dport=80, flags="PA")
    send(pkt, verbose=False)

# Attack Functions
def port_scan(sequential, dst):
    print("[*] Launching port‑scan …")
    if sequential:
        ports = list(range(20, 28))  # 8 sequential ports
    else:
        ports = random.sample(range(1025, 5000), 8)
    t0 = time.time()
    for p in ports:
        # Used SYN+ACK for port scan testing to avoid SYN flood detection. Maintain Independence
        pkt = IP(src=SRC, dst=dst) / TCP(sport=RandShort(), dport=p, flags="SA")
        send(pkt, verbose=False)
        time.sleep(1)
    print(f"[+] Port‑scan done in {time.time()-t0:.1f}s (ports {ports})")

def os_fingerprint(dst):
    print("[*] Launching OS‑fingerprint probe …")
    combos = ["S", "A", "F", "SA", "SF"] 
    t0 = time.time()
    for fl in combos:
        send_flags(fl, dst)
        time.sleep(2)                # Total duration < 20 s
    print(f"[+] OS‑fingerprint done in {time.time()-t0:.1f}s")

def benign_session(dst):
    print("[*] Sending benign 3‑way handshake …")
    send_flags("S", dst)
    send_flags("SA", dst)
    send_flags("A", dst)
    print("[+] Benign session sent.")

def syn_flood(dst):
    print("[*] Launching SYN flood attack …")
    t0 = time.time()
    # Send 20 SYN packets rapidly to port 80
    for _ in range(20):
        pkt = IP(src=SRC, dst=dst) / TCP(sport=RandShort(), dport=80, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.2)
    print(f"[+] SYN flood completed in {time.time()-t0:.1f}s")

def normal_traffic(dst):
    print("[*] Simulating normal traffic …")
    t0 = time.time()
    # Send 5 normal ACK/PSH packets
    for _ in range(5):
        send_ack_psh(dst)
        time.sleep(0.5)
    print(f"[+] Normal traffic simulation done in {time.time()-t0:.1f}s")

#Interactive Menu
def interactive():
    dst = input("Enter destination IP: ").strip()
    if not is_valid_ip(dst):
        print("Invalid destination IP. Exiting.")
        sys.exit(1)
    
    while True:
        print(
            "\nSelect traffic to generate:\n"
            "  P  Sequential Port Scan\n"
            "  R  Random Port Scan\n"
            "  O  OS Fingerprint Probe\n"
            "  S  SYN Flood Attack\n"
            "  N  Normal Traffic\n"
            "  A  All attacks\n"
            "  Q  Quit"
        )
        choice = input("Choice: ").strip().upper()
        if choice == "P":
            port_scan(True, dst)
        elif choice == "R":
            port_scan(False, dst)
        elif choice == "O":
            os_fingerprint(dst)
        elif choice == "S":
            syn_flood(dst)
        elif choice == "N":
            normal_traffic(dst)
        elif choice == "A":
            port_scan(True, dst)
            time.sleep(3)
            os_fingerprint(dst)
            time.sleep(2)
            syn_flood(dst)
            time.sleep(2)
            normal_traffic(dst)
            time.sleep(2)
            benign_session(dst)
        elif choice == "Q":
            break
        else:
            print("Invalid choice.")

# ───────── Main ─────────
def main():
    parser = argparse.ArgumentParser(description="Local IDS traffic generator")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--port-scan", action="store_true", help="Simulates sequential port scan")
    group.add_argument("--random", action="store_true", help="Simulates random port scan")
    group.add_argument("--os-fp", action="store_true", help="Simulates OS fingerprinting")
    group.add_argument("--syn-flood", action="store_true", help="Simulates SYN flood attack")
    group.add_argument("--normal", action="store_true", help="Simulates normal traffic")
    group.add_argument("--benign", action="store_true", help="simulate benign handshake")
    group.add_argument("--all", action="store_true", help="simulate all attack types")
    parser.add_argument("--dst", type=str, default="127.0.0.1",
                        help="Destination IP address for traffic (default: 127.0.0.1)")
    args = parser.parse_args()

    # Validate destination IP from command-line argument.
    if not is_valid_ip(args.dst):
        print(f"Error: Destination IP {args.dst} is not valid.")
        sys.exit(1)
    dst = args.dst

    # If any flag is provided, it runs non-interactively:
    if args.port_scan or args.random or args.os_fp or args.syn_flood or args.normal or args.benign or args.all:
        if args.port_scan:
            port_scan(True, dst)
        if args.random:
            port_scan(False, dst)
        if args.os_fp:
            os_fingerprint(dst)
        if args.syn_flood:
            syn_flood(dst)
        if args.normal:
            normal_traffic(dst)
        if args.benign:
            benign_session(dst)
        if args.all:
            port_scan(True, dst)
            time.sleep(3)
            os_fingerprint(dst)
            time.sleep(2)
            syn_flood(dst)
            time.sleep(2)
            normal_traffic(dst)
            time.sleep(2)
            benign_session(dst)
        return

    # Otherwise, run interactive mode:
    interactive()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run this script with sudo.")
        sys.exit(1)
    main()
