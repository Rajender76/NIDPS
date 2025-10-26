#!/usr/bin/env python3

import os, sys, time, threading, subprocess
from datetime import datetime
from scapy.all import AsyncSniffer, sniff, IP, TCP, get_if_list
from collections import Counter

# ───────────── configuration ─────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "ids.log")

# We are capturing on all available interfaces.
available_ifaces = get_if_list()
IFACE_IDS = available_ifaces      # for IDS engine
IFACE_LIVE = available_ifaces     # for live monitor

PORT_SCAN_WINDOW, PORT_SCAN_THRESH = 15, 6   # seconds, >6 ports
OS_FP_WINDOW,   OS_FP_THRESH       = 20, 5   # seconds, ≥5 combos
# ─────────────────────────────────────────

if os.geteuid() != 0:
    print("Run this script with sudo.")
    sys.exit(1)


class NIDPS:
    def __init__(self):
        self.running = False
        self.sniffers = []  
        self.port_rec, self.fp_rec = {}, {}  # detection trackers
        self.blocked_ips = set()
        self.live_pkts = []               # considering last 50 packets seen by IDS
        self.lock = threading.Lock()
        self.syn_flood_rec = {}
        open(LOG_PATH, "w").close()

    # ── IDS control ─────────────────────────────────────
    def start(self):
        if self.running:
            print("IDS already running.")
            return
        for iface in available_ifaces:
            try:
                sniffer = AsyncSniffer(iface=iface,
                                       filter="tcp",
                                       store=False,
                                       prn=self._ids_callback)
                sniffer.start()
                self.sniffers.append(sniffer)
                print(f"Started IDS sniffer on interface: {iface}")
            except Exception as e:
                print(f"Error starting sniffer on {iface}: {e}")
        if self.sniffers:
            self.running = True
            print(f"IDS started on {len(self.sniffers)} interface(s).")
        else:
            print("No valid interfaces found for IDS.")

    def stop(self):
        if not self.running:
            print("IDS is not running.")
            return
        for sniffer in self.sniffers:
            try:
                sniffer.stop(join=False)
            except Exception as e:
                print(f"Error stopping sniffer: {e}")
        self.sniffers.clear()
        self.running = False
        print("IDS stopped.")

    #IDS packet handler 
    def _ids_callback(self, pkt):
        if IP not in pkt or TCP not in pkt:
            return
        ts = time.time()

        src, dst = pkt[IP].src, pkt[IP].dst
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        flags = pkt[TCP].flags
        protocol="TCP"
        line = (f"{datetime.fromtimestamp(ts):%d-%m-%y %H:%M:%S} "
                f"{src}:{sport} -> {dst}:{dport} Protocol: {protocol} Flags:{flags}")

        with self.lock:
            self.live_pkts.append(line)
            if len(self.live_pkts) > 50:
                self.live_pkts.pop(0)

        # If the IP is already blocked, skip further detection process
        with self.lock:
            if src in self.blocked_ips:
                return

        self._detect_port_scan(src, dport, ts)
        combo = self._flag_subset(flags)
        if combo:
            self._detect_os_fp(src, combo, ts)
            self._detect_syn_flood(src, dport, combo, ts) 


    @staticmethod
    def _flag_subset(flags):
        keep = set(str(flags)) & {'S', 'A', 'F'}
        return ''.join(sorted(keep)) if keep else None

    @staticmethod
    def _fmt(pkt):
        if IP in pkt and TCP in pkt:
            ts = datetime.now().strftime("%d-%m-%y %H:%M:%S")
            protocol="TCP"
            return (f"{ts} {pkt[IP].src}:{pkt[TCP].sport}"
                    f" -> {pkt[IP].dst}:{pkt[TCP].dport} Protocol:{protocol}"
                    f" Flags:{pkt[TCP].flags}")
        return ""

    @staticmethod
    def _sequential(nums):
        return all(b - a == 1 for a, b in zip(nums, nums[1:]))

    #  detection logic
    def _detect_port_scan(self, ip, dport, ts):
        with self.lock:
            if ip in self.blocked_ips:
                return
            rec = self.port_rec.setdefault(ip, [])
            rec.append((ts, dport))
            rec[:] = [(t, p) for t, p in rec if ts - t <= PORT_SCAN_WINDOW]
            ports = {p for _, p in rec}

        if len(ports) > PORT_SCAN_THRESH:
            detail = ", ".join(str(p) for p in sorted(ports))
            if self._sequential(sorted(ports)):
                detail += " [Sequential]"
            self._log_intrusion("Port Scanning", ip, detail, rec[0][0], ts)
            self._block_ip(ip)
            with self.lock:
                rec.clear()

    def _detect_os_fp(self, ip, combo, ts):
        with self.lock:
            if ip in self.blocked_ips:
                return
            rec = self.fp_rec.setdefault(ip, [])
            rec.append((ts, combo))
            rec[:] = [(t, c) for t, c in rec if ts - t <= OS_FP_WINDOW]
            combos = {c for _, c in rec}

        if len(combos) >= OS_FP_THRESH:
            detail = ", ".join(sorted(list(combos)))
            self._log_intrusion("OS Fingerprinting", ip, detail, rec[0][0], ts)
            self._block_ip(ip)
            with self.lock:
                rec.clear()

    # Logging & prevention logic
    def _log_intrusion(self, itype, ip, detail, start_ts, end_ts):
        now = datetime.now()
        span = int(end_ts - start_ts)
        entry = (f"{now:%d-%m-%y %H:%M:%S} — {itype} — {ip} — {detail} — {span}s\n")
        print("ALERT:", entry.strip())
        with open(LOG_PATH, "a") as f:
            f.write(entry)
            f.flush()
            os.fsync(f.fileno())

    def _block_ip(self, ip):
        with self.lock:
            if ip in self.blocked_ips:
                return
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP",
                 "-m", "comment", "--comment", "NIDPS"],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            with self.lock:
                self.blocked_ips.add(ip)
            print(f"Blocked IP: {ip}")
        except subprocess.CalledProcessError as e:
            print(f"iptables error while blocking {ip}: {e}")
    
    def _detect_syn_flood(self, ip, dport, combo, ts):
        if combo != 'S':  # only SYNs
            return

        with self.lock:
            if ip in self.blocked_ips:
                return
            rec = self.syn_flood_rec.setdefault(ip, [])
            rec.append(ts)
            rec[:] = [t for t in rec if ts - t <= 5]
            
        if len(rec) >= 10:  # threshold: 10 SYNs in 5 sec
            detail = f"Destination Port: {dport} — SYN count: {len(rec)}"
            self._log_intrusion("SYN Flood", ip, detail, rec[0], ts)
            self._block_ip(ip)
            with self.lock:
                rec.clear()


    def unblock_ip(self, ip):
        max_attempts = 5
        attempts = 0
        removed = False
        while attempts < max_attempts:
            test = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP",
                 "-m", "comment", "--comment", "NIDPS"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            if test.returncode != 0:
                break
            try:
                subprocess.run(
                    ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP",
                     "-m", "comment", "--comment", "NIDPS"],
                    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                removed = True
            except subprocess.CalledProcessError as e:
                print(f"iptables error while unblocking {ip}: {e}")
                break
            attempts += 1

        with self.lock:
            if removed:
                self.blocked_ips.discard(ip)
                print(f"Unblocked IP: {ip}")
            else:
                print(f"{ip} was not in the NIDPS block list.")

    def clear_blocks(self):
        with self.lock:
            ips = list(self.blocked_ips)
        for ip in ips:
            self.unblock_ip(ip)
    
    def show_summary(self):
        if not os.path.exists(LOG_PATH):
            print("Log file does not exist.")
            return

        types = Counter()
        attackers = Counter()
        ports = Counter()
        total = 0

        with open(LOG_PATH, "r") as f:
            for line in f:
                parts = [p.strip() for p in line.strip().split("—")]
                if len(parts) < 4:
                    continue
                date_time, itype, ip, *rest = parts
                detail = " — ".join(rest)
                
                types[itype] += 1
                attackers[ip] += 1
                for p in detail.split(","):
                    for token in p.split():
                        if token.isdigit():
                            ports[token] += 1
                total += 1


        print("\n==== Intrusion Summary ====")
        print(f"Total Intrusions Detected: {total}")
        print("\nBy Type:")
        for t, count in types.items():
            print(f"• {t}: {count}")
        print("\nTop Attacker IPs:")
        for ip, count in attackers.most_common(5):
            print(f"• {ip}: {count} attacks")
        print("\nMost Targeted Ports:")
        for port, count in ports.most_common(5):
            print(f"• Port {port}: {count} times")
        print("===========================\n")

    # ── CLI utilities ──────────────────────────────────
    def live_monitor(self, duration=0):
        from scapy.all import sniff
        default_duration = 30
        if duration == 0:
            duration = default_duration

        start_ts = datetime.now()
        print(f"\n=== Live TCP Traffic — {start_ts:%d-%m-%y %H:%M:%S} (running {duration}s or Ctrl‑C) ===")

        counter = 0
        def printer(pkt):
            nonlocal counter
            counter += 1
            print(f"{counter:05d}  {self._fmt(pkt)}", flush=True)

        try:
            sniff(iface=available_ifaces,
                  filter="tcp",
                  store=False,
                  timeout=duration,
                  prn=printer)
        except KeyboardInterrupt:
            print("\nUser interrupted live view.")

        if counter == 0:
            print("(No TCP packets captured during this session)")
        print("=== End of live traffic session ===\n")

    def show_logs(self):
        with open(LOG_PATH, "r") as f:
            logs = f.read()
            print(logs if logs else "Log file is empty.")

    def show_blocks(self):
        with self.lock:
            if self.blocked_ips:
                print("Blocked IPs:")
                for ip in self.blocked_ips:
                    print(ip)
            else:
                print("No IPs are currently blocked.")


# ── CLI loop ───────────────────────────────────────────
def menu():
    print("""
==== NIDPS Menu ====
1  Start IDS
2  Stop IDS
3  View Live Traffic
4  View Intrusion Logs
5  Display Blocked IPs
6  Clear Block List
7  Unblock an IP
8  Intrusion Summary
9  Exit
""", end="Choice: ")

def main():
    ids = NIDPS()
    while True:
        menu()
        choice = input().strip()
        if choice == "1":
            ids.start()
        elif choice == "2":
            ids.stop()
        elif choice == "3":
            ids.live_monitor()
        elif choice == "4":
            ids.show_logs()
        elif choice == "5":
            ids.show_blocks()
        elif choice == "6":
            ids.clear_blocks()
        elif choice == "7":
            ip_to_unblock = input("Enter IP to unblock: ").strip()
            ids.unblock_ip(ip_to_unblock)
        elif choice == "8":
            ids.show_summary()
        elif choice == "9":
            ids.stop()
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
