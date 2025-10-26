# Network Intrusion Detection and Prevention System (NIDPS)

This project implements a Network-based Intrusion Detection and Prevention System using Python and Scapy. The Intrusion Detection System detects malicious network activities through signature and anomaly-based detection techniques, logs detected attacks, and provides a CLI-based interface for management and monitoring.

## Features

- **Real-time traffic monitoring** across all network interfaces
- Eg - lo(localhost),eth0 etc..
- **Intrusion detection** for multiple attack types:
  - Port scanning (Multiple Port Scanning, Sequential Port Scanning)
  - OS fingerprinting attempts.
  - SYN flood attacks.(DDOS Attack).
- **Automatic intrusion prevention** using iptables
- **Comprehensive logging** of all detected intrusions
- **Management interface** for system control and monitoring

### Additional Features

- We have added a new Attack``(DDOS Attack (SYNC Flood))`` detection which is not mentioned asked in assignment.
-  Given an option for the user to get the detailed summary of the intrusion detections so far.
    Eg - 
``` 
==== Intrusion Summary ====
Total Intrusions Detected: 8

By Type:
• Port Scanning: 3
• SYN Flood: 4
• OS Fingerprinting: 1

Top Attacker IPs:
• 142.250.195.78: 2 attacks
• 10.3.8.108: 2 attacks
• 127.0.0.2: 2 attacks
• 10.42.0.19: 2 attacks

Most Targeted Ports:
• Port 10: 4 times
• Port 443: 2 times
• Port 57822: 1 times
• Port 57826: 1 times
• Port 57830: 1 times
===========================

```
- This IDS is used to detect(sniff) the packets in all types of interfaces(lo, eth0, etc..)
- We designed our IDS and test script such that the attacker can attack from the local system(`we used spoofing here` for easy detection of IP) and also he can run the scripts from the remote system.  
- We used Threading and locks for thread-safe operation.

## Requirements

- Python 3.8+
- Libraries Used: Scapy 2.5.0+
- Linux environment with iptables support
- Root privileges (for packet capture and iptables manipulation)

## Assumptions for Intrusion Detection

1) For Port Scanning, we made an assumption that In 15 s, if there are 6 portscans then it is logged as Issue.
2) For OS fingerprinting- we made an assumtion that In 20 s if there are 5 combinations of flags , then it is logged as Issue.
3) For SYN Flooding Attack - we made an assumption that In 10 s, if more than 10 SYNC requests then logged as Issue.
4) For Network Traffic Display, we are displaying the 30 sec live traffic(TCP packets as mentioned in assignment). Displaying Traffic is independent of whether IDS is running or not.
5) If an IP is blocked, then we are not allowing further malware attacks from that particular IP.
6) We are clearing the ids.log file when we are newly starting the program.
7) We are considering last 50 packets for Intrusion Detection.

- For Testing
   -  We first tried bash scripts for testing( using nmap, hping3) but later we integrated all into a single python code which only takes the help of SCAPY.
    - For testing Network Traffic Flow, I used the below commands which helps to generate the TCP packets. but sometimes may  not work when we connected to authorized networks(`Used iproute to clarify this`)
        ``` 
        telnet google.com 80
        GET / HTTP/1.1 
        ```


### Running the NIDPS

Run the NIDPS script with root privileges:

```
sudo python3 main.py
```

The CLI menu provides the following options:
1. Start IDS
2. Stop IDS
3. View Live Traffic
4. View Intrusion Logs
5. Display Blocked IPs
6. Clear Block List
7. Unblock an IP
8. Intrusion Summary
9. Exit

### Running the Attacker Tool (For Testing)

The project includes an attacker script for testing the NIDPS:

```
sudo python3 attacker.py
```

You can choose the interface driven attacker.py with options as

 "  P  Sequential Port Scan\n"
    "  R  Random Port Scan\n"
            "  O  OS Fingerprint Probe\n"
            "  S  SYN Flood Attack\n"
            "  N  Normal Traffic\n"
            "  A  All attacks\n"
            "  Q  Quit"

You can also run it with command-line arguments:
```
sudo python3 attacker.py --dst 192.168.1.100 --port-scan --sequential
sudo python3 attacker.py --dst 192.168.1.100 --port-scan --random
sudo python3 attacker.py --dst 192.168.1.100 --os-fp
sudo python3 attacker.py --dst 192.168.1.100 --syn-flood
sudo python3 attacker.py --dst 192.168.1.100 --normal
sudo python3 attacker.py --dst 192.168.1.100 --all --sequential
```

## Detection Logic

### Port Scanning Detection
- Detects when a host attempts to connect to more than 6 different ports within 15 seconds
- Identifies sequential port access patterns.
- Blocks the attacker IP and logs details.

### OS Fingerprinting Detection
- Identifies IPs that send 5 or more different TCP flag combinations (SYN, ACK, FIN) within 20 seconds
- Blocks the attacker IP and logs the details.
### SYN Flood Detection
- Detects rapid SYN packet transmission (10+ packets in 5 seconds)
- Blocks the attacker IP and logs the attack details

## Log Format

Each intrusion is logged in the following format:
```
Date(DD-MM-YY) Time(HH:MM:SS) — Intrusion Type — Attacker IP — Details — Time Span Of Attack
```
Eg: 
06-04-25 23:10:15 — SYN Flood — 10.42.0.223 — Destination Port: 443 — SYN count: 10 — 4s
06-04-25 23:38:02 — Port Scanning — 172.64.155.209 — 42040, 42052, 42062, 42072, 42076, 59324, 59334 — 9s
06-04-25 23:38:02 — SYN Flood — 10.1.37.87 — Destination Port: 443 — SYN count: 10 — 4s
06-04-25 23:46:18 — Port Scanning — 172.217.31.195 — 33894, 40598, 43242, 55276, 55288, 55298, 56460 — 12s.


## Implementation Details

The NIDPS uses:
- AsyncSniffer from Scapy for non-blocking packet capture. by this we have sniffed the packets from various interfaces(lo,etho, etc..). This we have implemented using ` get_if_list` from scapy.
- Threading and locks for thread-safe operation
- We used Time windowing algorithms for temporal pattern detection.(Port Scan, Os fingerprint attack)
- We used Subprocess for interaction with the iptables. Used iptables to block and unblock the particular IP.
- We tested the normal traffic also using Simulation of normal traffic: ACK and PSH flags

## Contributors

2024202016 - Annam Rajender Reddy
2024202021 - Thammi Sai Charan
2024202027 - Aditya Sangana
