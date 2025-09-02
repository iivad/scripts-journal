#!/usr/bin/env python3
"""
ICMP sniffer using PyShark + tshark.

- Pretty output with aligned columns: src → dst, type, id, seq
- Graceful Ctrl+C handling
- Interface auto-detect (falls back to eth0)
- Optional display filter / optional PCAP saving
"""

import argparse, os, sys, signal
from datetime import datetime

try:
    import pyshark
except Exception as e:
    print(f"[!] PyShark import failed: {e}")
    print("    Use your venv Python and ensure tshark is installed.")
    sys.exit(1)

STOP = False

def sigint_handler(*_):
    global STOP
    STOP = True
    print("\n[+] Stopping capture… please wait.")

def guess_interface():
    for name in ("eth0", "ens33", "enp0s3"):
        if os.path.exists(f"/sys/class/net/{name}"):
            return name
    return "eth0"

def main():
    p = argparse.ArgumentParser(description="ICMP sniffer using pyshark")
    p.add_argument("-i","--interface", default=guess_interface(), help="Interface")
    p.add_argument("-c","--count", type=int, default=0, help="Packet count (0=until Ctrl+C)")
    p.add_argument("--display-filter", default="icmp", help="Wireshark display filter")
    p.add_argument("--pcap", help="Write packets to this pcap file (optional)")
    p.add_argument("--pretty", action="store_true", help="Pretty-print packet summary")
    args = p.parse_args()

    if os.geteuid() != 0:
        print("[!] Capturing needs root. Re-run with sudo (preserving venv):")
        print(f"    sudo -E {sys.executable} {' '.join(sys.argv)}")
        sys.exit(1)

    print(f"[+] Interface: {args.interface}")
    print(f"[+] Display filter: {args.display_filter}")
    if args.pcap: print(f"[+] PCAP output: {args.pcap}")

    signal.signal(signal.SIGINT, sigint_handler)

    try:
        cap = pyshark.LiveCapture(
            interface=args.interface,
            display_filter=args.display_filter,
            output_file=args.pcap
        )
    except Exception as e:
        print(f"[!] Failed to start capture: {e}")
        sys.exit(1)

    print("[+] Listening… (Ctrl+C to stop)")
    seen = 0

    if args.pretty:
        print(f"{'src':<17} → {'dst':<17}  {'type':<4} {'id':<6} {'seq':<6}")

    try:
        for pkt in cap.sniff_continuously(packet_count=args.count or None):
            if STOP: break
            try:
                if args.pretty:
                    ip, icmp = getattr(pkt, "ip", None), getattr(pkt, "icmp", None)
                    if ip and icmp:
                        print(f"{ip.src:<17} → {ip.dst:<17}  {str(getattr(icmp,'type','?')):<4} "
                              f"{str(getattr(icmp,'ident','?')):<6} {str(getattr(icmp,'seq','?')):<6}")
                    else:
                        print(pkt)
                else:
                    print(pkt)
                seen += 1
            except Exception as e:
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[{ts}] [warn] packet parse error: {e}")
    finally:
        try: cap.close()
        except Exception: pass
        print(f"[+] Done. Packets seen: {seen}")

if __name__ == "__main__":
    main()
