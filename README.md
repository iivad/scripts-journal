A public repository for documenting cybersecurity and networking scripts.
Each entry is clean, professional, and collaborative — developed through step-by-step troubleshooting with GPT-5 guidance.
# scripts-journal

A public repository for documenting practical cybersecurity and networking scripts.

## Current Entry
- **ICMP Sniffer** (`labs/pyshark/icmp_sniffer.py`):  
  Built with PyShark + tshark. Features:
  - Aligned packet output (`src → dst type id seq`)
  - Graceful shutdown (Ctrl+C safe)
  - Interface auto-detection
  - Optional PCAP saving

## Run
```bash
sudo -E $(python -c 'import sys,os;print(sys.executable)') labs/pyshark/icmp_sniffer.py --pretty -i eth0 -c 5
