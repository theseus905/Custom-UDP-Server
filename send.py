import pickle
import socket
import time
import random


random.seed(0x1337)


with open('payload_dump.bin') as f:
    payloads = pickle.load(f)[:250]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

for payload in payloads:
    sock.sendto(payload, ('127.0.0.1', 1337))
    time.sleep(0.001)

sock.close()
