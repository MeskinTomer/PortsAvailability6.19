from scapy import *
from scapy.layers.inet import *

TARGET_IP = "127.0.0.1"
PORT_INITIAL = 1000
PORT_END = 10000
TIMEOUT = 0.5


def check(port):
    # Construct packets
    ip = IP(dst=TARGET_IP)
    syn = TCP(dport=port, flags='S')
    # Send syn and sniff response
    response = sr1(ip/syn, timeout=TIMEOUT, verbose=0)

    if response is None:
        print(".", end="")
    elif TCP in response and response[TCP].flags & 0x04:
        print("-", end="")
    elif TCP in response and response[TCP].flags & 0x12:
        print(f"Port {port} is available")
    else:
        print(f"Port {port} status is unknown")


def main():
    for port in range(PORT_INITIAL, PORT_END + 1):
        check(port)


if __name__ == '__main__':
    main()
