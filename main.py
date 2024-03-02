"""
Author: Tomer Meskin
Date: 01/03/24
Checks which ports are in a LISTENING state in a specific IP
"""

from scapy import *
from scapy.layers.inet import *

TARGET_IP = "127.0.0.1"
PORT_INITIAL = 1000
PORT_END = 10000
TIMEOUT = 0.5


def check(port):
    """
    Sends a SYN packet to a given port and checks if the port responses - the port is open
    :param port: The intended PORT to check
    :return: None
    """
    # Construct packets
    ip = IP(dst=TARGET_IP)
    syn = TCP(dport=port, flags='S')
    # Send syn and sniff response
    response = sr1(ip/syn, timeout=TIMEOUT, verbose=0)

    # No response
    if response is None:
        print(".", end="")
    # Response has RST flag
    elif TCP in response and response[TCP].flags & 0x04:
        print("-", end="")
    # Response has TCP layer and SYN+ACK flags
    elif TCP in response and response[TCP].flags & 0x12:
        print(f"Port {port} is available")
    # Otherwise
    else:
        print(f"Port {port} status is unknown")


def main():
    for port in range(PORT_INITIAL, PORT_END + 1):
        check(port)


if __name__ == '__main__':
    main()
