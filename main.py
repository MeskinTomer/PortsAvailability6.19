from scapy import *

IP = "127.0.0.1"
PORT_INITIAL = 10
PORT_END = 1000
TIMEOUT = 0.5

def check(port):


def main():
    for port in range(PORT_INITIAL, PORT_END + 1):
        check(port)

if __name__ == '__main__':
    main()