#!/bin/env python3

from scapy.all import *
from binascii import hexlify, unhexlify
import sys


if __name__ == "__main__":
    filter = "port 9090"
    iface = "ens37"

    while(1):
        pkt = sniff(iface=iface, filter=filter, count=1)

        hexdump(pkt[0])
        print()


