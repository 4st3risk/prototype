from scapy.all import *
from binascii import hexlify
from time import sleep

def split_hex(src):
    return [src[i:i+2] for i in range(0, len(src), 2)]

def print_hex(hex):
    cnt = 0
    for prnt in hex:
        cnt += 1
        if cnt == 16:
            cnt = 0
            print()
        print(f"{prnt} ", end="")
    print()


while(1):
    pkt = sniff(filter="tcp", count=1)
    
    # Layer 3
    ip = pkt[0][1]
    
    print(ip)
    pkthex = hexlify(bytes(pkt[0])).decode()
    # Ethernet II 
    eth_src = pkthex[0:24]
    # Internet Protocol
    internet_proto = pkthex[25:44]
    # Transmission protocol
    trans_proto = pkthex[44:132]
   
    print()

    print_hex(split_hex(eth_src))
    print_hex(split_hex(internet_proto))
    print_hex(split_hex(trans_proto))
    

    print()
    print(hexdump(pkt[0]))

