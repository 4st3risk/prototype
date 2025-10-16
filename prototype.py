#!/bin/env python3

from scapy.all import *
from binascii import hexlify, unhexlify
from ipNumber import IP_PROTOCOL
import sys
import logging
import datetime as dt

def split_hex(src):
    return [src[i:i+2] for i in range(0, len(src), 2)]

def print_hex(hex):
    cnt = 0 
    for prnt in hex:
        cnt += 1
        if cnt == 16:
            cnt = 0
            print()
        logging.info(f"{prnt.upper()} ")
    logging.info("\n")

def print_mac(hex):
    cnt = 0
    for prnt in hex:
        cnt += 1 
        logging.info(f"{prnt.upper()}:")
    logging.info("\b \n")

def rethex(plist, num):
    return int(bytes(plist[0])[num])

def rethexs(plist, num1, num2):
    tmp = []
    
    for i in range(num1, num2):
        tmp.append(hex(rethex(plist, i)))

    return tmp

def compare_hex(hex1, hex2):
    int_hex1 = int(hex1, 16)
    int_hex2 = int(hex2, 16)

    if int_hex1 == int_hex2:
        return True
    else:
        return False

def hexnor(hex):
    if len(hex) % 2:
        hex_list = list(hex)
        hex_list.insert(2, "0")
        new_hex = "".join(hex_list)
        return new_hex
    else:
        return hex


def combine_hex(hexs):
    tmp = ""
    for hex in hexs:
        tmp += hex[2:]
    
    tmp_list = list(tmp)
    tmp_list.insert(0,"0x")
    new_tmp = "".join(tmp_list)
    return new_tmp

def set_hexs(*hexs):
    tmp = []
    cnt = 0
    for hex in hexs:
        tmp.insert(cnt, hex)
        cnt += 1
    return tmp

def compare_header_type(pktbytehex):
    hexs = set_hexs(hexnor(hex(pktbytehex[12])), hexnor(hex(pktbytehex[13])))
    combhex = combine_hex(hexs)
    
    if compare_hex(combhex, "0x0600"):
        return "XNS IDP"
    if compare_hex(combhex, "0x0800"):
        return "IPv4"
    if compare_hex(combhex, "0x0805"):
        return "X.25 PLP"
    if compare_hex(combhex, "0x0806"):
        return "ARP"
    if compare_hex(combhex, "0x8035"):
        return "RARP"
    if compare_hex(combhex, "0x8137"):
        return "Netware IPX"
    if compare_hex(combhex, "0x8191"):
        return "NetBIOS"
    if compare_hex(combhex, "0x86DD"):
        return "IPv6"

    for x in range(0x0000, 0x05dd):
        if compare_hex(combhex, x):
            return "IEEE 802.3 Data Length"

now = dt.datetime.now()
targets = logging.StreamHandler(sys.stdout), logging.FileHandler(f"packet_{now.strftime("%d-%m-%Y_%H_%M_%S")}.cap")
logging.basicConfig(format='%(message)s', level=logging.INFO, handlers=targets)

def main():

    targets[0].terminator=''
    targets[1].terminator=''
    filter = ""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} [filter]")
    else:
        filter = sys.argv[1]


    logging.info(f"Filter is [{sys.argv[1]}]\n\n")

    try:
        while(1):
            pkt = sniff(filter=filter, count=1)

            ip = pkt[0][1]
            logging.info('-' * 64)
            logging.info("\n")
            pkthex = hexlify(bytes(pkt[0])).decode()
            pktbytehex = bytes(pkt[0])

            result = compare_header_type(pktbytehex)
            logging.info(f"Type is:\t{result}\n")

        #        print(f"Protocol is: {IP_PROTOCOL[int(bytes(pkt[0])[23])]}")
        #        print(hex(bytes(pkt[0])[23]))
            logging.info(f"Protocol is:\t{IP_PROTOCOL[rethex(pkt, 23)]}\n")
            logging.info("\n")

            logging.info("Destination Address is:\t")

            dst = pkthex[0:12]
            print_mac(split_hex(dst))

            logging.info("Source Address is:\t")

            src = pkthex[12:24]
            print_mac(split_hex(src))

            src_port = combine_hex(set_hexs(hexnor(hex(pktbytehex[34])), hexnor(hex(pktbytehex[35]))))
            logging.info(f"Source Port is:\t\t{int(src_port, 16)}\n")

            dst_port = combine_hex(set_hexs(hexnor(hex(pktbytehex[36])), hexnor(hex(pktbytehex[37]))))
            logging.info(f"Destination Port is:\t{int(dst_port, 16)}\n")
            logging.info("\n")

            logging.info(hexdump(pkt[0], dump=True))
            logging.info("\n")
    except Exception as e:
        print(f"Quit Program ... exit code: {e}")
    finally:
        print("Program Terminated.")


if __name__ == "__main__":
    try:
        main()
    except:
            pass

