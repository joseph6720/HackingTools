#! /usr/bin/python3

import scapy.all as scapy
import argparse
from termcolor import colored

# def scan(ip):
#     scapy.arping(ip)
# implementing arping() function

# Create an Arp request and assign it to broadcast mac


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = broadcast/arp_request

    # Now we will use the scapy.srp() function to send the packet.
    # We are using the srp() function since our packet has a custom Ether layer
    # It will return a list containing answered and unaswered messagees in that order.
    # scapy.sr() is for packets without a custom Ether layer

    #(answered_list, unanswered_list) = scapy.srp(arp_packet, timeout=1, verbose=3)
    # since we are not going to use unanswered list we will eliminate it as follows

    answered_list = scapy.srp(arp_packet, timeout=1, verbose=3)[0]
    # print(answered_list.summary())
    for element in answered_list:
        print(colored(
            f'[+] Found device with ip: {element[1].psrc} and mac: {element[1].hwsrc}', "green"))
        # print("-------------------------------------------------------------")


parser = argparse.ArgumentParser(description='''This is a script to scan for devices in the
                                                network so provide the ip or ip range in the arguments''')

parser.add_argument("-ip", "--ipaddress", metavar="", required=True,
                    dest="ip", help="Enter the Ip address to be scanned")
args = parser.parse_args()
ip = args.ip

scan(ip)
