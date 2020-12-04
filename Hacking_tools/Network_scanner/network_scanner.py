#! /usr/bin/python3

import scapy.all as scapy
import argparse

# def scan(ip):
#     scapy.arping(ip)
#implementing arping() function

#Create an Arp request and assign it to broadcast mac
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = broadcast/arp_request
    arp_packet.show()


parser = argparse.ArgumentParser(description='''This is a script to scan for devices in the
                                                network so provide the ip or ip range in the arguments''')

parser.add_argument("-ip", "--ipaddress",metavar="",required=True, dest="ip", help="Enter the Ip address to be scanned")
args = parser.parse_args()
ip = args.ip

scan(ip)

