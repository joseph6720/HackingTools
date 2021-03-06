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
    # scapy.ls(scapy.Ether())

    #(answered_list, unanswered_list) = scapy.srp(arp_packet, timeout=1, verbose=3)
    # since we are not going to use unanswered list we will eliminate it as follows

    answered_list = scapy.srp(arp_packet, timeout=1, verbose=False)[0]
    # print(answered_list.summary())
    # print(answered_list.show())

    # The answered packet is a list of lists containing the broadcast part and the information part.

    thelist = []
    for item in answered_list:
        clients_dict = {"ip": item[1].psrc, "mac": item[1].hwsrc}
        thelist.append(clients_dict)
    return thelist


def display_devices(iplist):
    print(f"\n[+] {len(iplist)} Devices Found!!!".upper())
    print("-----------------------------------------")
    print("IP\t\t\tMac Adress\n-----------------------------------------")
    for element in iplist:
        print(colored(
            f'{element["ip"]}\t\t{element["mac"]}', "green"))
        # print("-------------------------------------------------------------")


def getArguments():
    parser = argparse.ArgumentParser(description='''This is a script to scan for devices in the
                                                    network so provide the ip or ip range in the arguments''')

    parser.add_argument("-ip", "--ipaddress", metavar="", required=True,
                        dest="ip", help="Enter the Ip address to be scanned")
    args = parser.parse_args()
    return args.ip


ip = getArguments()
iplist = scan(ip)
display_devices(iplist)
