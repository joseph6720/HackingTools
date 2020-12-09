#!/usr/bin/python3

import subprocess
import argparse
from termcolor import colored
import re


def get_arguments():
    parser = argparse.ArgumentParser(
        description="This is a script to change the mac address of your device")
    parser.add_argument("-i", "--interface", dest="interface",
                        help="The interface you want to change", metavar="", required=True)
    parser.add_argument("-m", "--mac", dest="new_mac", metavar="", required=True,
                      help="The new mac address")
    args = parser.parse_args()

    return (args.interface, args.new_mac)


def get_previous_mac(interface):
    if interface == "eth0":
        result = subprocess.check_output(["ifconfig", interface])
        result_string = result.decode("utf-8")

        regex = re.search(r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', result_string)

        if regex:
            return regex.group(0)
        else:
            print(colored("[-] There was an error", "red"))
    else:
        print(colored("The interface does not exist", "red"))


def change_mac(interface, mac, previous_mac):
    if (interface == "eth0"):
        print(colored("[+] Closing the network interface", "green"))
        subprocess.call(["ifconfig", interface, "down"])
        check_mac = mac.split(":")
        if len(check_mac) > 0 and len(check_mac) < 6:
            print(colored("[-] The mac address is too short", "red"))
            print(colored("[-] ReOpening the network interface", "green"))
            subprocess.call(["ifconfig", interface, "up"])
        elif len(check_mac) > 6:
            print(colored("[-] The Mac Address is too long...exitting", "red"))
            print(colored("[-] ReOpening the network interface", "green"))
            subprocess.call(["ifconfig", interface, "up"])
        else:
            print(colored(f"[+] Changing the mac address to {mac}", "green"))
            subprocess.call(["ifconfig", interface, "hw", "ether", mac])
            check_new_mac = subprocess.check_output(["ifconfig", interface])
            strings = check_new_mac.decode("utf-8")
            new_mac_before = re.search(
                r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', strings)
            new_mac = new_mac_before.group(0)
            if (new_mac == previous_mac):
                print(
                    colored("[+] There was an error changing the mac address", "red"))
                print(colored("[+] Restarting the interface", "green"))
                subprocess.call(["ifconfig", interface, "up"])
            else:
                print(colored(
                    f"[+] Mac Address changed successfully to : {new_mac} from {previous_mac}", "green"))
                print(colored("[+] Restarting the interface", "green"))
                subprocess.call(["ifconfig", interface, "up"])

    else:
        print(
            colored("[-] No such interface\n[-] Interfaces are eth0 and wlan0", "red"))


args = get_arguments()
interface = args[0]
mac = args[1]
previous_mac = get_previous_mac(interface)
change_mac(interface, mac, previous_mac)
