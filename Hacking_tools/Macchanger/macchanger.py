#!/usr/bin/python3

import subprocess
import optparse
from termcolor import colored
import re


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface",
                      help="The interface you want to change")
    parser.add_option("-m", "--mac", dest="new_mac",
                      help="The new mac address")
    (options, arguments) = parser.parse_args()

    if not options.interface:
        parser.error(
            colored("[-] Please specify an interface use --help for more info", "red"))
    if not options.new_mac:
        parser.error(
            colored("[-] Please specify a new mac address use --help for more info", "red"))

    return options


def get_previous_mac(interface):
    result = subprocess.check_output(["ifconfig", interface])
    result_string = result.decode("utf-8")

    regex = re.search(r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', result_string)

    if regex:
        return regex.group(0)
    else:
        print(colored("[-] There was an error", "red"))


def change_mac(interface, mac, previous_mac):
    if (interface == "eth0") or (interface == "wlan0"):
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


options = get_arguments()
interface = options.interface
mac = options.new_mac
previous_mac = get_previous_mac(interface)
change_mac(interface, mac, previous_mac)
