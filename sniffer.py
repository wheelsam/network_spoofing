from __future__ import print_function
from scapy.all import *
import time
from win32com.client import Dispatch
from scapy.layers.http import HTTPRequest # import HTTP packet
from colorama import init, Fore
# initialize colorama
init()
# define colors
GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET

__version__ = "0.0.3"
speak = Dispatch("SAPI.SpVoice")

# Fixup function to extract dhcp_options by key
def get_option(dhcp_options, key):

    must_decode = ['hostname', 'domain', 'vendor_class_id']
    try:
        for i in dhcp_options:
            if i[0] == key:
                # If DHCP Server Returned multiple name servers
                # return all as comma seperated string.
                if key == 'name_server' and len(i) > 2:
                    return ",".join(i[1:])
                # domain and hostname are binary strings,
                # decode to unicode string before returning
                elif key in must_decode:
                    return i[1].decode()
                else:
                    return i[1]
    except:
        pass


def handle_dhcp_packet(packet):
    # Match DHCP request
    if DHCP in packet and packet[DHCP].options[0][1] == 3:
        print('---')
        print('New DHCP Request')
        #print(packet.summary())
        #print(ls(packet))

        requested_addr = get_option(packet[DHCP].options, 'requested_addr')
        hostname = get_option(packet[DHCP].options, 'hostname')
        print(f"Host {hostname} ({packet[Ether].src}) requested {requested_addr}")
        if (hostname == "Galaxy-S8" and requested_addr == "192.168.1.5"):
            speak.Speak("Welcome home Sam")
        if (hostname == "SammyBlesiPhone" and requested_addr == "192.168.1.28"):
            speak.Speak("Hey Sammy you are looking cute as always")

    return

def handle_tcp_packet(packet):
    if packet.haslayer(HTTPRequest):
        # if this packet is an HTTP Request
        # get the requested URL
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # get the requester's IP Address
        ip = packet[IP].src
        # get the request method
        method = packet[HTTPRequest].Method.decode()
        print(f"\n{GREEN}[+] {ip} Requested {url} with {method}{RESET}")
        if show_raw and packet.haslayer(Raw) and method == "POST":
            # if show_raw flag is enabled, has raw data, and the requested method is "POST"
            # then show raw
            print(f"\n{RED}[*] Some useful Raw data: {packet[Raw].load}{RESET}")
    #if (packet[TCP].dport == 80 or packet[TCP].dport == 443):

def handle_packet(packet):
    if(DHCP in packet):
        handle_dhcp_packet(packet)
    elif(TCP in packet):
        handle_tcp_packet(packet)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="HTTP Packet Sniffer, this is useful when you're a man in the middle." \
                                     + "It is suggested that you run arp spoof before you use this script, otherwise  \
                                     it'll sniff your personal packets")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("--show-raw", dest="show_raw", action="store_true", help="Whether to print POST raw data, such as passwords, search queries, etc.")
    # parse arguments
    args = parser.parse_args()
    show_raw = args.show_raw
    sniff(prn=handle_packet)
