"""Script to test the capability of intercepting my own API calls to OpenWeather
    while simultaneously running that script/request"""

from scapy.all import *
from scapy.layers.http import HTTPRequest
from colorama import init, Fore

# Initialize colorama
init()
# define colors
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET


def sniff_packets(iface="eth0"):
    """Sniff packets using eth0 as default
        Free API calls force http, so 80 will be used"""

    if iface: # 'process_packet' will be our function we pass in
        sniff(filter="port 80", prn=process_packet, iface=iface, store=False)


def process_packet(packet): # Function to run whenever packet is sniffed ('sniff_packets')

    if packet.haslayer(HTTPRequest):
        # Get the requested URL
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # Get the requester's IP address
        ip = packet["IP"].src
        # Get the request method...
        method = packet[HTTPRequest].Method.decode()
        print(f"\n{GREEN} [+] Kyle at {ip} requested {url}\n with {method}{RESET}.")
        if method == 'GET':
        #if packet.haslayer(Raw) and method == 'GET':
            packet.show()

sniff_packets()
