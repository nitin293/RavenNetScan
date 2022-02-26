import scapy.all as scapy
import argparse

def banner():
    ban = '''
█▀█ ▄▀█ █░█ █▀▀ █▄░█ █▄░█ █▀▀ ▀█▀ █▀ █▀▀ ▄▀█ █▄░█
█▀▄ █▀█ ▀▄▀ ██▄ █░▀█ █░▀█ ██▄ ░█░ ▄█ █▄▄ █▀█ █░▀█

Author: Nitin Choudhury
Version: 0.1.0
    '''
    print(ban)

def netScan(iprange):
    MAP = {}

    ip = scapy.ARP(pdst=iprange)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    packet = broadcast/ip

    response_list = scapy.srp(packet, verbose=False, timeout=4)[0]

    for response in response_list:
        response = response[1]
        MAP[response.psrc] = response.hwsrc

    return MAP


def print_result(MAP):
    if MAP:
        print("IP\t\tMAC")
        print("-"*35)
        for ip in MAP.keys():
            print(f"{ip}\t{MAP[ip]}")



if __name__ == '__main__':
    banner()

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-r", "--range",
        help="Set IP Range",
        required=True,
        type=str
    )

    args = parser.parse_args()

    iprange = args.range

    map = netScan(iprange=iprange)
    print_result(map)