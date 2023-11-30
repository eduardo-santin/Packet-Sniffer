from socket import *
import os

ethernet_packets = {
    'IP': 0,
    'ARP': 0,
    'OTHER':0
}


ip_packets = {
    'TCP': 0,
    'UDP': 0,
    'ICMP': 0,
    'OTHER': 0
}

app_packets = {
    'HTTP': 0,
    'SSH': 0,
    'DNS': 0,
    'SMTP': 0,
    'OTHER': 0
}

def main():

    # open a raw socket to sniff
    raw_sock = socket(AF_PACKET, SOCK_RAW, htons(0x0003))
    while True:
        raw_data, addr = raw_sock.recvfrom(65536)


def exit_gracefully():
    # print total of packets
    print('--------------------------------------------------')
    print('The packet sniffer processed a total of N packets')
    print('Of the N packets:')
    print(f'{ethernet_packets["IP"]} were IP packets')
    print(f'{ethernet_packets["ARP"]} were ARP packets')
    print(f'{ethernet_packets["OTHER"]} were other packets\n')
    print('Of the IP packets: ')
    print(f'{ip_packets["TCP"]} were TCP packets')
    print(f'{ip_packets["UDP"]} were UDP packets')
    print(f'{ip_packets["ICMP"]} were ICMP packets')
    print(f'{ip_packets["OTHER"]} were other IP packets\n')
    print('Of the TCP and UDP packets: ')
    print(f'{app_packets["HTTP"]} were HTTP packets')
    print(f'{app_packets["SSH"]} were SSH packets')
    print(f'{app_packets["DNS"]} were DNS packets')
    print(f'{app_packets["SMTP"]} were SMTP packets')
    print(f'{app_packets["OTHER"]} were other TCP/UDP packets')
    print('--------------------------------------------------\n')   
    print('Thank you for trusting a students code with your packets <3')
    # TODO
    # maybe merry christmas print????
    print('Exiting gracefully...')
    
    




if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    finally:
        exit_gracefully()
