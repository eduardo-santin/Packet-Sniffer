from socket import *
import struct
import binascii

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

def analyze_ether(raw_data):

    proto_type = struct.unpack('!6s6sH', raw_data[:14])[2]
    if proto_type == 0x0800 or proto_type == 0x86dd:
        ethernet_packets['IP'] += 1
        analyze_ip(raw_data)
    elif proto_type == 0x0806:
        ethernet_packets['ARP'] += 1
    else:
        ethernet_packets['OTHER'] += 1

def analyze_ip(raw_data):
    ip_protocol = struct.unpack('!BBHHHBBH4s4s', raw_data[14:34])[6]

    if ip_protocol == 1:
        ip_packets['ICMP'] += 1
    elif ip_protocol == 6:
        ip_packets['TCP'] += 1
        analyze_tcp_udp(raw_data)
    elif ip_protocol == 17:
        ip_packets['UDP'] += 1
        analyze_tcp_udp(raw_data)
    else:
        ip_packets['OTHER'] += 1


def analyze_tcp_udp(raw_data):
    # check port number for http, ssh, dns, smtp or other
    port = struct.unpack('!HH', raw_data[34:38])

    if port[0] == 80 or port[1] == 80:
        app_packets['HTTP'] += 1
    elif port[0] == 22 or port[1] == 22:
        app_packets['SSH'] += 1
    elif port[0] == 53 or port[1] == 53:
        app_packets['DNS'] += 1
    elif port[0] == 25 or port[1] == 25:
        app_packets['SMTP'] += 1
    else:
        app_packets['OTHER'] += 1





def main():

    # open a raw socket to sniff
    raw_sock = socket(AF_PACKET, SOCK_RAW, htons(3))


    print('Sniffing packets...')
    while True:
        raw_data, addr = raw_sock.recvfrom(65536)
        analyze_ether(raw_data)
        # EthHeader = struct.unpack("!6s6sH",raw_data[0:14])
        # dstMac = binascii.hexlify(EthHeader[0]) 
        # srcMac = binascii.hexlify(EthHeader[1]) 
        # protoType = EthHeader[2] 
        # nextProto = hex(protoType)
        # if (nextProto == '0x800'): 
        #     proto = 'IPV4'
        #     ethernet_packets['IP'] += 1

        #     analyze_ether(raw_data)
            

        #     # analyze the IP header to see which protocol it is
        #     IPHeader = struct.unpack("!BBHHHBBH4s4s",raw_data[14:34])
        #     protocol = IPHeader[6]
        #     # check for tcp, udp, icmp or other
        #     if (protocol == 6):
        #         proto = 'TCP'
        #         ip_packets['TCP'] += 1

        #         # analyze the TCP header to see which application it is
        #         TCPHeader = struct.unpack("!HHLLBBHHH",raw_data[34:54])
        #         # check for http, ssh, dns, smtp or other
        #         if (TCPHeader[0] == 80 or TCPHeader[1] == 80):
        #             proto = 'HTTP'
        #             app_packets['HTTP'] += 1

        #         elif (TCPHeader[0] == 22 or TCPHeader[1] == 22):
        #             proto = 'SSH'
        #             app_packets['SSH'] += 1

        #         elif (TCPHeader[0] == 53 or TCPHeader[1] == 53):
        #             proto = 'DNS'
        #             app_packets['DNS'] += 1

        #         elif (TCPHeader[0] == 25 or TCPHeader[1] == 25):
        #             proto = 'SMTP'
        #             app_packets['SMTP'] += 1

        #         else:
        #             proto = 'OTHER'
        #             app_packets['OTHER'] += 1

        #     elif (protocol == 17):
        #         proto = 'UDP'
        #         ip_packets['UDP'] += 1

        #         # analyze the UDP header to see which application it is
        #         UDPHeader = struct.unpack("!HHHH",raw_data[34:42])
        #         # check for http, ssh, dns, smtp or other
        #         if (UDPHeader[0] == 80 or UDPHeader[1] == 80):
        #             proto = 'HTTP'
        #             app_packets['HTTP'] += 1

        #         elif (UDPHeader[0] == 22 or UDPHeader[1] == 22):
        #             proto = 'SSH'
        #             app_packets['SSH'] += 1

        #         elif (UDPHeader[0] == 53 or UDPHeader[1] == 53):
        #             proto = 'DNS'
        #             app_packets['DNS'] += 1

        #         elif (UDPHeader[0] == 25 or UDPHeader[1] == 25):
        #             proto = 'SMTP'
        #             app_packets['SMTP'] += 1

        #         else:
        #             proto = 'OTHER'
        #             app_packets['OTHER'] += 1

        #     elif (protocol == 1):
        #         proto = 'ICMP'
        #         ip_packets['ICMP'] += 1
        #     else:
        #         proto = 'OTHER'
        #         ip_packets['OTHER'] += 1

        # elif (nextProto == '0x86dd'): 
        #     proto = 'IPV6'
        #     ethernet_packets['IP'] += 1

        # elif (nextProto == '0x806'):
        #     proto = 'ARP'
        #     ethernet_packets['ARP'] += 1

        # else:
        #     proto = 'OTHER'
        #     ethernet_packets['OTHER'] += 1


    


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
