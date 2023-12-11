from socket import *
import struct
import binascii

debug = False

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


# function to analyze the ethernet frame
# takes in
def analyze_ether(data):
    # the raw socket returns the ethernet frame without the preamble
    # so we start at the first byte of the destination mac address
    # doing the math, we can get that type adress are the two bytes at
    # index 12 and 14 of the ethernet frame

    
    proto_type = struct.unpack('!H', data[12:14])[0]

    if debug:
        print(f'Protocol type int: {proto_type}')
        print(f'Protocol type hex: {hex(proto_type)}')

    # ipv4 or ipv6 check
    if proto_type == 0x0800 or proto_type == 0x86dd:
        ethernet_packets['IP'] += 1

        ip_data = data[14:]
        analyze_ip(ip_data)

    # arp check
    elif proto_type == 0x0806:
        ethernet_packets['ARP'] += 1

    # other
    else:
        ethernet_packets['OTHER'] += 1


def analyze_tcp_udp(data):

    # we just need to check the port numbers
    # those are the first 4 bytes of the data in the header
    port = struct.unpack('!HH', data[:4])


    # determine which port it is for the app layer
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

def analyze_ip(data):

    # the ip header is 20 bytes long
    # so we can un pack the first 20 bytes of the data
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])

    # from debugging, we know that the 6th index is the protocol
    ip_protocol = ip_header[6]

    if debug:
        print(f'IP Protocol int: {ip_protocol}')

    if ip_protocol == 1:
        ip_packets['ICMP'] += 1
    elif ip_protocol == 6:
        ip_packets['TCP'] += 1


        app_data = data[20:]
        analyze_tcp_udp(app_data)
    elif ip_protocol == 17:
        ip_packets['UDP'] += 1
        
        app_data = data[20:]
        analyze_tcp_udp(app_data)
    else:
        ip_packets['OTHER'] += 1








def main():

    # open a raw socket to sniff
    raw_sock = socket(AF_PACKET, SOCK_RAW, htons(3))


    print('Sniffing packets...')
    while True:
        raw_data, addr = raw_sock.recvfrom(65536)
        analyze_ether(raw_data)
        

    

# function to print total packets
def exit_gracefully():
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
    
    



# main section so it calls the main sniffer script and then
# waits for a CTRL-C to exit
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    finally:
        exit_gracefully()
