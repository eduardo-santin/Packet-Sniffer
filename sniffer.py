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
    'HTTPS': 0,
    'SSH': 0,
    'DNS': 0,
    'SMTP': 0,
    'OTHER': 0
}


# function to analyze the ethernet frame
def analyze_ether(data):
    # the raw socket returns the ethernet frame without the preamble
    # so we start at the first byte of the destination mac address
    

    ethernet_header = struct.unpack('!6s6sH', data[:14])


    # get the protocol type
    proto_type = ethernet_header[2]
    

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

    # the first 4 bytes of the data are the source and destination ports
    tcp_header = struct.unpack('!HH', data[:4])

    # get the source and destination ports
    src_port = tcp_header[0]
    dst_port = tcp_header[1]

    if (src_port == 80 or dst_port == 80):
        app_packets['HTTP'] += 1
        if debug: print('HTTP')
    

    elif (src_port == 53 or dst_port == 53):
        app_packets['DNS'] += 1
        if debug: print('DNS')
    

    elif (src_port == 22 or dst_port == 22):
        app_packets['SSH'] += 1
        if debug: print('SSH')
    

    elif (src_port == 443 or dst_port == 443):
        app_packets['HTTPS'] += 1
        if debug: print('HTTPS')

        
    # tried to cover for all the different smtp ports
    elif (src_port == 587 or dst_port == 587) or (src_port == 25 or dst_port == 25) or (src_port == 465 or dst_port == 465) or (src_port == 2525 or dst_port == 2525):
        app_packets['SMTP'] += 1
        if debug: print('SMTP')


    else:
        app_packets['OTHER'] += 1
        if debug: print('OTHER')

def analyze_ip(data):

    # we just need the first 10 bytes of the ip header
    # to get the protocol and the header length
    # we then adjust the app data to start after the ip header
    ip_header = struct.unpack('!BBHHHBB', data[:10])


    if debug:
        print(f'IP Header: {ip_header}')


    # get which version of ip we are using
    ip_version = ip_header[0] >> 4


    if debug:
        print(f'IP Version: {ip_version}')
    

    # get the ip header length
    ip_header_length = ip_header[0] & 0xF 
    ip_header_length_bytes = ip_header_length * 4  # Convert to bytes


    # set the app data after the ip header length
    # this should avoid the extra header data if there is any
    app_data = data[ip_header_length_bytes:]


    # debugging print statements let 
    ip_protocol = ip_header[6]


    if debug:
        print(f'IP Protocol int: {ip_protocol}')


    # check for protocol type and sum to the dictionary
    # if tcp or udp, call the tcp/udp function to proceed to the next layer
    if ip_protocol == 1:
        ip_packets['ICMP'] += 1


    elif ip_protocol == 6:
        ip_packets['TCP'] += 1
        analyze_tcp_udp(app_data)


    elif ip_protocol == 17:
        ip_packets['UDP'] += 1
        analyze_tcp_udp(app_data)


    else:
        ip_packets['OTHER'] += 1




def main():

    # open a raw socket to sniff
    raw_sock = socket(AF_PACKET, SOCK_RAW, ntohs(3))


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
    print(f'{app_packets["HTTPS"]} were HTTPS packets')
    print(f'{app_packets["SSH"]} were SSH packets')
    print(f'{app_packets["DNS"]} were DNS packets')
    print(f'{app_packets["SMTP"]} were SMTP packets')
    print(f'{app_packets["OTHER"]} were other TCP/UDP packets')
    print('--------------------------------------------------\n')   
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
