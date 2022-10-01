"""
Note: This sniffer was made following thenewboston's tutorial:
https://www.youtube.com/watch?v=3zwuOo7U1YQ

The main idea of this proyect is to reconvert it to my own version.
"""


from struct import *
import socket,struct  #Libraries
import coded #Program

##parsing

#LINK layer
def get_mac(addr):
    return ':'.join(map('{:02x}'.format ,addr)).upper()

def get_ipv4(addr):
    return '.'.join(map(str ,addr))

def ethernet_head(raw_data): #MAC Adress
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    dest_mac = get_mac(dest)
    src_mac = get_mac(src)
    proto = socket.htons(prototype)   #inner protocol.
    data = raw_data[14:]
    return dest_mac, src_mac, proto, data

def eth_print(eth):
    print('\nEthernet Frame:')
    print('MAC Destination: {}, MAC Source: {}, InnerProtocol: {}'.format(eth[0], eth[1], coded.eth_sub_protocols.get(eth[2] ,eth[2] )))


#NET layer
def ipv4_head(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    data = raw_data[header_length:]
    return version, header_length, ttl, proto, get_ipv4(src), get_ipv4(target), data[header_length:]


def ipv4_print(ipv4):
    print( '\t - ' + 'IPv4 Packet:')
    print('\t\t - ' + 'Version: {}, Header Length: {}, TTL:{},'.format(ipv4[0], ipv4[1], ipv4[2]))
    print('\t\t - ' + 'Protocol: {}, Source: {}, Target:{}'.format(coded.transport_sub_protocols.get(ipv4[3] ,ipv4[3] ), ipv4[4], ipv4[5]))

    return ipv4[3] ,ipv4[6] #Inner protocol + inner protocol data


#Transport Layer
def tcp_head( raw_data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack( '! H H L L H', raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, raw_data[offset:]

#Main loop
def main():
    print("Sniffer Listening")
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True: 
        print("-------------------------------------------")
        raw_data, addr = s.recvfrom(65535)
        eth = ethernet_head(raw_data)
        eth_print(eth)
        if eth[2] == 8:
            ipv4 = ipv4_head(eth[3])
            trans_protocol ,trans_data = ipv4_print(ipv4)
            if trans_protocol == 6: #TCP 
                tcp = tcp_head(trans_data)
                print('TCP Segment:')
                print('Source Port: {}, Destination Port: {}'.format(tcp[0], tcp[1]))
                print('Sequence: {}, Acknowledgment: {}'.format(tcp[2], tcp[3]))
                print('Flags:')
                print('URG: {}, ACK: {}, PSH:{}'.format(tcp[4], tcp[5], tcp[6]))
                print('RST: {}, SYN: {}, FIN:{}'.format(tcp[7], tcp[8], tcp[9]))
main()



