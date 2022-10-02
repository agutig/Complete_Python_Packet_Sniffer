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

def get_ipv6(addr):
    chain = ''.join(map('{:02x}'.format ,addr))
    new_chain = ''
    for i in range(0,len(str(chain))):
        if i % 4 == 0 & i != 0:
            new_chain += chain[i] + ":"
        else:
            new_chain += chain[i]
    return new_chain

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
    return version, header_length, ttl, proto, get_ipv4(src), get_ipv4(target), raw_data[header_length:]


def ipv4_print(ipv4):
    print( '\t - ' + 'IPv4 Packet:')
    print('\t\t - ' + 'Version: {}, Header Length: {}, TTL:{},'.format(ipv4[0], ipv4[1], ipv4[2]))
    print('\t\t - ' + 'Protocol: {}, Source: {}, Target:{}'.format(coded.transport_sub_protocols.get(ipv4[3] ,ipv4[3] ), ipv4[4], ipv4[5]))

    return ipv4[3] ,ipv4[6] #Inner protocol + inner protocol data


def ipv6_head(raw_data):
    
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    #4 -> 0.5    8 ->1B         20 ->2.5     16->2B         8->1B       8->1B       128->16B    128->16B
    #version    trafic class   flow label   paload length   next header  hop       source       dest
    traffic_class = raw_data[1] #This isn probably wrong
    payload_len, next_header , hop_limit , source_dir , desti_dir = struct.unpack('! H B B 16s 16s', raw_data[4:40])

    return version, traffic_class ,payload_len, next_header , hop_limit , source_dir , desti_dir, raw_data[64:]

def ipv6_print(ipv6):
    print( '\t - ' + 'IPv6 Packet:     WARNING: THE INFORMATION MAY BE WORNG FOR THIS PROTOCOL'  )
    print('\t\t - ' + 'Version: {}, Traffic Class: {} (May not be correct), Payload Length: {} ' + 'Next Header: {} , Hop Limit: {} '.format(ipv6[0], ipv6[1], ipv6[2],ipv6[3], ipv6[4]))

    print('\t\t - ' + 'Source: {} --> Target:{}'.format(get_ipv6(ipv6[5]),get_ipv6(ipv6[6])))

    return ipv6[7] #Inner protocol + inner protocol data

def arp_packet(raw_data):
    (hardware_type, protocol_type, hardware_len, proto_len, operation ,sender_link_dir, 
    sender_net_dir, target_link_dir, target_net_dir) = struct.unpack( '! H H B B H 6s 4s 6s 4s', raw_data[:28])
    if hardware_type == 1:
        hardware_type = "1 (ethernet)"
    
    if operation == 1:
        operation = "1 (REQUEST)"
    elif operation == 2:
        operation = "2 (RESPONSE)"

    print( '\t - ' + 'ARP Packet:')
    print('\t\t - ' + 'Hardware type: {}, Protocol type {}, Hardware Len:{}, Protocol Len:{}, '.format(hardware_type, protocol_type, hardware_len ,proto_len))
    print('\t\t - ' + 'FROM: MAC: {} || IP: {}  ------>  TO: MAC: {} || IP: {}'.format(get_mac(sender_link_dir),get_ipv4(sender_net_dir)
    ,get_mac(target_link_dir),get_ipv4(target_net_dir )))
    print('\t\t - ' + 'Operation {}'.format(operation))
    


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

def tcp_print(tcp):
    print('\t\t -> ' + 'TCP Segment:')
    print('\t\t\t - ' + 'Source Port: {}, Destination Port: {}'.format(tcp[0], tcp[1]))
    print('\t\t\t - ' + 'Sequence: {}, Acknowledgment: {}'.format(tcp[2], tcp[3]))
    print('\t\t\t - ' + 'Flags:')
    print('\t\t\t - ' + 'URG: {}, ACK: {}, PSH:{}'.format(tcp[4], tcp[5], tcp[6]))
    print('\t\t\t - ' +'RST: {}, SYN: {}, FIN:{}'.format(tcp[7], tcp[8], tcp[9]))

def udp_head(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H' ,data[:8])
    print('\t\t -> ' + 'UDP Segment:')
    print('\t\t\t - ' + "Source port: " + str(src_port))
    print('\t\t\t - ' + "Destination port: " + str(dest_port))
    print('\t\t\t - ' + "Size: " + str(size))
    return src_port, dest_port, size, data[8:]

def icmp_header(data):
    icmp_type, code ,checksum = struct.unpack('! B B H',data[:4])
    print('\t\t -> ' + 'ICMP Segment:')
    print('\t\t\t - ' + "Type:" + str(icmp_type))
    print('\t\t\t - ' + "Code:" + str(code))
    print('\t\t\t - ' + "Checksum:" + str(checksum))
    return icmp_type, code ,checksum, data[4:]

#Main loop  
def main():

    print("Sniffer Listening")
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True: 
        print("-------------------------------------------")
        raw_data, addr = s.recvfrom(65535)
        eth = ethernet_head(raw_data)
        eth_print(eth)
        if eth[2] == 8: #ipv4
            ipv4 = ipv4_head(eth[3])
            trans_protocol ,trans_data = ipv4_print(ipv4)

            if trans_protocol == 6: #TCP 
                tcp = tcp_head(trans_data)
                tcp_print(tcp)
            
            elif trans_protocol == 17: #ICMP
                udp = udp_head(trans_data)

            elif trans_protocol == 1: #ICMP
                icmp = icmp_header(trans_data)

        elif eth[2] == 1544:  #ACK
            arp_packet(eth[3])

        elif eth[2] ==  56710:
            ipv6 = ipv6_head(eth[3])
            ipv6_print(ipv6)
                
main()



