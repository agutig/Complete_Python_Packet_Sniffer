#Source https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

eth_sub_protocols = {  #TODO only works ipv4 --> Net layer
    8:"IPv4",     #0x0800
    1544:"ARP",   #0x0806
    56710:"IPv6"  #0x86DD

}

transport_sub_protocols = {  #Transport layer
    1:"ICMP",
    2:"IGMP",
    6:"TCP",
    9:"IGRP",
    17:"UDP",
    47:"GRE",
    50:"ESP",
    51:"AH",
    57:"SKIP",
    88:"EIGRP",
    89:"OSPF",
    115:"L2TP"

}