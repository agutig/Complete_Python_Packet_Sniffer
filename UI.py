
from psutil import net_if_addrs
import sys

def main():

    encrypted = False
    sys.argv[1] = ""

    if (sys.argv[1] == "c" ):

        for i in net_if_addrs().items():
            print("")
            print('\t\t Iface:'+ str(i[0]))
            for j in i[1:]:
                for h in j:
                    print('\t\t  - ' + 'family: ' + str(h.family).split(".")[1] + ' | address: ' + str(h.address) + ' | netmask: ' + str(h.netmask) + ' | broadcast: ' + str(h.broadcast)  + ' | ptp: ' + str(h.ptp))        
        print("Sniffer Listening -> Local Machine:")

    else:
        print("please init with a mode: c for encrypted addresses , p for visualizating adresses ")

main()