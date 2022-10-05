
from psutil import net_if_addrs
import sys

def main():

    hide = True
    try:

        hide = True if  (sys.argv[1] == "c") else False
        iface_array = []
        iface_number = 0
        for i in net_if_addrs().items():
            print("")
            print('\t\t' + str(iface_number) + '.  Iface: '+ str(i[0]))
            iface_array.append(str(i[0]))
            for j in i[1:]:
                for h in j:
                    address = ""
                    
                    if (not hide):
                        address = str(h.address)
                    else:
                        if str(h.family).split(".")[1]  == "AF_INET":
                            address = "LOCAL IP"
                        elif str(h.family).split(".")[1]  == "AF_INET6":
                            address = "LOCAL MAC"
                        else:
                            address = "LOCAL ADDRESS"

                    print('\t\t\t  - ' + 'family: ' + str(h.family).split(".")[1] + 
                    ' | address: ' +  (str(address)) 
                    + ' | netmask: ' + str(h.netmask) + ' | broadcast: ' + str(h.broadcast)  + ' | ptp: ' + str(h.ptp))        
            iface_number += 1    
        print("")
        print('\t\t' + str(iface_number) + '. ALL ifaces')
        iface_array.append("ALL")
        print("")

        keep_loop = True

        while keep_loop == True:
            choice = input('Select an Iface option (number + enter) :')
            try:
                iface_array[int(choice)]
                keep_loop = False
                print("Sniffer listening for: " + iface_array[int(choice)])
                break

            except (IndexError , TypeError):
                print("invalid value, choose an option between 0 and " + str(len(iface_array) - 1))
    
    except  IndexError:
        print("please init with a mode: c to hide local addresses , p for visualizating all adresses ")

main()