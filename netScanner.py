"""
  this is a network scanner script that allow us to discover things
  that are connected in the same net by showing the ip and mac adress.
  this script works like doing (net discover -r IP ADRESS)

"""
import scapy.all as scapy
import argparse

def arg():
    parser= argparse.ArgumentParser()
    parser.add_argument('-i', "--ip", dest="ipadress",  help="Target IP adress")
    options= parser.parse_args()
    return options
def scan(ip_adress):
    arp_request = scapy.ARP(pdst = ip_adress)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast= broadcast/arp_request # combining them using scapy /
    ansList  = scapy.srp(arp_request_broadcast, timeout=1,verbose=False)[0] # send broadcast to all dev connnecting on the same net
    # verbos = False means to hide the text that appear

    
    clients_list=[]
    for el in ansList:
        clients_dict={"ip":el[1].psrc,"mac":el[1].hwsrc}
        clients_list.append(clients_dict)
        
        # print ip adress of the the target using psrc
        #get the mac adress of the target  using hwsrc
    return clients_list     
def print_result(result_list):
    print('IP\t\tMAC ADRESS\n----------------------------')
    for i in result_list:
        print(i["ip"] + "\t\t" + i["mac"])
options= arg()
scan_res = scan(options.ipadress)    
print_result(scan_res)