from scapy import config
from scapy.all import *
import configparser

#Naming convention:
#module_name, package_name, ClassName, method_name, ExceptionName, function_name, GLOBAL_CONSTANT_NAME, global_var_name, instance_var_name, function_parameter_name, local_var_name.

class PktProcessor:

    
    detected_mac_adressess = list(set(()))


    def __init__(self, legit_mac_addressess_file_name):
        with open(legit_mac_addressess_file_name) as file:
            self.not_sorted_legit_mac_list = file.read().splitlines()
            self.merge_sort(self.not_sorted_legit_mac_list)
                
    def merge(self, a, b):

        index_a = 0
        index_b = 0
        c = []
        while index_a < len(a) and index_b < len(b):
            if a[index_a] <= b[index_b]:
                c.append(a[index_a])
                index_a = index_a + 1
            else:
                c.append(b[index_b])
                index_b = index_b + 1
 
        c.extend(a[index_a:])
        c.extend(b[index_b:])
        return c

    def merge_sort(self, list):
        if len(list) == 0 or len(list) == 1: 
            return list[:len(list)] 
        #recursion
        half_way = len(list) // 2
        list1 = list[0:half_way]
        list2 = list[half_way:len(list)]
        new_list1 = self.merge_sort(list1) 
        new_list2 = self.merge_sort(list2) 
        self.legit_mac_list = self.merge(new_list1, new_list2)
        return self.legit_mac_list

    def initiate_Pcap(self,pcapFileName):
        self.packets = rdpcap(pcapFileName)
        print('Pcap file lenth: ',len(self.packets))
    
    def initiate_Interface(self, interface):
        print("Live capture not implemented yet...")

   
    def binary_search(self, word, list):

        first = 0
        last = len(list) - 1
        while first <= last and not False:
            middle = (first + last)//2
            if list[middle] == word:
                return True
            else:
                if word < list[middle]:
                    last = middle - 1
                else:
                    first = middle + 1

    def linear_search(self, word, set1):
  
        for i in range(len(set1)):
            if set1[i] == word:
                return True
  
    def check_mac(self,mac, ip):
        if self.binary_search(mac, self.legit_mac_list) is None:
            if self.linear_search(mac, self.detected_mac_adressess) is None:
                warning.display_warning(mac, ip)
                self.detected_mac_adressess.append(mac)
        
    def next(self, packet):
        if IP in packet:
            ip_source=packet[IP].src
            ip_destination = packet[IP].dst
        else:
            ip_source = ip_destination = '0.0.0.0'
        e = packet[Ether]
        mac_source = str(e.src)
        mac_destination = str(e.dst)
        self.check_mac(mac_source, ip_source)
        self.check_mac(mac_destination, ip_destination)

class MacWarning:
    def __init__(self):
        pass

    def display_warning(self, mac, ip):
        print("Warning! Suspicious mac adress was detected:", mac,"  ", ip)


CONFIGFILE="nad.cfg"
config=configparser.ConfigParser()
config.read(CONFIGFILE)

warning = MacWarning()
processor = PktProcessor(config['path']['legitmacs'])
if config['conf']['mode'] == "pcap":
    processor.initiate_Pcap(config['path']['pcap'])
else:
    processor.initiate_Interface(config['conf']['interface'])
for packet in processor.packets: 
    processor.next(packet)
      
