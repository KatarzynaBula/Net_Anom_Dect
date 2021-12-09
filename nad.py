from scapy import config
from scapy.all import *
import configparser


class PktProcessor:

    
    detectedmacadressess = list(set(()))


    def __init__(self, legitMacaddressessFileName):
        with open(legitMacaddressessFileName) as file:
            #self.notsortedlegitmaclist = file.readlines()
            self.notsortedlegitmaclist = file.read().splitlines()
            self.mergesort(self.notsortedlegitmaclist)
                
          

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

    def mergesort(self, list):
        if len(list) == 0 or len(list) == 1: 
            return list[:len(list)] 
        #recursion
        halfway = len(list) // 2
        list1 = list[0:halfway]
        list2 = list[halfway:len(list)]
        newlist1 = self.mergesort(list1) 
        newlist2 = self.mergesort(list2) 
        self.legitmaclist = self.merge(newlist1, newlist2)
        return self.legitmaclist

   
        

    def initiatePcap(self,pcapFileName):
        self.packets = rdpcap(pcapFileName)
        print('Pcap file lenth: ',len(self.packets))
    
    def initiateInterface(self, interface):
        print("Not implemented yet...")

   
    def binarysearch(self, word, list):

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

    def linearsearch(self, word, set1):
  
        for i in range(len(set1)):
            if set1[i] == word:
                return True
  
   

    def checkmac(self,mac, ip):
        if self.binarysearch(mac, self.legitmaclist) is None:
            if self.linearsearch(mac, self.detectedmacadressess) is None:
                warning.displaywarning(mac, ip)
                self.detectedmacadressess.append(mac)
        
                      

    def next(self, packet):
        if IP in packet:
            ipsource=packet[IP].src
            ipdestination = packet[IP].dst
        else:
            ipsource = ipdestination = '0.0.0.0'
        e = packet[Ether]
        #macsource = str(e.src) + str('\n')
        macsource = str(e.src)
        #macdestination = str(e.dst) + str('\n')
        macdestination = str(e.dst)
        self.checkmac(macsource, ipsource)
        self.checkmac(macdestination, ipdestination)

class MacWarning:
    def __init__(self):
        pass

    def displaywarning(self, mac, ip):
        print("Warning! Suspicious mac adress was detected:", mac,"  ", ip)


CONFIGFILE="nad.cfg"
config=configparser.ConfigParser()
config.read(CONFIGFILE)

warning = MacWarning()
processor = PktProcessor(config['path']['legitmacs'])
if config['conf']['mode'] == "pcap":
    processor.initiatePcap(config['path']['pcap'])
else:
    processor.initiateInterface(config['conf']['interface'])
#pstream = 
for packet in processor.packets: 
    processor.next(packet)
      
   

    #print(ipsource, ipdestination, macsource, macdestination)
    #print(macsource, macdestination, sep='\n')


