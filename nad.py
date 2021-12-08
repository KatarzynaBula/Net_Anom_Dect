from scapy.all import *

#file = sys.argv[1]

n = len(sys.argv)
print("Total arguments passed:", n)




#input("Press Enter to continue...")
# legitmaclist = []
# with open("legitmacaddressess.txt") as file:
#     legitmacmaclist = file.readlines()


class PktProcessor:

    #legitmaclist = [] # tim sort algorithme merge = insertion
    
    detectedmacadressess = list(set(()))

#    packets = []

    def __init__(self, legitMacaddressessFileName):
        with open(legitMacaddressessFileName) as file:
            self.notsortedlegitmaclist = file.readlines()
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
        print('Długość: ',len(self.packets))

    def getStream(self) -> list:
        return self.packets
    
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
                print(self.detectedmacadressess)

         
    
                
          

    def next(self, packet):
        if IP in packet:
            ipsource=packet[IP].src
            ipdestination = packet[IP].dst
        else:
            ipsource = ipdestination = '0.0.0.0'
        e = packet[Ether]
        macsource = str(e.src) + str('\n')
        macdestination = str(e.dst) + str('\n')
        self.checkmac(macsource, ipsource)
        self.checkmac(macdestination, ipdestination)

class MacWarning:
    def __init__(self):
        pass

    def displaywarning(self, mac, ip):
        print("Warning! Suspicious mac adress was detected:", mac,"  ", ip)



warning = MacWarning()
processor = PktProcessor("legitmacaddressess.txt")
processor.initiatePcap('t3.pcap')
#pstream = 
for packet in processor.getStream():
    processor.next(packet)
      
   

    #print(ipsource, ipdestination, macsource, macdestination)
    #print(macsource, macdestination, sep='\n')


