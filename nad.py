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
    detectedmacadressess = set(())

#    packets = []

    def __init__(self, legitMacaddressessFileName):
        with open(legitMacaddressessFileName) as file:
            self.legitmaclist = file.readlines()
            #self.legitmaclist.sort()
        

    def initiatePcap(self,pcapFileName):
        self.packets = rdpcap(pcapFileName)
        print('Długość: ',len(self.packets))

    def getStream(self) -> list:
        return self.packets
    
    def binarysearch(self, word, list):

        first = 0
        last = len(list) - 1
        found = False
        while first <= last and not found:
            middle = (first + last)//2
            if list[middle] == word:
                True
            else:
                if word < list[middle]:
                    last = middle - 1
                else:
                    first = middle + 1
        return 

    def checkmac(self,mac, ip):
        for mac in self.legitmaclist:
           if self.binarysearch(mac, self.legitmaclist) is False:
                if not mac in self.detectedmacadressess:
                    warning.displaywarning(mac, ip)
                    self.detectedmacadressess.add(mac)
                    print(self.detectedmacadressess)

         
    
                
          

    def next(self, packet):
        if IP in packet:
            ipsource=packet[IP].src
            ipdestination = packet[IP].dst
        else:
            ipsource = ipdestination = '0.0.0.0'
        e = packet[Ether]
        macsource = e.src
        macdestination =e.dst
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


