from scapy.all import *

#file = sys.argv[1]

n = len(sys.argv)
print("Total arguments passed:", n)




#input("Press Enter to continue...")
# legitmaclist = []
# with open("legitmacaddressess.txt") as file:
#     legitmacmaclist = file.readlines()


class PktProcessor:

    legitmaclist = []
#    packets = []

    def __init__(self, legitMacaddressessFileName):
        with open(legitMacaddressessFileName) as file:
            legitmacmaclist = file.readlines()

    def initiatePcap(self,pcapFileName):
        self.packets = rdpcap(pcapFileName)
        print('Długość: ',len(self.packets))

    def getStream(self) -> list:
        return self.packets

    def checkmac(self,mac, ip):
        if not mac in self.legitmaclist:
            print("Warning! Suspicious mac adress was detected:", mac,"  ", ip)

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

processor = PktProcessor("legitmacaddressess.txt")
processor.initiatePcap('/home/robert/pcap/t3.pcap')
#pstream = 
for packet in processor.getStream():
    processor.next(packet)
   

    #print(ipsource, ipdestination, macsource, macdestination)
    #print(macsource, macdestination, sep='\n')


