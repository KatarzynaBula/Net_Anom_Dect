from scapy.all import *

file = sys.argv[1]

n = len(sys.argv)
print("Total arguments passed:", n)


def checkmac(mac, ip):
    if not mac in legitmaclist:
        print("Warning! Suspicious mac adress was detected:", mac,"  ", ip)

packets = rdpcap('/home/robert/pcap/t3.pcap')

legitmaclist = []
with open("legitmacaddressess.txt") as file:
    legitmacmaclist = file.readlines()



for packet in packets:
    if IP in packet:
        ipsource=packet[IP].src
        ipdestiation = packet[IP].dst
    e = packet[Ether]
    macsource = e.src
    macdestination =e.dst
    checkmac(macsource, ipsource)
    checkmac(macdestination, ipdestiation)
   

    #print(ipsource, ipdestiation, macsource, macdestination)
    #print(macsource, macdestination, sep='\n')


