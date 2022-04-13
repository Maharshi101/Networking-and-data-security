
import os, platform, subprocess, threading
from datetime import datetime
from scapy.all import *


numarp=0

def getMacs(ip, oneMac=True):

    arp = ARP(pdst=ip)                      
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  
    arp_broadcast_packet = ether/arp        


    answered_packets = srp(arp_broadcast_packet, timeout=3, verbose=0)[0]

    
    if(oneMac):
        try:
            mac= answered_packets[0][1].hwsrc 
            
            return mac
        except: 
           
            return None
    else:
        print("\nYour Network:")
        hosts = []
        for sent_packet,received_packet in answered_packets:
            hosts.append({'ip': received_packet.psrc, 'mac': received_packet.hwsrc})

       
        print("-----------------------------------\nIP Address\tMAC Address\n-----------------------------------")
        for host in hosts:
            print("{}\t{}".format(host['ip'], host['mac']))
        return(hosts)

def checkForDuplicateMacs(entries):
  
    macarr = []                         
    for entry in entries:
        macarr.append(entry['mac'])  

    print("\nThe MAC entries in the table are:\n",macarr)
    print("\nInitiated testing for identical MAC addresses in table of IP-MAC bindings.") 
    
    d = {}                             
    dup_count = 0                       
    

    for mac in macarr:
        if (mac in d):
            d[mac]+=1
            dup_count+=1
        else:
            d[mac]=1

    if (dup_count == 0):
        print("No duplicate MAC addresses detected.")
    else:
        print("Warning! Identical MAC addresses have been detected in the table.")
        print("There might be an ARP cache poisoning attack on the network!")
        duplicates = dict((k, v) for k, v in d.items() if v > 1)
        print (duplicates)



def getArpTable():
    command = ['arp', '-a']
    subprocess.call(command)    


def checkMac(packet):
     global numarp
     if packet.haslayer(ARP): 
        numarp+=1
       
        if packet[ARP].op == 2: 
            try:
                ip =packet[ARP].psrc
                real_mac = getMacs(ip) 
                if(real_mac==None):
                   
                    return
                response_mac = packet[ARP].hwsrc 
                if real_mac != response_mac:
                    print(f"[*] Fake arp detected:\n REAL-MAC: {real_mac.upper()}, FAKE-MAC: {response_mac.upper()}")
            except:
                print("Couldn't check MAC of",ip)

def Detect(duration=10):
    start_time=datetime.now()
    print("Started at",start_time)
    print('Sniffing and checking...')

    t = AsyncSniffer(prn=checkMac, store=False)
    t.start()
    time.sleep(duration)
    t.stop()
    print(numarp,'ARP packets were detected')

    print('\nStopped. Time taken:', datetime.now()-start_time)

if __name__ == "__main__":

    target_ip =  input("Enter Target IP: ")
    IP_MAC_entries = getMacs(target_ip,False)
    checkForDuplicateMacs(IP_MAC_entries)

    print('\nYour current ARP table:',end='')
    getArpTable()

    print('\n')
    duration=input('Enter how many SECONDS you would like to sniff packets:\n')
    while(type(duration)!=int or duration<1):
        try:
            duration=int(duration)
            if(duration<1):
                duration=int(input("Please enter a positive integer: "))
        except:
            duration=input("Please enter an integer: ")
    
    Detect(duration)