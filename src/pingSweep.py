import ipaddress
from scapy.all import ICMP,IP,sr1,TCP,get_if_addr,conf
import colorama
from colorama import Fore


class pingSweep:
    def __init__(self):
        colorama.init(autoreset=True)
        # getting the network range for currently connected network
        self.addr = ipaddress.ip_network(get_if_addr(conf.iface)+'/'+'255.255.255.0',strict=False)

        self.respCount = 0
        self.blockCount = 0
        self.checkCount = 0
        self.blocks = []
        self.active = []
        
        
    def sweep(self):
        self.start = int(input("Enter start value: "))
        self.stop = int(input("Enter stop value: "))
        for host in self.addr:
            host = host + self.start
            if (host in (self.addr.network_address,self.addr.broadcast_address)):
                #ignore if address is x.x.x.0 or   x.x.x.255 
                continue          

            print(host)

            resp = sr1(
                IP(dst=str(host))/ICMP(),
                timeout=2,
                verbose=0,
            )

            if resp is None:
                pass
            elif (int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code in [1,2,3,9,10,13])):
                self.block.append(host)
                self.blockCount+=1
            else:
                self.active.append(host)
                self.respCount+=1
            
            self.checkCount += 1
            if self.stop==self.checkCount:
                break
        


    def showResults(self):
        print("\n\n=====================================")   
        print("Total checks = " + Fore.GREEN + f"{self.checkCount}")
        self.showActive()
        self.showBlock()
        print("=====================================")   

    def showActive(self):
        print("\nActive hosts = " + Fore.GREEN + f"{self.respCount}")
        print("---------------------")        
        for i in self.active:
            print(i)
        print("---------------------")

    def showBlock(self):
        print(f"\nActive but blocking hosts = "+ Fore.GREEN +f"{self.blockCount}")
        print("---------------------")        
        for i in self.blocks:
            print(i)
        print("---------------------")

