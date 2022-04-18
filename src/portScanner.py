from scapy.all import ICMP,IP,sr1,TCP,get_if_addr,conf
import ipaddress
import colorama
from colorama import Fore

class portScanner:
    def __init__(self):
        colorama.init(autoreset=True)
        self.ip = get_if_addr(conf.iface)
        self.srcPort = 3000
        self.destPort = list(range(0,65534))
        # 22 - SSH, Secure logins, filetransfers and port forwarding
        # 23 - Telnet protocol - unencrypted text comms
        # 80 - HTTP uses TCP v1.x and 2
        # 443 - HTTPS uses TCP v1.x and 2
        # 3389 - Microsoft Terminal Server (RDP) official registered as Windows Based Terminal
        self.checkCount = 0
        self.activeCount = 0
        self.unusedCount = 0
        self.filteredCount = 0
        self.unused = []
        self.active = []
        self.filtered = []
    
    def check(self):
        self.start = int(input("Enter start value: "))
        self.stop = int(input("Enter stop value: "))
        
        for dstPort in self.destPort:
            dstPort = dstPort + self.start
            # send SYN using port 3000 to dstPort
            resp = sr1(
                IP(dst=self.ip)/TCP(sport=self.srcPort,dport=dstPort,flags='S'),
                timeout=1,
                verbose=0,
            )

            if resp is None:
                self.unused.append(dstPort)
                self.unusedCount+=1
            
            elif (resp.haslayer(TCP)):
                # to close the connection if dstPort responds
                send_rst = sr1(
                    IP(dst=self.ip)/TCP(sport=self.srcPort,dport=dstPort,flags='R'),
                    timeout=1,
                    verbose=0,
                )

                self.activeCount+=1
                self.active.append(dstPort)

            elif (resp.haslayer(ICMP)):
                if( int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    self.filteredCount+=1
                    self.filtered.append(dstPort)
                

            print(dstPort)
            self.checkCount+=1
            if self.stop==self.checkCount:
                break

    def scanExtPort(self):
        self.ip = input("Enter IP address: ")
        self.start = int(input("Enter start value: "))
        self.stop = int(input("Enter stop value: "))
        
        for dstPort in self.destPort:
            dstPort = dstPort + self.start
            # send SYN using port 3000 to dstPort
            resp = sr1(
                IP(dst=self.ip)/TCP(sport=self.srcPort,dport=dstPort,flags='S'),
                timeout=1,
                verbose=0,
            )

            if resp is None:
                self.unused.append(dstPort)
                self.unusedCount+=1
            
            elif (resp.haslayer(TCP)):
                # to close the connection if dstPort responds
                send_rst = sr1(
                    IP(dst=self.ip)/TCP(sport=self.srcPort,dport=dstPort,flags='R'),
                    timeout=1,
                    verbose=0,
                )

                self.activeCount+=1
                self.active.append(dstPort)

            elif (resp.haslayer(ICMP)):
                if( int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    self.filteredCount+=1
                    self.filtered.append(dstPort)
                

            print(dstPort)
            self.checkCount+=1
            if self.stop==self.checkCount:
                break



    def showResults(self):
        print("\n\n=====================================")   
        print("Total checks = " + Fore.GREEN + f"{self.checkCount}")
        self.showActive()
        self.showFiltered()
        self.showUnused()
        print("=====================================")  

    def showActive(self):
        print("\nActive ports = " + Fore.GREEN + f"{self.activeCount}")
        print("---------------------")        
        for i in self.active:
            print(i)
        print("---------------------")

    def showUnused(self):
        print(f"\nUnused ports = "+ Fore.GREEN +f"{self.unusedCount}")
        print("---------------------")        
        for i in self.unused:
            print(i)
        print("---------------------")

    def showFiltered(self):
        print(f"\nFiltered ports = "+ Fore.GREEN +f"{self.filteredCount}")
        print("---------------------")        
        for i in self.filtered:
            print(i)
        print("---------------------")      

