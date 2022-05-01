from scapy.all import ICMP,IP,sr1,TCP,get_if_addr,conf
import ipaddress
import colorama
from colorama import Fore

class portScanner:
    def __init__(self):
        colorama.init(autoreset=True)
        self.__ip = get_if_addr(conf.iface)
        self.__srcPort = 3000
        self.__destPort = list(range(0,65534))
        # 22 - SSH, Secure logins, filetransfers and port forwarding
        # 23 - Telnet protocol - unencrypted text comms
        # 80 - HTTP uses TCP v1.x and 2
        # 443 - HTTPS uses TCP v1.x and 2
        # 3389 - Microsoft Terminal Server (RDP) official registered as Windows Based Terminal
        self.__checkCount = 0
        self.__activeCount = 0
        self.__unusedCount = 0
        self.__filteredCount = 0
        self.__unused = []
        self.__activee = []
        self.__filtered = []
    
    def scanport(self,ext=0):
        if ext==1:
            self.__ip = input("Enter IP address: ")
        self.start = int(input("Enter start value: "))
        self.stop = int(input("Enter stop value: "))
        
        for dstPort in self.__destPort:
            dstPort = dstPort + self.start
            # send SYN using port 3000 to dstPort
            resp = sr1(
                IP(dst=self.__ip)/TCP(sport=self.__srcPort,dport=dstPort,flags='S'),
                timeout=1,
                verbose=0,
            )

            if resp is None:
                self.__unused.append(dstPort)
                self.__unusedCount+=1
            
            elif (resp.haslayer(TCP)):
                # to close the connection if dstPort responds
                send_rst = sr1(
                    IP(dst=self.__ip)/TCP(sport=self.__srcPort,dport=dstPort,flags='R'),
                    timeout=1,
                    verbose=0,
                )

                self.__activeCount+=1
                self.__activee.append(dstPort)

            elif (resp.haslayer(ICMP)):
                if( int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    self.__filteredCount+=1
                    self.__filtered.append(dstPort)
                

            print(dstPort)
            self.__checkCount+=1
            if self.stop==self.__checkCount:
                break
            

    def showResults(self,ext=0):
        print("\n\n=====================================")   
        print("Total checks = " + Fore.GREEN + f"{self.__checkCount}")
        self.showActive()
        self.showFiltered()
        if ext==0:
            self.showUnused()
        print("=====================================")  

    def showActive(self):
        print("\nActive ports = " + Fore.GREEN + f"{self.__activeCount}")
        print("---------------------")        
        for i in self.__activee:
            print(i)
        print("---------------------")

    def showUnused(self):
        print(f"\nUnused ports = "+ Fore.GREEN +f"{self.__unusedCount}")
        print("---------------------")        
        for i in self.__unused:
            print(i)
        print("---------------------")

    def showFiltered(self):
        print(f"\nFiltered ports = "+ Fore.GREEN +f"{self.__filteredCount}")
        print("---------------------")        
        for i in self.__filtered:
            print(i)
        print("---------------------")      

