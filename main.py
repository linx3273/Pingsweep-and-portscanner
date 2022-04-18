import sys
import src.usage as usage
from src.portScanner import portScanner
from src.pingSweep import pingSweep

def main():
    if len(sys.argv)==1:
        print(usage.inf())
    else:
        if sys.argv[1]=="--help" or sys.argv[1]=="-h":
            print(usage.inf())
        
        elif sys.argv[1]=="scanport":
            obj = portScanner()
            obj.check()
            obj.showResults()
        elif sys.argv[1]=="pingsweep":
            obj = pingSweep()
            obj.sweep()
            obj.showResults()
        elif sys.argv[1]=="extport":
            obj = portScanner()
            obj.scanExtPort()
            obj.showResults()

        else:
            print("Invalid arguments. Run 'python main.py --help'")


if __name__=="__main__":
    main()