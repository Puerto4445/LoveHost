#!/usr/bin/python
import argparse
from termcolor import colored
import subprocess
import signal
import sys
from concurrent.futures import ThreadPoolExecutor
from pyfiglet import Figlet

def print_figlet(text):
    figlet = Figlet(font='banner3')
    ascii_art = figlet.renderText(text)
    lolcat_process = subprocess.Popen(['lolcat'], stdin=subprocess.PIPE)
    lolcat_process.communicate(input=ascii_art.encode())

def close_program(sig,frame):
    print(colored(f"\n[!] Hasta la proxima amor ","red"))
    sys.exit(1)

signal.signal(signal.SIGINT, close_program)


def Arg_parse():
    #192.168.111.1-255
    help = argparse.ArgumentParser(description="Descubre Host activos con (ICMP)")
    help.add_argument('-t','--target', required=True,dest="target",help="Ex: -t 192.168.0.1")
    arg = help.parse_args()
    return arg.target 

def Valid_target(target):
    target_split = target.split(".")
    three_octets = '.'.join(target_split[:3])

    if len(target_split) == 4:
        if "-" in target_split[3]:
            start,end=target_split[3].split("-")
            return [f"{three_octets}.{i}"for i in range(int(start),int(end)+1)]
        else:
            return [target]
    else:
        print(colored(f"\n[!] Formato o rango de IP desconocido\n","red"))

def descovery_host(target):
    try:
        discovery = subprocess.run(["ping","-c","1", target], timeout=1,stdout=subprocess.DEVNULL )
        if discovery.returncode == 0:
            print(colored(f"\n\tHost: {target} UP","green", attrs=["bold"]))
        
    except subprocess.TimeoutExpired:
        pass
    

def main():
    print_figlet("LOVEHOST")
    print("\n@puerto4444")
    print("-"*30)
    target = Arg_parse()    #El valor pasasdo esta en tipo string 
    targets = Valid_target(target)
    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(descovery_host,targets)

if __name__=="__main__":
    main()