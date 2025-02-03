from scapy.all import *
import signal
import sys
import os
def signal_handler(sig, frame):
    print('Stopping the scanner...')
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

def ping(target):
    os.system("clear")
    #Check if the target machine is online using an ICMP ping.
    res, unans = sr(IP(dst=target)/ICMP(), timeout=3, verbose=0)
    live_ips = {received.src for sent, received in res}
    print("\nScan Results:")
    for ip in live_ips:
            print(f"{ip} is up")

def scan(target, ports):
    os.system("clear")
    #check if ports are a list and sanitize them
    if type(ports) == list:
        #Perform TCP SYN scan to check for open ports
        res,unans = sr(IP(dst=target)/TCP(flags="S", dport=(int(ports[0]),int(ports[1]))), timeout=1, verbose=0)
    else:
        res,unans = sr(IP(dst=target)/TCP(flags="S", dport=(int(ports))), timeout=1, verbose=0)
    print("Scan results:")
    for s,r in res:
        if r[TCP].flags == 0x12:
            print(f"Port {s[TCP].dport} in {s[IP].dst} is open")
        elif r[TCP].flags == 0x14:
            print(f"Port {s[TCP].dport} in {s[IP].dst} is closed")
    for s in unans:
        print(f"Port {s[TCP].dport} in {s[IP].dst} is closed or filtered.")

def changeip(target, ports):
    os.system("clear")
    print("Please write the target IP to scan, this can be a single IP, an IP range, a list of IPs or even a hostname.")
    print("Examples: \nSingle IP = 192.168.0.1      IP list: 192.168.0.1, 172.18.0.1, 10.0.0.8\nIP range: 192.168.0.1/24     Hostname: example.com\n")
    targetraw = input("> ")
    if ',' in targetraw:
        target = targetraw.split(',')
        target = [i.strip(' ') for i in target]
    else:
        target = targetraw
    menu(target, ports)

def changescan(target, ports):
    os.system("clear")
    print("What kind of scan do you want to perform?\n1. ICMP Ping  2. TCP SYN\n")
    scantype = input("> ")
    match scantype:
        case "1":
            ping(target)
        case "2":
            scan(target, ports)
        case _:
            print("\nPlease write only the number")
            changescan()

def changeports(target, ports):
    os.system("clear")
    print("Please type a range of ports or a sigle port to scan.\nAccepted formats:   1. A range of ports     2. A single port: 80")
    ports = input('> ')
    match ports:
        case "1":
            print("Please type the first port to scan:")
            port1 = input("> ")
            print("Please type the final port to scan:")
            port2 = input("> ")
            ports = [port1, port2]
        case "2":
            print("Please enter the port to scan:")
            ports = input("> ")
        case _:
            print("Please provide a valid option.")
    menu(target, ports)

def menu(target, ports):
    os.system("clear")
    print("\033[31m.▄▄ · ▪  • ▌ ▄ ·.  ▄▄▄·▄▄▌  ▄▄▄ .    .▄▄ ·  ▄▄·  ▄▄▄·  ▐ ▄  ▐ ▄ ▄▄▄ .▄▄▄  \033[0m")
    print("\033[31m▐█ ▀. ██ ·██ ▐███▪▐█ ▄███•  ▀▄.▀·    ▐█ ▀. ▐█ ▌▪▐█ ▀█ •█▌▐█•█▌▐█▀▄.▀·▀▄ █·\033[0m")
    print("\033[31m▄▀▀▀█▄▐█·▐█ ▌▐▌▐█· ██▀·██▪  ▐▀▀▪▄    ▄▀▀▀█▄██ ▄▄▄█▀▀█ ▐█▐▐▌▐█▐▐▌▐▀▀▪▄▐▀▀▄ \033[0m")
    print("\033[31m▐█▄▪▐█▐█▌██ ██▌▐█▌▐█▪·•▐█▌▐▌▐█▄▄▌    ▐█▄▪▐█▐███▌▐█ ▪▐▌██▐█▌██▐█▌▐█▄▄▌▐█•█▌\033[0m")
    print("\033[31m ▀▀▀▀ ▀▀▀▀▀  █▪▀▀▀.▀   .▀▀▀  ▀▀▀      ▀▀▀▀ ·▀▀▀  ▀  ▀ ▀▀ █▪▀▀ █▪ ▀▀▀ .▀  ▀\033[0m")
    print(f"Current values: Target:\033[31m{target}\033[0m   Ports to scan:\033[31m{ports}\033[0m\nTo change these settings use the following options: 1. Change target IP   2. Change ports to scan   3. Start scan   4. Exit")
    menuoption = input("> ")
    match menuoption:
        case "1":
            changeip(target, ports)
        case "2":
            changeports(target, ports)
        case "3":
            changescan(target, ports)
        case "4":
            exit()
        case _:
            print("Please provide a valid option, only write the number of the option that you want to use.")
            menu(target, ports)

menu(None, None)
