from scapy.all import *
import signal
import sys
def signal_handler(sig, frame):
    print('Stopping the scanner...')
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

def ping(target):
    #Check if the target machine is online using an ICMP ping.
    res, unans = sr(IP(dst=target)/ICMP(), timeout=3, verbose=0)
    live_ips = {received.src for sent, received in res}
    print("\nScan Results:")
    for ip in live_ips:
            print(f"{ip} is up")

def scan(target):
    #Perform TCP SYN scan to check for open ports
    res,unans = sr(IP(dst=target)/TCP(flags="S", dport=(1,100)), timeout=1, verbose=0)
    print("Scan results:")
    for s,r in res:
        if r[TCP].flags == 0x12:
            print(f"Port {s[TCP].dport} in {s[IP].dst} is open")
        elif r[TCP].flags == 0x14:
            print(f"Port {s[TCP].dport} in {s[IP].dst} is closed")
    for s in unans:
        print(f"Port {s[TCP].dport} in {s[IP].dst} is closed or filtered.")

print("Please write the target IP to scan, this can be a single IP, an IP range, a list of IPs or even a hostname.")
print("Examples: \nSingle IP = 192.168.0.1      IP list: 192.168.0.1, 172.18.0.1, 10.0.0.8\nIP range: 192.168.0.1/24     Hostname: example.com\n")
targetraw = input("> ")
print()
if ',' in targetraw:
    target = targetraw.split(',')
    target = [i.strip(' ') for i in target]
else:
    target = targetraw

def changescan():
    print("What kind of scan do you want to perform?\n1. ICMP Ping  2. TCP SYN\n")
    scantype = input("> ")
    match scantype:
        case "1":
            ping(target)
        case "2":
            scan(target)
        case _:
            print("\nPlease write only the number")
            changescan()
changescan()
