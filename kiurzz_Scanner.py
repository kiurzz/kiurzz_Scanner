import argparse
import ipaddress
import socket
from threading import Thread 
import queue

hotes_trouves = 0

if __name__ == '__main__':
	print("""\
 __  ___  __   __    __  .______      ________   ________             _______.  ______     ___      .__   __. .__   __.  _______ .______      
|  |/  / |  | |  |  |  | |   _  \    |       /  |       /            /       | /      |   /   \     |  \ |  | |  \ |  | |   ____||   _  \     
|  '  /  |  | |  |  |  | |  |_)  |   `---/  /   `---/  /            |   (----`|  ,----'  /  ^  \    |   \|  | |   \|  | |  |__   |  |_)  |    
|    <   |  | |  |  |  | |      /       /  /       /  /              \   \    |  |      /  /_\  \   |  . `  | |  . `  | |   __|  |      /     
|  .  \  |  | |  `--'  | |  |\  \----. /  /----.  /  /----.      .----)   |   |  `----./  _____  \  |  |\   | |  |\   | |  |____ |  |\  \----.
|__|\__\ |__|  \______/  | _| `._____|/________| /________| _____|_______/     \______/__/     \__\ |__| \__| |__| \__| |_______|| _| `._____|
                                                           |______|                                                                           """)

	print("kiurzz_Scanner | Best LP Cyber Network Scanner")
	print("Aide & arguments disponibles: python3 kiurzz_Scanner.py -h\n")
	parser = argparse.ArgumentParser()
	parser.add_argument('-n','--network', help='Permet de spécifier un réseau et son masque. ex : 192.168.1.0/24', type=str, required=True)
	args = parser.parse_args()
	networktoscan = ipaddress.ip_network(args.network, strict=False)

def gethostname(address, q, hostnames):

    try:
        hostname, alias, _ = socket.gethostbyaddr(str(address))
    except socket.herror:
        hostname = None
        alias = None
    hostnames[address] = hostname
    q.put(hostnames)

q = queue.Queue()

threads = []

hostnames = {}

for address in networktoscan.hosts():
    t = Thread(target=gethostname, args=(address,q, hostnames))
    threads.append(t)

for t in threads:
    t.start()
for t in threads:
    t.join()

hostnames = q.get()

for address, hostname in hostnames.items():
    if (hostname != None):
        print(address, '=>', hostname)
        hotes_trouves = hotes_trouves+1
print("\n"+str(hotes_trouves)+" hôte(s) trouvé(s) sur le réseau spécifié")
