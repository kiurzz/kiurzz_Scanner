import argparse
import csv
import ipaddress
import queue
import socket
from threading import Thread


# Allows you to scan the network
def scanNetwork(address, q, hostnames):
    result = {}
    portopen = []
    threada = []
    try:
        hostname = socket.gethostbyaddr(str(address))[0]
        # Scanning common ports
        for port in range(1, 1024):
            t = Thread(target=scanPort, args=(address, port, portopen))
            threada.append(t)
            t.start()
        for t in threada:
            t.join()
        result["ip_addr"] = address
        result["hostname"] = hostname
        result["port_open"] = portopen
        hostnames.append(result)
    except socket.herror:
        pass
    q.put(hostnames)


# Allows you to scan ports
def scanPort(address, port, portopen):
    try:
        socket.setdefaulttimeout(1)
        socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        resultscan = socket_obj.connect_ex((str(address), port))
        socket_obj.close()
        if resultscan == 0:
            portopen.append(port)
    except:
        pass


if __name__ == '__main__':
    print("""\
 __  ___  __   __    __  .______      ________   ________             _______.  ______     ___      .__   __. .__   __.  _______ .______      
|  |/  / |  | |  |  |  | |   _  \    |       /  |       /            /       | /      |   /   \     |  \ |  | |  \ |  | |   ____||   _  \     
|  '  /  |  | |  |  |  | |  |_)  |   `---/  /   `---/  /            |   (----`|  ,----'  /  ^  \    |   \|  | |   \|  | |  |__   |  |_)  |    
|    <   |  | |  |  |  | |      /       /  /       /  /              \   \    |  |      /  /_\  \   |  . `  | |  . `  | |   __|  |      /     
|  .  \  |  | |  `--'  | |  |\  \----. /  /----.  /  /----.      .----)   |   |  `----./  _____  \  |  |\   | |  |\   | |  |____ |  |\  \----.
|__|\__\ |__|  \______/  | _| `._____|/________| /________| _____|_______/     \______/__/     \__\ |__| \__| |__| \__| |_______|| _| `._____|
                                                           |______|                                                                           """)

    print("kiurzz_Scanner | Advanced Network Scanner")
    print("Help is available with the command : python3 kiurzz_Scanner.py -h\n")
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--network',
                        help='Allows to define the IP address and its subnet mask. ex : 192.168.1.0/24', type=str,
                        required=True)
    parser.add_argument('-f', '--file', help='Name of the file where to put the results. (default: networkscan.csv) ',
                        type=str, required=False)
    # We retrieve the arguments given by the user
    args = parser.parse_args()
    # Allows you to create an ip_network object to be able to manipulate the ip address.
    networktoscan = ipaddress.ip_network(args.network, strict=False)

    # If the parameter file is set
    if args.file:
        file = args.file
    # If the parameter file is not set
    else:
        file = "networkscan.csv"

        q = queue.Queue()
        threads = []
        hostnames = []

        # For each address on the network, a scan is launched.
        for address in networktoscan.hosts():
            t = Thread(target=scanNetwork, args=(address, q, hostnames))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        hostnames = q.get()

        # Allows you to write to a .csv file
        try:
            with open(file, 'w') as csvfile:
                writer = csv.DictWriter(
                    csvfile, fieldnames=['Ip_addr', 'HostName', 'Open_ports'])
                writer.writeheader()
                for data in hostnames:
                    for key in data.keys():
                        csvfile.write("%s, %s, %s\n" % (data["ip_addr"], data["hostname"], data["port_open"]))
            print("The " + file + " file has been successfully generated.")
        except:
            pass

        # Print results
        print("Scan Result : ")
        for data in hostnames:
            print(data["ip_addr"], '=>', data["hostname"])
            if len(data["port_open"]) > 0:
                print("Open ports :")
                for port in data["port_open"]:
                    print("[*]" + str(port))
            else:
                print("No open ports.")
            print("--------------------")
