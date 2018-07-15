from scapy.all import *
import socket
from datetime import datetime


def SniffPacket(log_file):
    'sniffs the interface for incoming and outgoing packets'
    sniff(iface='Broadcom 802.11n Network Adapter',
          prn=packet2log_with_filename(log_file),
          lfilter=lambda (pkt): IP in pkt and TCP in pkt)


def packet2log_with_filename(log_file):
    'function within function in order to use the packet parameter for packet2log and still be able to specify a filename in which to write the logs'
    def packet2log(pkt):
        'receives a packet and converts into a log in the desired format'
        pkt_time = str(datetime.now()).split('.')[0]
        log_line = '{} {} {} {} {}'.format(pkt_time,
                                           pkt[IP].src,
                                           pkt[IP].dst,
                                           pkt[TCP].dport,
                                           'PASS')
        print log_line
        log_file.write(log_line + '\n')
        log_file.flush()
    return packet2log

def main():
    with open('ScapyLogs.txt', 'a') as log_file:
        SniffPacket(log_file)

if __name__ == '__main__':
    main()


#function to view available interfaces to sniff
'''def get_interfaces():
    interfaces = []

    for iface_name in sorted(ifaces.data.keys()):
        dev = ifaces.data[iface_name]
        i = name=str(dev.name).ljust(4)
        interfaces.append(i)
    return interfaces

print get_interfaces()'''
