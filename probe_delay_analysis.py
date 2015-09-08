#!/usr/bin/env python
#
# This script determines the delay between decoy connection and probing
# connection.

import sys

import scapy.all as scapy

decoy_conns = {}
time_deltas = {}


def analyse_pcap(pcap_file, ip_addr):
    prev = 0

    for packet in scapy.PcapReader(pcap_file):

        # Weed out everything which is not a TCP SYN segment.

        if (not scapy.TCP in packet) or (not packet[scapy.TCP].flags == 2):
            continue

        # Add timestamp and port for our reference IP address.

        if packet[scapy.IP].src == ip_addr:
            if prev == 0: prev = packet.time
            decoy_conns[packet[scapy.TCP].dport] = packet.time
            print int(packet.time) - int(prev)
            prev = packet.time
            continue

        # Figure out time delta.

        time = decoy_conns.get(packet[scapy.TCP].dport)
        if time is not None:
            delta = packet.time - time

            del decoy_conns[packet[scapy.TCP].dport]

            time_deltas[packet[scapy.TCP].dport] = delta

    # Dump CSV to stdout.

    print "delay, port"
    ports = time_deltas.keys()
    for port in ports:
        print "%.3f, %d" % (time_deltas[port], port)

def main():

    if len(sys.argv) != 3:
        print >> sys.stderr, "\nUsage: %s PCAP_FILE IP_ADDR\n" % sys.argv[0]
        return 1
    pcap_file = sys.argv[1]
    ip_addr = sys.argv[2]

    analyse_pcap(pcap_file, ip_addr)

    return 0

if __name__ == "__main__":
    sys.exit(main())
