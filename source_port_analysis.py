#!/usr/bin/env python

import sys
import time

import scapy.all as scapy

SEQ_MAX = 2**32 - 1

previous_packets = set()


def is_retransmission(packet):

    packet_key = "%d%d%d" % (packet[scapy.TCP].sport,
                             packet[scapy.TCP].dport,
                             packet[scapy.TCP].seq)

    if packet_key in previous_packets:
        return True
    else:
        previous_packets.add(packet_key)
        return False


def analyse_pcap(pcap_file):

    old_port = 0

    for packet in scapy.PcapReader(pcap_file):

        # Weed out SYN retransmissions.

        if (not scapy.TCP in packet) or (not packet[scapy.TCP].flags == 2):
            continue

        if packet[scapy.IP].src == "211.155.86.135":
            continue

        print packet[scapy.IP].src
        continue

        if is_retransmission(packet):
            continue

        t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.time))
        #diff = packet[scapy.TCP].sport - old_port
        #if diff < 0:
        #    diff = 65535 - abs(diff)
        #print diff

        #old_port = packet[scapy.TCP].sport

        #for opt_name, opt_val in packet[scapy.TCP].options:
        #    if opt_name == "Timestamp":
                #print packet.time, opt_val[0]

        if packet[scapy.IP].src == "211.155.86.135":
            print "%s, %d, 1" % (t, packet[scapy.TCP].dport)
        else:
            print "%s, %d, 0" % (t, packet[scapy.TCP].dport)


def main():

    if len(sys.argv) != 2:
        print >> sys.stderr, "\nUsage: %s PCAP_FILE\n" % sys.argv[0]
        return 1
    pcap_file = sys.argv[1]

    analyse_pcap(pcap_file)

    return 0

if __name__ == "__main__":
    sys.exit(main())
