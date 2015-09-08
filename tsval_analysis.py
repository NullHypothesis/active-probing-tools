#!/usr/bin/env python
#
# This script extracts the TSval from the TCP header.

import sys

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

    print "x, y"

    for packet in scapy.PcapReader(pcap_file):

        # Weed out SYN retransmissions.

        if is_retransmission(packet):
            continue

        for opt_name, opt_val in packet[scapy.TCP].options:
            if opt_name == "Timestamp":
                print packet.time, opt_val[0]


def main():

    if len(sys.argv) != 2:
        print >> sys.stderr, "\nUsage: %s PCAP_FILE\n" % sys.argv[0]
        return 1
    pcap_file = sys.argv[1]

    analyse_pcap(pcap_file)

    return 0

if __name__ == "__main__":
    sys.exit(main())
