#!/usr/bin/env python
#
# This script analysis TCP initial sequence numbers, similar to how it was done
# in the book "Silence on the Wire".

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

    really_old_seq = quite_old_seq = old_seq = current_seq = 0

    print "x, y"

    packets = scapy.rdpcap(pcap_file)
    for packet in packets:

        # Weed out SYN retransmissions.

        if is_retransmission(packet):
            continue

        really_old_seq = quite_old_seq
        quite_old_seq = old_seq
        old_seq = current_seq
        current_seq = packet[scapy.TCP].seq

        x = current_seq - old_seq
        y = old_seq - quite_old_seq
        z = quite_old_seq - really_old_seq

        if x < 0:
            x = SEQ_MAX - abs(x)
        if y < 0:
            y = SEQ_MAX - abs(y)
        if z < 0:
            z = SEQ_MAX - abs(z)

        print "%d, %d" % (x, y)


def main():

    if len(sys.argv) != 2:
        print >> sys.stderr, "\nUsage: %s PCAP_FILE\n" % sys.argv[0]
        return 1
    pcap_file = sys.argv[1]

    analyse_pcap(pcap_file)

    return 0

if __name__ == "__main__":
    sys.exit(main())
