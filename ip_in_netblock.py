#!/usr/bin/env python
#
# This script takes as input a file containing IP networks and a file containing
# IP addresses.  It then outputs all networks that contain at least one IP
# address.

import sys
import netaddr

def main():

    if len(sys.argv) != 3:
        print >> sys.stderr, ("\nUsage: %s NETWORKS_FILE IP_ADDR_FILE\n" %
                              sys.argv[0])
        return 1

    networks_file = sys.argv[1]
    ip_addr_file = sys.argv[2]

    networks = []
    affected_networks = set()

    with open(networks_file, "r") as fd:
        for line in fd.readlines():
            networks.append(netaddr.IPNetwork(line.strip()))

    print >> sys.stderr, "Done parsing networks."

    with open(ip_addr_file, "r") as fd:
        for line in fd.readlines():
            for network in networks:
                if netaddr.IPAddress(line) in network:
                    affected_networks.add(network)

    for network in affected_networks:
        print network

    return 0


if __name__ == "__main__":
    sys.exit(main())
