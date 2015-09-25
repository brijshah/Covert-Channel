#!/usr/bin/python

import sys
import os
from scapy.all import *

f = open('covert', 'w')

def decode(string):
	octets = string.split('.')
	return octets[3]

def parse(pkt):
	port = pkt['TCP'].dport
	if port == 80:
		ip = pkt['IP'].src
		char = chr(int(decode(ip)))
		f.write(ip + '(' + char + ')' + '\n')

def main():
	sniff(filter="ip and tcp", prn=parse)

if __name__ == '__main__':
	main()

	

