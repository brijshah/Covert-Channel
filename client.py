#!/usr/bin/python

import sys
import os
import argparse
import setproctitle
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

parser = argparse.ArgumentParser(description='Covert Channels')
parser.add_argument('-d', '--destination', dest='dest_ip', help='destination IP address', required=True)
parser.add_argument('-m', '--message', dest='msg', help='message to send', required=True)
args = parser.parse_args()

def encrypt(message, key):
	des = ARC4.new(key)
	return des.encrypt(message)

def decrypt(cipher_text, key):
	des = ARC4.new(key)
	return des.decrypt(cipher_text)

def craft_packet(int):
	global pkt
	pkt = IP(dst=args.dest_ip, src="192.168.0."+`int`)/TCP(sport=RandNum(0, 65335), dport=8000, window=4096)
	return pkt

def send_packet():
	msg = args.msg
	for char in msg:
		num_char = ord(char)
		new_pkt = craft_packet(num_char)
		send(new_pkt)

def main():
	setproctitle.setproctitle("messenger")
	send_packet()

if __name__ == '__main__':
	main()