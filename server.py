#!/usr/bin/python

#-----------------------------------------------------------------------------
#--	SOURCE FILE:	server.py -   Covert TCP Server
#--
#--	FUNCTIONS:		decode(string)
#--					parse(pkt)
#--					main					
#--
#--	DATE:			September 28, 2015
#--
#--	DESIGNERS:		Brij Shah
#--
#--	PROGRAMMERS:	Brij Shah
#--
#--	NOTES:
#--	Server sniffs all packets coming into the machine and waits for a specified
#-- 'flag' of some sort to being collecting the necessary packets. In this case,
#-- any packet with a TCP window size of 4096 is collected. The server then
#-- converts the last octect of the source IP from a number to a character
#-- and writes it to a file.
#-----------------------------------------------------------------------------

import sys
import os
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

#-----------------------------------------------------------------------------
#-- FUNCTION:       decode(string)
#--
#-- VARIABLES(S):   string - the source IP to be split up by octect
#--
#-- NOTES:
#-- decode takes in a string (the source IP) and splits it up by octect.
#-- it returns the last octect of the IP which is a character of the covert
#-- message.
#-----------------------------------------------------------------------------
def decode(string):
	octets = string.split('.')
	return octets[3]

#-----------------------------------------------------------------------------
#-- FUNCTION:       parse(pkt)
#--
#-- VARIABLES(S):   pkt - a packet incoming into the machine
#--
#-- NOTES:
#-- parse goes through all packets coming into the machine. If any packet has
#-- a window size of 4096, it obtains the source IP, subtracts 10, converts it 
#-- to a character and writes it to a file.
#-----------------------------------------------------------------------------
def parse(pkt):
	wnd = pkt['TCP'].window
	if wnd == 4096:
		ip = pkt['IP'].src
		char = chr(int(decode(ip)) - 10)
		f = open('covert', 'a')
		f.write(ip + '(' + char + ')' + '\n')
		f.close()

#-----------------------------------------------------------------------------
#-- FUNCTION:       main()
#--
#-- NOTES:
#-- The pseudomain method, filters for IP and TCP traffic and calls the parse
#-- method.
#-----------------------------------------------------------------------------
def main():
	sniff(filter="ip and tcp", prn=parse)

if __name__ == '__main__':
	main()

	

