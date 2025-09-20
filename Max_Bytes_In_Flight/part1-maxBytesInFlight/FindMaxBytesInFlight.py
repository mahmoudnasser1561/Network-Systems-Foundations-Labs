#!/usr/bin/python3

from scapy.all import *


### 
# LAB REQUIREMENT
# Implement findMaxBytesInFlight - which takes in the name of a pcap file, and finds
#                                  the maximum number of bytes in flight during the session
#                                  Basically highest sequence number of sent packets minus
#                                  the highest acknowledgement number received
# Note: you only need to look at direction from server to client 
# (which you can tell from three way handshake - client will initiate the connection)
# Note: you need to take into account dropped packets and out of order packets
# Note: you can use the data structure and helper functions provided, but don't need to.


# This class captures some information about a unidirectional flow
# startSeqNum - the starting TCP sequence number for data sent in this flow
# ackNumReceived - tracks the highest acknowledgement number received
# highestSeqNum - for data sent, this holds the highest sequence number seen
# pktLenOfHighestSeqNumPacket - for the packet that was the highestSeqNum, this is the length of that packet
# srcIP - the IP address for the source in this flow (the one sending data and the seq num refers to)
# destIP - the IP address for the destination in this flow
class FlowTracking:
    def __init__(self, startSeqNum, ackNumReceived, srcIP, dstIP):
        self.startSeqNum = startSeqNum;
        self.ackNumReceived = ackNumReceived;
        self.highestSeqNum = 0;
        self.pktLenOfHighestSeqNumPacket = 0;
        self.srcIP = srcIP;
        self.dstIP = dstIP; 

# Returns FlowTracking object for the server side 
# (client sends the syn, server sends the synack, client sends ack)
def readHandShake(pcap):
   # read syn
   p = pcap.pop(0);
   seqInit = p[TCP].seq;
   srcInit = p[IP].src;
   dstInit = p[IP].dst;

   # read ack
   p = pcap.pop(0);
   if (p[TCP].ack != seqInit+1):
      print(string("ERROR: seq="+seqInit+", ack="+p[TCP].ack ));
   if (p[IP].src != dstInit or p[IP].dst != srcInit):
      print(string("ERROR: srcInit="+srcInit+", destInit="+dstInit+"Resp: src="+p[IP].src+",dst="+p[IP].dst ));

   seqOther = p[TCP].seq

   # read synack
   p = pcap.pop(0);
   if (p[TCP].ack != seqOther+1):
      print(string("ERROR: seq="+seqInit+", ack="+p[TCP].ack ));
   if (p[IP].src != srcInit or p[IP].dst != dstInit):
      print(string("ERROR: srcInit="+srcInit+", destInit="+dstInit+"Resp: src="+p[IP].src+",dst="+p[IP].dst ));

   return FlowTracking(seqOther, seqOther+1, dstInit, srcInit)


# Returns true if the packet p is in the direction of the unidirectional
# flow represented by f (FlowTracking)
def isFlowEgress(p, f):
   if (p[IP].src == f.srcIP):
      return True
   return False


# TASK

# Given a pcap file name as a string, this function will return the max number of bytes
# that were in flight (unacknowledge) for this stream.
# Assume - only one TCP session (i.e., one pair of IP address and TCP ports)
#        - the pcap starts with the 3 way handshake as the first 3 packets
def findMaxBytesInFlight(pcapfile):   
   maxBytesInFlight = 0 

   # YOUR CODE HERE

   return maxBytesInFlight

def get_payload_len(p):
   payload_len = 0 

   # YOUR CODE HERE

   return payload_len

if __name__ == '__main__':
   # check for the expected payload lengths for a couple different packets
   pcap = rdpcap("simple-tcp-session.pcap")
   assert get_payload_len(pcap[3]) == 5

   pcap = rdpcap("out_10m_0p.pcap")
   assert get_payload_len(pcap[3]) == 122
   assert get_payload_len(pcap[5]) == 17

   # pcap is a server side capture
   maxBytesInFlight = findMaxBytesInFlight("simple-tcp-session.pcap")
   print("Max: " + str(maxBytesInFlight))
   print()

   maxBytesInFlight = findMaxBytesInFlight("out_10m_0p.pcap")
   print("Max: " + str(maxBytesInFlight))
   print()
