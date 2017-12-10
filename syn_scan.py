import socket, argparse, sys, logging
from time import sleep
from struct import pack, unpack
from scapy.all import *
from multiprocessing import Process

# script usage
parser = argparse.ArgumentParser(description="TCP SYN SCAN IN SPECIFIED INTERVALS. Scan result will be store in syn_scan.log")
parser.add_argument('-s','--source', help='Source IP | x.x.x.x',required=True)
parser.add_argument('-d','--destination',help='Destination IP | x.x.x.x', required=True)
parser.add_argument('-w','--wait',help='Time interval in milisecond | x', required=True)
args = parser.parse_args()

# conver second to milisecond
args.wait = float(args.wait) / 1000

# save output to file
logfile="syn_scan.log"
logging.basicConfig(filename=logfile, format='%(message)s', level=logging.INFO)

# TCP checksum function
def checksum(source_string):
    sum = 0
    count_to = (len(source_string) / 2) * 2
    count = 0
    while count < count_to:
        this_val = ord(source_string[count + 1])*256+ord(source_string[count])
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2
    if count_to < len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

# parse data from sniffer
def parser(data):
    if data.haslayer(TCP):
        sport = data.sprintf("%TCP.sport%")
        if sport.isdigit():
            print(data.sprintf("%TCP.flags% %IP.src%:" + sport))
            logging.info(data.sprintf("%TCP.flags% %IP.src%:" + sport + " %.time%"))
        else:
            sport = TCP_SERVICES[sport]
            print(data.sprintf("%TCP.flags% %IP.src%:" + str(sport)))
            logging.info(data.sprintf("%TCP.flags% %IP.src%:" + str(sport) + " %.time%"))

# sniff in backgorund packet from destination            
def _multisniffer(destination, future): 
    try:
        print("ip src host " + destination +" and tcp dst port 65534")
        sniff(filter="ip src host " + destination +" and tcp dst port 65534", prn=parser, store=0)
    except KeyboardInterrupt:
        exit(0)

 
# create socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) 
 
source = 65534              # source port, identifies the sending port
dest = 1234                 # destination port, identifies the receiving port
seq = 0                     # sequence number, this is the initial sequence number
ack_seq = 0                 # acknowledgment number, sequence number of the actual first data byte and the acknowledged number
offset_res = (5 << 4) + 0   # Data offset, specifies the size of the TCP header in 32-bit words, 5 * 4 = 20 bytes

#tcp flags, these are control bits that indicate different connection states or information about how a packet should be handled
fin = 0                     # last packet from sender.
syn = 1                     # synchronize sequence numbers. Only the first packet sent from each end should have this flag set.
rst = 0                     # reset the connection
psh = 0                     # push function. asks to push the buffered data to the receiving application.
ack = 0                     # indicates that the Acknowledgment field is significant. All packets after the initial SYN packet sent by the client should have this flag set.
urg = 0                     # If the URG flag is set, the receiving station evaluates the urgent pointer, a 16-bit field in the TCP header. 
ecn = 0                     # congestion control mechanism
cwr = 0                     # congestion control mechanism
window = socket.htons (8192)    # maximum allowed window size
check = 0                   # checksum
urg_ptr = 0                 # This pointer indicates how much of the data in the segment, counting from the first byte, is urgent.

reserved = 0

# merge TCP flags
tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5) + (ecn << 6) + (cwr << 7)

# run sniffer in background and wait 2 second
p = Process(target=_multisniffer, args=(args.destination,2))
p.start()
try:
    sleep(2)
except KeyboardInterrupt:
    exit(0) 

# TCP port range 1-65535
for x in range(1, 65535 + 1):
    # build TCP header, checksum = 0
    check = 0
    tcp_header = pack('!HHLLBBHHH' , source, x, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)
    # build IP header
    IP_header = pack("!4s4sBBH", socket.inet_aton(args.source), socket.inet_aton(args.destination), reserved, socket.IPPROTO_TCP, len(tcp_header))
    # calculate checksum from IP and TCP headers
    check = checksum(IP_header + tcp_header)
    # build TCP header, correct checksum
    tcp_header = pack('!HHLLBBHHH' , source, x, seq, ack_seq, offset_res, tcp_flags,  window, check, urg_ptr)

    try:
        sent = s.sendto(tcp_header, (args.destination, 1))
    except:
        print("Unexpected error. Repeat SCAN.")
    
    try:
        sleep(args.wait)
    except KeyboardInterrupt:
        exit(0)    
        
    if x%1000 == 0:
        print(x)

#kill sniffer
p.terminate()