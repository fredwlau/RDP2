
# CS 352 project part 2 
# this is the initial socket library for project 2 
# You wil need to fill in the various methods in this
# library 

# main libraries 
import binascii
import socket as syssock
import struct
import sys
import time
from random import randint

# encryption libraries 
import nacl.utils
import nacl.secret
import nacl.utils
from nacl.public import PublicKey, PrivateKey, Box

# if you want to debug and print the current stack frame 
from inspect import currentframe, getframeinfo

# these are globals to the sock352 class and
# define the UDP ports all messages are sent
# and received from

# the ports to use for the sock352 messages 
global sock352portTx
global sock352portRx
# the public and private keychains in hex format 
global publicKeysHex
global privateKeysHex

# the public and private keychains in binary format 
global publicKeys
global privateKeys

# the encryption flag 
global ENCRYPT

publicKeysHex = {} 
privateKeysHex = {} 
publicKeys = {} 
privateKeys = {}

# this is 0xEC 
ENCRYPT = 236 

# this is the structure of the sock352 packet 
HEADER_STRUCT = '!BBBBHHLLQQLL'
HEADER_SIZE = struct.calcsize(HEADER_STRUCT)

#set header flags
SYN_VAL = 0x1
FIN_VAL = 0x2
ACK_VAL = 0x4
RESET_VAL = 0x8
OPTION_VAL = 0xA0

packet_size=8192

#header object for referencing
class packHeader:
	def __init__(self, theHeader=None):
		self.header_struct = struct.Struct(HEADER_STRUCT)

		#constructor for header fields
		if (theHeader is None):
			self.flags = 0
			self.version = 1
			self.opt_ptr = 0
			self.protocol = 0
			self.checksum = 0
			self.sequence_no = 0
			self.source_port = 0
			self.ack_no = 0
			self.dest_port = 0
			self.window = 0
			self.payload_len = 0
		else:
			#unpack header for receive function
			self.unpackHeader(theHeader)

	#Returns a packed header object
	def getPacketHeader(self):
		return self.header_struct.pack(self.version, self.flags, self.opt_ptr, self.protocol, struct.calcsize(HEADER_STRUCT), self.checksum, self.source_port, self.dest_port, self.sequence_no, self.ack_no, self.window, self.payload_len)

	#Returns an unpacked header
	def unpackHeader(self, theHeader):
		if len(theHeader) < 40:
			print ("Invalid Header"), len(theHeader)
			return -1
		if len(theHeader) > 40:
			print ("Invalid Header"), len(theHeader)
		header_array = self.header_struct.unpack(theHeader)
		self.version = header_array[0]
		self.flags = header_array[1]
		self.opt_ptr = header_array[2]
		self.protocol = header_array[3]
		self.header_len = header_array[4]
		self.checksum = header_array[5]
		self.source_port = header_array[6]
		self.dest_port = header_array[7]
		self.sequence_no = header_array[8]
		self.ack_no = header_array[9]
		self.window = header_array[10]
		self.payload_len = header_array[11]
		return header_array 

#packet object
class new_packet:
	def __init__(self, header=None, payload=None):
		#constructor for packet fields, differs from header by adding payload
		if header is None:
			self.header = packHeader()
		else:
			self.header = header
		if payload is None:
			self.payload = None
		else:
			self.payload = payload
			self.header.payload_len = len(self.payload)
		pass
	#Packs the packetheader and payload and combines them into one packet object
	def packPacket(self):
		packed_header = self.header.getPacketHeader()

		if (self.payload is None):
			packed_packet = packed_header
		else:
			packed_packet = packed_header + self.payload

		return packed_packet

	#Creates an ack packet
	def create_ack(self, rHeader):
		self.header.ack_no = rHeader.sequence_no + rHeader.payload_len
		self.header.sequence_no = rHeader.ack_no + 1;
		self.header.flags = ACK_VAL;
	#Creates a SYN packet
	def create_syn(self, seq_num):
		self.header.flags = SYN_VAL
		self.header.sequence_no = seq_num
		
def init(UDPportTx,UDPportRx):
	global sendPort
	global receivePort
	
	sendPort=1111
	receivePort=1111
	
	#init global socket for sending and receiving
	global global_socket
	global_socket = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)

	
# read the keyfile. The result should be a private key and a keychain of
# public keys
def readKeyChain(filename):
	global publicKeysHex
	global privateKeysHex 
	global publicKeys
	global privateKeys 
	
	if (filename):
		try:
			keyfile_fd = open(filename,"r")
			for line in keyfile_fd:
				words = line.split()
				# check if a comment
				# more than 2 words, and the first word does not have a
				# hash, we may have a valid host/key pair in the keychain
				if ( (len(words) >= 4) and (words[0].find("#") == -1)):
					host = words[1]
					port = words[2]
					keyInHex = words[3]
					if (words[0] == "private"):
						privateKeysHex[(host,port)] = keyInHex
						privateKeys[(host,port)] = nacl.public.PrivateKey(keyInHex, nacl.encoding.HexEncoder)
					elif (words[0] == "public"):
						publicKeysHex[(host,port)] = keyInHex
						publicKeys[(host,port)] = nacl.public.PublicKey(keyInHex, nacl.encoding.HexEncoder)
		except Exception,e:
			print ( "error: opening keychain file: %s %s" % (filename,repr(e)))
	else:
			print ("error: No filename presented")			 

	return (publicKeys,privateKeys)

class socket:
	
	def __init__(self):
		# your code goes here
		self.connected=False
		self.address=None
		self.prev_ack=0
		self.next_ack=0
		self.init_seq=0
		self.next_seq=0
		self.encrypt=False
		return 
		
	def bind(self,address):
		# bind is not used in this assignment
		global_socket.bind(address)
		#print("bound to: ",  address)
		return

	def connect(self,*args):
		global publicKeysHex
		global privateKeysHex 
		global publicKeys
		global privateKeys
		#global udpGlobalSocket 
		# example code to parse an argument list 
		#global sock352portTx
		global ENCRYPT
		if (len(args) >= 1): 
			(host,port) = args[0]
		#if (len(args) >= 2):
		#	if (args[1] == ENCRYPT):
		#		self.encrypt = True
		
		#print "In Connect"
		#sets sequence and ack numbers to be referenced in the new syn packet
		#self.box = Box(privateKeys[('*', '*')], publicKeys[(host,receivePort)])
		#print ("Box created for Host")
		#self.nonce = nacl.utils.random(Box.NONCE_SIZE)
		
		self.init_seq=randint(0, 2**64)
		self.ack_no=0
		#print "creating SYN Packet"
		#creates a new packet
		syn=new_packet()

		#specifies new packet as a syn packet
		syn.create_syn(self.init_seq)

		#packages the syn packet
		packsyn=syn.packPacket()
		
		#if(self.encrypt):
		#	packsyn = self.box.encrypt(packsyn, self.nonce)
		#	self.length_encrypted_header = len(packsyn)
		#	#print "Length encrypted Header: ", len(packsyn)
		#	headerLen = self.length_encrypted_header
		
		
		#send out the syn packet to setup connection
		while True:
			#sends syn packet through global socket to address provided
			global_socket.sendto(packsyn, (host, int(sendPort)))
			#print("Sent packet")
			#print "Sending SYN to", address LOOKATME
			try:
				#sets timeout of .2 seconds, keep trying to send packet during this timeout

				#print "not getting here"
				global_socket.settimeout(.2)

				#returns packet size in rpacket
				(rpacket, sender)=global_socket.recvfrom(40)
				#print "Received ACK Packet", sender
				break
			#fails if timeout exception
			except syssock.timeout:
				print "Socket timeout..."
				time.sleep(5)
			finally:

				#resets timer
				global_socket.settimeout(None)
		#retrieves packet header of 'syn' packet, packet header is the first 40 bytes of the packet as denoted by [:40]
		#rec_packet=packHeader(rpacket[:40])
		#print "Syn Packet sent and ACK SYN packet received successfully"
		
		#if(self.encrypt):
		#	rec_packet = packHeader(self.box.decrypt(rpacket))
		#else:
		rec_packet = packHeader(rpacket[:40])
								 
		#print "Getting ACK SYN packet header"
		#checks flag to verify that it is indeed a SYN flag OR checks ack number to verify it is the sequence number +1 as denoted in class
		if (rec_packet.flags != 5 or rec_packet.ack_no != (syn.header.sequence_no + 1)):
			print "Bad ACK for the SYN we sent"
		else:
			#print "Proper ACK for the SYN we sent"
			#proper ACKSYN, connect set to true, seq numbers set to proper values
			self.connected= True
			self.address=sender
			self.next_seq = rec_packet.ack_no
			self.prev_ack = rec_packet.ack_no - 1
			#print "Connected"
		return	  
		# your code goes here 

	def listen(self,backlog):
		# listen is not used in this assignments 
		pass
	

	def accept(self,*args):
		# example code to parse an argument list 
		global ENCRYPT
		if (len(args) >= 1):
			if (args[0] == ENCRYPT):
				self.encryption = True
		# your code goes here 
		while True:

			try:
				#sets timeout for receiving
				global_socket.settimeout(.2)
				#print "timeout set"
				(rpacket, sender)=global_socket.recvfrom(packet_size)
				#rec_packet=packHeader(rpacket[:40])
				#print "Server accepting from...", sender
				#if(self.encrypt):
				#	self.length_encrypted_header = len(rpacket)
				#	self.box = Box(privateKeys[('*', '*')], publicKeys[('localhost',send_port)])	#LOOKHERE
				#	rpacket = self.box.decrypt(rpacket)
					#print "Server PrivateKey: %s PublicKey: %s" %(privateKeysHex[('*', '*')], publicKeysHex[('localhost', recv_port)])
					#print "Encrypted Server Creating Box"
				#print "Packet Read During Accept"
				#print "Packet received... Packed Header is: ", binascii.hexlify(raw_packet)
				rec_packet = packHeader(rpacket[:40])
				
				if (rec_packet.flags != SYN_VAL):
					print "Non connection flag"
				else:
					break
			except syssock.timeout:
				print "Socket timed out"
				time.sleep(5)
				continue
			finally:
				global_socket.settimeout(None)
		#print "Server accepted connection"
		#initial sequence number should be random between this range 0-2^64
		self.init_seq=randint(0, 2**64)
		#prev ack should be sequence number -1
		self.prev_ack=rec_packet.sequence_no-1
		#creates new packet of type ACK
		ack=new_packet()
		#print "Creating ACK Packet"
		#sets flags of ACK pack, ACKING a SYN packet
		ack.header.flags=ACK_VAL+SYN_VAL
		ack.header.sequence_no=self.init_seq

		#ack number is sequence number +1
		ack.header.ack_no=rec_packet.sequence_no+1
		#packages the ack packet
		packed_ack=ack.packPacket()
		
		#checks whether it is an encrypted connection, if it is, creates nonce
		if(self.encrypt):
			self.nonce = nacl.utils.random(Box.NONCE_SIZE)
			packed_ack = self.box.encrypt(packed_ack, self.nonce)
								 
		#returns the number of bytes sent
		#print "Sending ACK Packet back to client"
		bytes_s=global_socket.sendto(packed_ack, sender)

		#sets new socket
		#print "Creating new socket"
		clientsocket=self
		#print "New socket created"
		#print "Sender is", sender
		#returns new socket with address
		self.address=sender
		return(clientsocket, sender)
	
	def close(self):
		# your code goes here
		# send a FIN packet (flags with FIN bit set)
		# remove the connection from the list of connections
		#initializes FIN packet
		FIN = new_packet()
		FIN.header.flags = FIN_VAL
		packed_FIN = FIN.packPacket()
		if(self.encrypt):
			 packed_FIN = self.box.encrypt(packed_FIN, self.nonce)
								 
		global_socket.sendto(packed_FIN, self.address)
		print "Closing socket"
		self.connected = False
		self.address=None
		self.prev_ack = 0
		self.next_seq = 0
		self.next_ack = 0
		self.init_seq = 0
		return 

	def send(self,buffer):
		# your code goes here
		#print "In send function"
		bytessent = 0  # fill in your code here
		#assigns the data in buffer up until the 5000th byte to payload
		payload = buffer[:4096]
		#creates new packet of type payload
		#print "Creating payload packet"
		data = new_packet()
		#assigns payload length
		data.header.payload_len = len(payload)
		#print "payload length is", data.header.payload_len
		#sets sequence and ack numbers
		#print "Setting ACK and SEQ numbers of payload packet"
		data.header.sequence_no = self.next_seq
		#print "sequence number", self.next_seq
		
		data.header.ack_no = data.header.sequence_no+1
		#print "ack number", data.header.ack_no
		if(self.encrypt):
			self.nonce=nacl.utils.random(Box.NONCE_SIZE)
			payload=self.box.encrypt(payload, self.nonce)
		#assigns payload to the payload field of data packet
		data.payload = payload
		
		#packages the data packet
		#print "Packaging payload packet"
		packed_data = data.packPacket()
		#count += count
		'''if(self.encrypt):
			self.nonce = nacl.utils.random(Box.NONCE_SIZE)
			packed_data = self.box.encrypt(packed_data, self.nonce)'''
								 
		#print "Sending payload packet"
		while True:
		
			bytesSent = global_socket.sendto(packed_data, self.address)

			try:
				global_socket.settimeout(.2)
				#(raw_packet, sender) = global_socket.recvfrom(HEADER_SIZE)
				#rec_packet = packHeader(raw_packet)
				if(self.encrypt):
					(raw_packet, sender) = global_socket.recvfrom(self.length_encrypted_header)
					rec_packet = self.box.decrypt(raw_packet)
				else:
					#(rec_packet, sender) = global_socket.recvfrom(HEADER_SIZE)
					(raw_packet, sender) = global_socket.recvfrom(HEADER_SIZE)
					#rec_packet = packHeader(raw_packet)
				rec_packet = packHeader(raw_packet)
				#print "Packet received..."
				if (rec_packet.flags != ACK_VAL or rec_packet.ack_no != (data.header.sequence_no + 1)):
					print "Wrong ACK, Going Back N"
					#go back n protocol implemented here
					#LOOKATME
				break
			except syssock.timeout:
				print "Socket Timed Out.."
				#continue

			finally:
				global_socket.settimeout(None)
		#sets ack and sequence numbers of data packet
		self.next_seq= rec_packet.ack_no 
		self.prev_ack = rec_packet.ack_no - 1
		self.next_ack = rec_packet.ack_no + 1
		
		'''if(self.encrypt):
			 headerLen = self.length_encrypted_header'''
		#else:
		headerLen = HEADER_SIZE
		
		bytesSent = len(buffer)

		if(len(buffer) > 4096):
			bytesSent = 4096

		
		return bytesSent
		#return bytesSent - HEADER_SIZE 

	def recv(self,nbytes):
		# your code goes here
		#standard code of timeout and receive from functions
		while True:
			try:
				global_socket.settimeout(.2)
				rPack, sender = global_socket.recvfrom(8192)
				print "received packet"
				rec_packet_header = packHeader(rPack[:40])
				payload=rPack[40:]
				
				if (self.encrypt):
					payload=self.box.decrypt(payload)
								 
				#rec_packet_header = packHeader(rec_packet[:40])
				#print "getting packet header"

				if (rec_packet_header.flags > 0):
					print "Not data packet"
					if (rec_packet_header.flags == FIN_VAL):
						global_socket.close()
						break;

				else:
					print "Its a data packet!"
					break

			except syssock.timeout:
				print "Socket timed out recieving"

			finally:
				#print "Its a data packet!"
				global_socket.settimeout(None)
		#print "Its a data packet!"
		self.next_seq = rec_packet_header.ack_no
		self.prev_ack= rec_packet_header.ack_no - 1
		self.next_ack = rec_packet_header.ack_no + 1
	
		#payload is now everything after the 40th byte of the received packet
		ack = new_packet()
		print "creating ACK packet in recv"
		ack.create_ack(rec_packet_header)
		packed_ack = ack.packPacket()
		print "sending ACK packet in recv"
		
		'''if(self.encrypt):
			packed_ack = self.box.encrypt(packed_ack, self.nonce)'''
		global_socket.sendto(packed_ack, sender)

		return payload
