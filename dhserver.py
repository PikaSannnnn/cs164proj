from socket import *

"""
DHCP Option Params:
	https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
Byte Conversion: 
	https://docs.python.org/3/library/stdtypes.html
"""

def format_addr(m, t='', d='d'):
	if t == 'mac':
		ret = format(m[0], 'x')
	else:
		if t == 'ip':
			ret = format(m[0], 'd')
		else:
			ret = format(m[0], d)
	
	for i in m[1:]:
		if t == 'mac':
			ret += ':' + format(i, 'x')
		elif t == 'ip':
			ret += '.' + format(i, 'd')
		else:
			ret += format(i, d)
	return ret

# SUBNET Stuff
SUBNET = (192).to_bytes(1, 'big') + (168).to_bytes(1, 'big') + (0).to_bytes(1, 'big')
SUBNET_POOL = [1]	# /24 -> last num ambig

while(1):
	DHCP_SERVER = ('', 67)
	DHCP_CLIENT = ('255.255.255.255', 68)
	# Create a UDP socket
	s = socket(AF_INET, SOCK_DGRAM)
	# Allow socket to broadcast messages
	s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
	# Bind socket to the well-known port reserved for DHCP servers
	s.bind(DHCP_SERVER)
	# Recieve a UDP message
	msg, addr = s.recvfrom(1024)
	
	"""
	Parsing through Discover Message
	"""
	# OP
	OP = msg[0]
	# HTYPE
	HTYPE = msg[1]
	# HLEN
	HLEN = msg[2]
	# HOPS
	HOPS = msg[3]
	# XID
	XID = msg[4:7 + 1]
	# SECS
	SECS = msg[8:9 + 1]
	# FLAGS
	FLAGS = msg[10:11 + 1] 
	# CLIENT SRC IP
	CIP = msg[12:15 + 1]
	# YIADDR OFFER IP
	YIP = msg[16:19 + 1]
	# SERVER SRC IP
	SIP = msg[20:23 + 1]
	# GATEWAY IP
	GIP = msg[24:27 + 1]
	# MAC address
	MAC = msg[28:33 + 1]
	# BOOTSTRAP
	BOOTP = msg[34:235 + 1]
	# MAGIC COOKIE
	MCOOKIE = msg[236:239 + 1]
	# DHCP ACTION TYPE
	DACT = msg[240:242 + 1] 
	# THE REST OF DHCP OPTIONS
	DOPTIONS = msg[243:len(msg) - 1]
	# TODO: first byte = Code, second after = num bytes for this code

	if DACT[2] == 3:
		print("Received DHCPREQUEST, XID: " + format_addr(XID, d='x') + ", MAC: " + format_addr(MAC, 'mac'))
		server_ip = SUBNET + SUBNET_POOL[0].to_bytes(1, 'big')
		offer_ip  = DOPTIONS[2:6]	# TODO: Fix if DOPTIONS is parsed correctly
		ret_msg = b'\x02' + HTYPE.to_bytes(1, 'big')
		ret_msg += HLEN.to_bytes(1, 'big')
		ret_msg += HOPS.to_bytes(1, 'big')
		ret_msg += XID + SECS + FLAGS

		# Addresses
		ret_msg += CIP
		ret_msg += offer_ip
		ret_msg += server_ip
		ret_msg += GIP + MAC
		# Misc pt 1 (BOOTSTRAP and COOKIE)
		ret_msg += BOOTP + MCOOKIE

		# DHCP Message Type
		ret_msg += (53).to_bytes(1, 'big') + b'\x01' + b'\x05'

		# Address Time
		ret_msg += (51).to_bytes(1, 'big')
		ret_msg += (8000).to_bytes(((8000).bit_length() + 7) // 8, 'big')

		# DHCP Server
		ret_msg += (54).to_bytes(1, 'big')
		ret_msg += server_ip

		# Fill Rest of Message
		ret_msg += (b'\x00' * (len(msg) - len(ret_msg)))

		print("\tAcknowledging: " + format_addr(offer_ip, 'ip'))
	elif DACT[2] == 1:
		print("Received DHCPDISCOVER, XID: " + format_addr(XID, d='x') + ", MAC: " + format_addr(MAC, 'mac'))
		"""
		Building return message (offer)
		"""
		server_ip = SUBNET + SUBNET_POOL[0].to_bytes(1, 'big')
		offer_ip = ''
		for i in range(1, 256):
			if i not in SUBNET_POOL:
				SUBNET_POOL.append(i)
				offer_ip = SUBNET + i.to_bytes(1, 'big')
				break
		
		ret_msg = b'\x02' + HTYPE.to_bytes(1, 'big') 
		ret_msg += HLEN.to_bytes(1, 'big')
		ret_msg += HOPS.to_bytes(1, 'big')
		ret_msg += XID + SECS + FLAGS
		
		# Addresses
		ret_msg += CIP
		ret_msg += offer_ip
		ret_msg += server_ip
		ret_msg += GIP + MAC
		
		# Misc pt 1 (BOOTSTRAP and COOKIE)
		ret_msg += BOOTP + MCOOKIE
		
		# TODO: Fix if DOPTIONS CHANGED
		# DHCP Message Type
		ret_msg += (53).to_bytes(1, 'big') + b'\x01' + b'\x02'
		
		# Address Time
		ret_msg += (51).to_bytes(1, 'big') 
		ret_msg += (8000).to_bytes(((8000).bit_length() + 7) // 8, 'big')
		
		# DHCP Server
		ret_msg += (54).to_bytes(1, 'big')
		ret_msg += server_ip
		
		# Fill Rest of Message
		ret_msg += (b'\x00' * (len(msg) - len(ret_msg)))
		
		print("\tOffering: " + format_addr(offer_ip, 'ip'))
	
	# print(format_addr(msg, d='x'))
	# print(format_addr(MCOOKIE))
	# print((53).to_bytes(1, 'big') + b'\x01' + b'\x02')
	# print(msg)
	# print(ret_msg)
	# print(len(msg))
	# print(len(ret_msg))	
	
	# Send a UDP message (Broadcast)
	s.sendto(ret_msg, DHCP_CLIENT)
