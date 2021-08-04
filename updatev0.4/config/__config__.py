from scapy.all import  * 
class listen_addr():
	_ip_ = get_if_addr(conf.iface)
	_port_ = 10491
	accept = "*"
class handlers():
	max_clients = 5000
	max_buffer = 256
	silent = True
	encr = "AES"
	exencr = "base64"
class important_menu():               
	# PLEASE EDIT CAREFULLY!          #
	# IT MIGHT MAKE THE PROGRAM SLOW! #
	# READ THE DECRIPTION BELOW!      #
	###################################
	ssl_check = False #It will check SSL, If it is availiable, but will only slow the program down, If doesn't have.
	raw_socket = True # This is for socket connection with RAW_SOCKET family, It will make the program a little bit faster.
	request_lib = False # This is for the library requests, target might not have requests, so it makes the program .. very slowlier. . 
