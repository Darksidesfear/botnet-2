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
