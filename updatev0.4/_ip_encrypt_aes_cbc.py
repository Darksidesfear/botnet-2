from Crypto.Cipher import AES
import argparse
import sys
from Crypto.Util.Padding import pad
class utils():
	def encrypt_ip(**kwargs):
		if len(kwargs.get("key")) > 16 or len(kwargs.get("key")) < int(128/8):
			print("* Length is not 16, It is '%d'"%(len(kwargs.get("key"))),)
		if len(kwargs.get("iv")) > 16 or len(kwargs.get("iv")) < int(128/8):
			print("* Length of vector is no 16, It is '%d'"%(len(kwargs.get("iv"))),)
		aess = AES.new(kwargs.get("key").encode("utf-8"), AES.MODE_CBC, kwargs.get("iv").encode("utf-8"))
		encr = aess.encrypt(pad(kwargs.get("ip").encode("utf-8"), int(128/8)))
		print('''
==================
| Plain-text: %s
| Encrypted object: %s
| Key: %s
| Vector: %s
| Encryption type: CBC AES-128
|===================
|Now, put in the client where It says - AES_IP'''%(kwargs.get("ip"), encr, kwargs.get("key"), kwargs.get("iv")))

def __main__(af_inet):
	parsie = argparse.ArgumentParser()
	parsie.add_argument("-i", '--internetprotocol', help="Usage: %s --internetprotocol 192.168.0.100 or --internetprotocol hostname.com", required=True)
	parsie.add_argument("-v", "--version", help="Specify a version, default is ipv4", default=af_inet, required=False)
	parsie.add_argument("-k", "--key", help="Specify a key with the length of 16", required=True)
	parsie.add_argument("-V", '--vector', help="Specify a vector with the length of 16", required=True)
	args = parsie.parse_args()
	ints = args.internetprotocol
	vers = args.version
	key = args.key
	vecs = args.vector
	utils.encrypt_ip(ip=ints, version=vers, key=key, iv=vecs)
inits = __main__(af_inet="ipv4")





