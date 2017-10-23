#!/usr/bin/env python
# encoding: utf-8
from socket import *
from select import *
from pyasn1_modules import pem, rfc2459
from pyasn1.codec.der import decoder as der_decoder
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hmac, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from OpenSSL.crypto import FILETYPE_ASN1
from Crypto.Hash import SHA, SHA256
import time, json, sys, base64, os
import urllib2
import common_cc, common_cert
import PyKCS11
import copy
import collections
import dmidecode, uuid

BUFSIZE = 512 * 1024
DEBUG = False
STATE_NONE = 0
STATE_CONNECTED = 1
STATE_DISCONNECTED = 2
STATE_CONNECTING = 3


RESEND_IF_NOT_ACKED = 15
MAX_SERVER_MESSAGES = 1000 # Establishing sessions takes a long time now, 'disable' this for now
MAX_ENDPOINT_MESSAGES = 1000
MAX_CLIENT_SESSION_SECONDS = 10000
MAX_SERVER_SESSION_SECONDS = 10000

class Client:	
	def __init__(self, ip_addr, port):

		self.sock = socket(AF_INET, SOCK_STREAM)
		self.sock.connect((ip_addr, port))
		self.pkcs11lib = "/usr/local/lib/libpteidpkcs11.so"
		common_cc.refreshCertificates()
		self.pkcs11 = PyKCS11.PyKCS11Lib()
		self.chosen_slot = -1
		self.userCert = None
		self.serverCert = None
		self.cardSession = None
		self.userName = ""
		self.pickSlot()
		self.availableCipherSpecs = ["ECDHE_WITH_AES_256_CTR_SHA256", "ECDHE_WITH_AES_256_OFB_SHA256"]
		self.serverCipherSpec = None
		self.restartFlag = False
		self.msgs = []
		self.clientList = []
		self.connectedClients = dict()
		self.buffer = ""
		self.uid = None
		self.selectedClient = -1
		self.connect()
		self.waitingForServerACK = dict()
		self.newServerCipherKey(None)
		self.TRADED_MESSAGES = 0

		while True:
			try:
				self.listenLoop()
			except KeyboardInterrupt:
				print "[ \033[41m\033[1m END \033[0m\033[0m ]: Keyboard Interrupt, terminating client."
				self.sock.close()
				return

	def getHardwareID(self):
		all_dmi = dmidecode.parse_dmi(dmidecode._get_output())
		cpu_IDs = [] # Add found CPU IDs
		ram_partNO = [] # Add part numbers of every RAM module found
		system_UUID = [] # Add system UUID
		for dmi in all_dmi:
			if dmi[0] == 1:
				if 'UUID' in dmi[1]:
					system_UUID.append(dmi[1]['UUID'])
			if dmi[0] == 4:
				if 'ID' in dmi[1]:
					cpu_IDs.append(dmi[1]['ID'].replace(" ", ""))
			elif dmi[0] == 17:
				if 'Part Number' in dmi[1]:
					if dmi[1]['Part Number'].upper() != "[EMPTY]":
						ram_partNO.append(dmi[1]['Part Number'])			
		hardwareID = SHA.new()
		for part_id in (cpu_IDs + ram_partNO + system_UUID):
			hardwareID.update(part_id)
		hardwareID.update(str(uuid.getnode())) # Add network interface MAC address
		return hardwareID.hexdigest().upper()

	def pickSlot(self):
		first = True
		free = False
		prevcounter = 0
		userinput = ""
		chosen_slot = -1
		r = None
		while not free:
			userinput = ""
			print "[ \033[100m INFO \033[0m ]: Detecting smartcard slots...\n\n"
			while userinput == "":
				r, not_used, not_used = select([sys.stdin], [], [], 0.3)
				if r:
					r = sys.stdin.readline()
					userinput = r
					break
				else:
					self.pkcs11.__del__()
					self.pkcs11 = PyKCS11.PyKCS11Lib()
					self.pkcs11.load(self.pkcs11lib)
					try:
						slotcounter = len([slot for slot in self.pkcs11.getSlotList() if self.pkcs11.getSlotInfo(slot).slotDescription.strip().upper() != "VIRTUAL SLOT"])
					except:
						continue
					if not first:
						sys.stderr.write("\033[2D\033[1K")
						for count in xrange(prevcounter):
							sys.stderr.write("\033[1A\r\033[K")
					prevcounter = slotcounter
					for card_slot in self.pkcs11.getSlotList():
						slot_desc = self.pkcs11.getSlotInfo(card_slot).slotDescription.strip()
						if slot_desc.upper() != "VIRTUAL SLOT":
							sys.stderr.write("[ \033[100m INFO \033[0m ]: Slot " + str(card_slot) + ": " + slot_desc[0: -6])
							if 'CKF_TOKEN_PRESENT' not in self.pkcs11.getSlotInfo(card_slot).flags2text():
								sys.stderr.write(" (no smartcard inserted)\n")
							else:
								session = self.pkcs11.openSession(card_slot)
								sys.stderr.write(" (" + common_cc.getGivenName(session) + ")\n")
								session.closeSession()
					if slotcounter > 0:
						sys.stderr.write("[ \033[100m INFO \033[0m ]: Select a slot: ")

					first = False
			sys.stderr.write("\033[2K")
			for count in xrange(prevcounter+1):
							sys.stderr.write("\033[1A\r\033[2K")
			try:
				temp_slot = int(userinput.strip()[-1])
				if temp_slot >= 0 and temp_slot < prevcounter:
					if 'CKF_TOKEN_PRESENT' not in self.pkcs11.getSlotInfo(temp_slot).flags2text():
						print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: No smartcard inserted.\n"
					else:
						free = True
						self.chosen_slot = temp_slot
				else:
					print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Invalid slot chosen.\n"
			except:
				print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Invalid slot chosen.\n"

		session = self.pkcs11.openSession(self.chosen_slot)
		self.userCert = common_cc.getLeafCertificate(session)				# Pull certificate from the smartcard
		if common_cert.verifyUserCertificate(self.userCert, FILETYPE_ASN1):			# Verify certificate
			print "[ \033[45mUSERID\033[0m ]: Certified ID detected."
			self.userName = ' '.join(map(lambda a: a.capitalize(), common_cc.getGivenName(session).split(" "))) # NUNO HUMBERTO -> Nuno Humberto
		else:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Invalid ID, cannot proceed.\n"
			session.closeSession()
			return
		print "[ \033[45mUSERID\033[0m ]: Authenticating as \033[1m\033[32m" + self.userName + "\033[0m\033[0m."
		time.sleep(0.5)
		try:
			session.sign(session.findObjects()[0], " ") # Sign something, just to cache the PIN
		except:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Authentication failed.\n"
			sys.exit()
		self.cardSession = session

	def getBlockCipherModeFromSpec(self, spec):
		try:
			return spec.split('_')[4]
		except:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Error extracting block cipher mode!"
			return "CTR"

	def getKeyExchangeFromSpec(self, spec):
		try:
			return spec.split('_')[0]
		except:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Error extracting key exchange algorithm!"
			return "ECDHE"

	def getList(self):
		msg = {'type': 'list'}
		self.sendSecureToServer(msg)

	def processList(self, msg):
		self.clientList = []
		clientNo = 1
		clients = json.loads(msg)
		for client in clients: 
			if client['id'] == self.uid:
				continue
			self.clientList.append({'index': clientNo, 'id': client['id'], 'name': base64.urlsafe_b64decode(str(client['name'])), 'level' : client['level'], 'ccID': client['ccID']})
			clientNo += 1

		if self.clientList != []:
			print "\n[ \033[43mSERVER\033[0m ]: Available clients:"
			for client in self.clientList:
				print "[ \033[43mSERVER\033[0m ]: %d: %s - \033[1m\033[32m%s\033[0m\033[0m (%s) - LEVEL %d" % (client['index'], client['id'], client['name'], client['ccID'], client['level'] )
			sys.stdout.write("\n")
		else:
			print "\n[ \033[43mSERVER\033[0m ]: No clients available."	

	def sendACK(self, dst):
		#msg = {'type': 'ack', 'src': self.uid, 'dst' : dst }
		#self.sendSecureToServer(msg)
		pass 

	def processClientConnect(self, msg, reexchange=False):
		if msg == None:
			try:
				dst = self.clientList[self.selectedClient-1]['id']
			except:
				print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: No valid client selected"
				return
			msg = {'type' : 'client-connect', 'src': dst , 'dst': self.uid, 'phase' : 0, 'reexchange': reexchange}

		elif msg['phase'] != 0:
			self.sendACK(msg['src'])
			if DEBUG:
				print "[ \033[41m\033[1m DEBUG \033[0m\033[0m ]: SENDING AN ACK FOR: " + str(msg['type'])

		if DEBUG:
			print "[ \033[41m\033[1m DEBUG \033[0m\033[0m ]: GOT A CLIENT CONNECT MESSAGE WITH PHASE " + str(msg['phase'])

		if 'reexchange' in msg and msg['reexchange'] == True:
			reexchange = True
		else:
			reexchange = False

		msg_to_send = {'type' : 'client-connect', 'src' : self.uid, 'name': base64.urlsafe_b64encode(self.userName), 'dst': msg['src'], 'phase' : msg['phase'] + 1, 'reexchange' : reexchange}

		if (msg_to_send['dst'] in self.connectedClients and self.connectedClients[msg_to_send['dst']]['state'] == STATE_CONNECTED) and not reexchange:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Client already connected!"
			return
			

		if msg_to_send['phase'] == 1:
			msg_to_send['ciphers'] = self.availableCipherSpecs

		if msg_to_send['phase'] == 2:
			compatible = []
			for spec in msg['ciphers']:
				if spec in self.availableCipherSpecs:
					compatible.append(spec)
			msg_to_send['ciphers'] = compatible
			msg_to_send['cert'] = base64.urlsafe_b64encode(self.userCert)
			msg_to_send['uuid'] = self.getHardwareID()

		if msg_to_send['phase'] == 3:

			if 'cert' in msg:
				temp_cert = base64.urlsafe_b64decode(str(msg['cert']))
				if common_cert.verifyUserCertificate(temp_cert, FILETYPE_ASN1):
					print "[ \033[44mCLIENT\033[0m ]: Received a valid certificate from client \033[1m\033[32m" + base64.urlsafe_b64decode(str(msg['name'])) + "\033[0m\033[0m."
				else:
					print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Received an invalid certificate from client \033[1m\033[32m" + base64.urlsafe_b64decode(str(msg['name'])) + "\033[0m\033[0m."
			else:
				logging.warning("Invalid key exchange message")
				return


			if msg['ciphers'] == []:
				print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Unable to reach a cipher agreement."
				return
			for spec in self.availableCipherSpecs:
				if spec in msg['ciphers']:
					msg_to_send['ciphers'] = [spec]
					break
			if 'ciphers' not in msg_to_send:
				print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Unable to reach a cipher agreement."
				return
			
			if 'uuid' in msg:
				print "[ \033[44mCLIENT\033[0m ]: \033[1m\033[32m" + base64.urlsafe_b64decode(str(msg['name'])) + "'s\033[0m\033[0m HWID: \033[36m" + msg['uuid'] + "\033[0m."

			challenge_to_client = os.urandom(16)

			msg_to_send['cert'] = base64.urlsafe_b64encode(self.userCert)
			msg_to_send['uuid'] = self.getHardwareID()
			msg_to_send['challenge'] = base64.urlsafe_b64encode(challenge_to_client)

			client_keys = self.generateTransportKeyPair(self.getKeyExchangeFromSpec(msg_to_send['ciphers'][0]), interclient=True)
			self.connectedClients[msg_to_send['dst']] = dict()
			self.connectedClients[msg_to_send['dst']]['waitingForClientACK'] = dict()
			self.connectedClients[msg_to_send['dst']]['cert'] = temp_cert
			self.connectedClients[msg_to_send['dst']]['challenge_given'] = challenge_to_client
			self.connectedClients[msg_to_send['dst']]['chosenSpec'] = msg_to_send['ciphers'][0]
			self.connectedClients[msg_to_send['dst']]['state'] = STATE_CONNECTING
			self.connectedClients[msg_to_send['dst']]['data'] = client_keys

			with open(msg_to_send['dst'], 'a+b') as f:
				f.write(json.dumps({'name' : msg['name'], 'hwid' : msg['uuid']}) + '\n\n')
				f.close()

			
			msg_to_send['data'] = {
				'pubkey' : self.connectedClients[msg_to_send['dst']]['data']['pubkey'].public_bytes(encoding=serialization.Encoding.PEM,
						format=serialization.PublicFormat.SubjectPublicKeyInfo)
			}

		if msg_to_send['phase'] == 4:
			if 'cert' in msg:
				temp_cert = base64.urlsafe_b64decode(str(msg['cert']))
				if common_cert.verifyUserCertificate(temp_cert, FILETYPE_ASN1):
					print "[ \033[44mCLIENT\033[0m ]: Received a valid certificate from client \033[1m\033[32m" + base64.urlsafe_b64decode(str(msg['name'])) + "\033[0m\033[0m."
				else:
					print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Received an invalid certificate from client \033[1m\033[32m" + base64.urlsafe_b64decode(str(msg['name'])) + "\033[0m\033[0m."
			else:
				logging.warning("Invalid key exchange message")
				return

			if 'challenge' in msg:
				challenge_from_client = base64.urlsafe_b64decode(str(msg['challenge']))
				response_to_client = self.cardSession.sign(self.cardSession.findObjects()[0],
									challenge_from_client, mecha=PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None))
				response_to_client = ''.join(chr(signature_byte) for signature_byte in response_to_client)		
			else:
				print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Client did not provide challenge."
				return

			if 'uuid' in msg:
				print "[ \033[44mCLIENT\033[0m ]: \033[1m\033[32m" + base64.urlsafe_b64decode(str(msg['name'])) + "'s\033[0m\033[0m HWID: \033[36m" + msg['uuid'] + "\033[0m."

			if 'data' in msg:
				if 'pubkey' in msg['data']:
					client_keys = self.generateTransportKeyPair(self.getKeyExchangeFromSpec(msg['ciphers'][0]), interclient=True)


					challenge_to_client = os.urandom(16)

					msg_to_send['challenge'] = base64.urlsafe_b64encode(challenge_to_client)
					msg_to_send['response'] = base64.urlsafe_b64encode(response_to_client)
					

					self.connectedClients[msg_to_send['dst']] = dict()
					self.connectedClients[msg_to_send['dst']]['waitingForClientACK'] = dict()
					self.connectedClients[msg_to_send['dst']]['challenge_given'] = challenge_to_client
					self.connectedClients[msg_to_send['dst']]['cert'] = temp_cert
					self.connectedClients[msg_to_send['dst']]['chosenSpec'] = msg['ciphers'][0]
					self.connectedClients[msg_to_send['dst']]['state'] = STATE_CONNECTING
					self.connectedClients[msg_to_send['dst']]['data'] = client_keys
					
					with open(msg_to_send['dst'], 'a+b') as f:
						f.write(json.dumps({'name' : msg['name'], 'hwid' : msg['uuid']}) + '\n\n')
						f.close()


					imported_key = serialization.load_pem_public_key(str(msg['data']['pubkey']), backend=default_backend())

					self.connectedClients[msg_to_send['dst']]['data']['secret'] = self.connectedClients[msg_to_send['dst']]['data']['privkey'].exchange(ec.ECDH(), imported_key)
					self.connectedClients[msg_to_send['dst']]['data']['saltA'] = os.urandom(16)
					self.connectedClients[msg_to_send['dst']]['state'] = STATE_CONNECTING

					msg_to_send['data'] = dict()
					msg_to_send['data']['pubkey'] = self.connectedClients[msg_to_send['dst']]['data']['pubkey'].public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
					msg_to_send['data']['saltA'] =  base64.urlsafe_b64encode(self.connectedClients[msg_to_send['dst']]['data']['saltA'])
					del self.connectedClients[msg_to_send['dst']]['data']['privkey']
					del self.connectedClients[msg_to_send['dst']]['data']['pubkey']
					if DEBUG:
						print "[ \033[44mCLIENT\033[0m ]: Shared secret established."
				else:
					print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Invalid key exchange message"
					return
		
		if msg_to_send['phase'] == 5:
			if 'response' in msg:
				response_from_client = base64.urlsafe_b64decode(str(msg['response']))
				if common_cert.verifySignature(self.connectedClients[msg_to_send['dst']]['cert'], response_from_client, self.connectedClients[msg_to_send['dst']]['challenge_given']):
					print "[ \033[44mCLIENT\033[0m ]: Successfully verified the identity of \033[1m\033[32m" + base64.urlsafe_b64decode(str(msg['name'])) + "\033[0m\033[0m."
					with open(msg_to_send['dst'] + '.crt', 'wb') as f:		# Save user certificate for offline log verification
						f.write(self.connectedClients[msg_to_send['dst']]['cert'])
						f.close()
				else:
					print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Failed to verify the identity of \033[1m\033[32m" + base64.urlsafe_b64decode(str(msg['name'])) + "\033[0m\033[0m."
					return

			if 'challenge' in msg:
				challenge_from_client = base64.urlsafe_b64decode(str(msg['challenge']))
				response_to_client = self.cardSession.sign(self.cardSession.findObjects()[0], challenge_from_client, mecha=PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None))
				response_to_client = ''.join(chr(signature_byte) for signature_byte in response_to_client)		
			else:
				print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Client did not provide challenge."
				return

			if 'data' in msg:
				if 'pubkey' in msg['data']:
					imported_key = serialization.load_pem_public_key(str(msg['data']['pubkey']), backend=default_backend())
					self.connectedClients[msg_to_send['dst']]['data']['secret'] = self.connectedClients[msg_to_send['dst']]['data']['privkey'].exchange(ec.ECDH(), imported_key)
					del self.connectedClients[msg_to_send['dst']]['data']['privkey']
					del self.connectedClients[msg_to_send['dst']]['data']['pubkey']
		
					connectionSaltA = base64.urlsafe_b64decode(str(msg['data']['saltA']))
					connectionSaltB = os.urandom(16)
					if DEBUG:
						print "[ \033[44mCLIENT\033[0m ]: Shared secret established."

					derived_key = PBKDF2HMAC(algorithm=hashes.SHA512(), length=64, salt=connectionSaltA+connectionSaltB, iterations=100000, backend=default_backend()).derive(self.connectedClients[msg_to_send['dst']]['data']['secret'])
					
					self.connectedClients[msg_to_send['dst']]['data']['derived_key'] = derived_key
					plaintext = "Verification OK"+os.urandom(16)
		
					cipher_algo = algorithms.AES(derived_key[:32])
					counternonce = os.urandom(cipher_algo.block_size/8)


					bc_spec = self.getBlockCipherModeFromSpec(self.connectedClients[msg_to_send['dst']]['chosenSpec'])
					if bc_spec == "CTR":
						ciphermode = modes.CTR(counternonce)
					elif bc_spec == "OFB":
						ciphermode = modes.OFB(counternonce)

					countercipher = Cipher(cipher_algo, ciphermode, backend=default_backend())
					ciphertext_gen = countercipher.encryptor()
		
					ciphertext = ciphertext_gen.update(plaintext) + ciphertext_gen.finalize()
		
					hmac_holder = hmac.HMAC(derived_key[32:64], hashes.SHA256(), backend=default_backend())
					hmac_holder.update(ciphertext)
					hmac_to_send = hmac_holder.finalize()
		
					msg_to_send['data'] = dict()
					msg_to_send['response'] = base64.urlsafe_b64encode(response_to_client)
					msg_to_send['data']['saltB'] = base64.urlsafe_b64encode(connectionSaltB)
					msg_to_send['data']['ciphertext'] = base64.urlsafe_b64encode(ciphertext)
					msg_to_send['data']['counternonce'] = base64.urlsafe_b64encode(counternonce)
					msg_to_send['data']['hmac'] = base64.urlsafe_b64encode(hmac_to_send)


		if msg_to_send['phase'] == 6:
			if 'response' in msg:
				response_from_client = base64.urlsafe_b64decode(str(msg['response']))
				if common_cert.verifySignature(self.connectedClients[msg_to_send['dst']]['cert'], response_from_client, self.connectedClients[msg_to_send['dst']]['challenge_given']):
					with open(msg_to_send['dst'] + '.crt', 'wb') as f:
						f.write(self.connectedClients[msg_to_send['dst']]['cert'])
						f.close()
					print "[ \033[44mCLIENT\033[0m ]: Successfully verified the identity of \033[1m\033[32m" + base64.urlsafe_b64decode(str(msg['name'])) + "\033[0m\033[0m."
				else:
					print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Failed to verify the identity of \033[1m\033[32m" + base64.urlsafe_b64decode(str(msg['name'])) + "\033[0m\033[0m."
					return


			if 'data' in msg:
				if not all (k in msg['data'].keys() for k in ("saltB", "ciphertext", "counternonce", "hmac")):
					print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Connect message with missing fields"
					return
			else:
				print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Connect message with missing fields"
				return
			
		
			connectionSaltB = base64.urlsafe_b64decode(str(msg['data']['saltB']))
			ciphertext = base64.urlsafe_b64decode(str(msg['data']['ciphertext']))
			received_hmac = base64.urlsafe_b64decode(str(msg['data']['hmac']))
			
			
		
			derived_key = PBKDF2HMAC(algorithm=hashes.SHA512(), length=64, salt=self.connectedClients[msg_to_send['dst']]['data']['saltA']+connectionSaltB, iterations=100000, backend=default_backend()).derive(self.connectedClients[msg_to_send['dst']]['data']['secret'])
			cipher_algo = algorithms.AES(derived_key[:32])
			counternonce = base64.urlsafe_b64decode(str(msg['data']['counternonce']))

			bc_spec = self.getBlockCipherModeFromSpec(self.connectedClients[msg_to_send['dst']]['chosenSpec'])
			if bc_spec == "CTR":
				ciphermode = modes.CTR(counternonce)
			elif bc_spec == "OFB":
				ciphermode = modes.OFB(counternonce)


			countercipher = Cipher(cipher_algo, ciphermode, backend=default_backend())
			plaintext_gen = countercipher.decryptor()
			plaintext = plaintext_gen.update(ciphertext) + plaintext_gen.finalize()
			
			hmac_holder = hmac.HMAC(derived_key[32:64], hashes.SHA256(), backend=default_backend())
			hmac_holder.update(ciphertext)
			try:
				hmac_holder.verify(received_hmac)
				self.connectedClients[msg_to_send['dst']]['state'] = STATE_CONNECTED
				self.connectedClients[msg_to_send['dst']]['last'] = False
				self.connectedClients[msg_to_send['dst']]['sent_messages'] = 0
			except:
				print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Verification failed, removing client."
				del self.connectedClients[msg_to_send['dst']]
				return
			
			# If verification went OK - It's the server's turn
			
			plaintext = "Verification OK"+os.urandom(16)

			cipher_algo = algorithms.AES(derived_key[:32])
			counternonce = os.urandom(cipher_algo.block_size/8)

			if bc_spec == "CTR":
				ciphermode = modes.CTR(counternonce)
			elif bc_spec == "OFB":
				ciphermode = modes.OFB(counternonce)

			countercipher = Cipher(cipher_algo, ciphermode, backend=default_backend())
			ciphertext_gen = countercipher.encryptor()

			ciphertext = ciphertext_gen.update(plaintext) + ciphertext_gen.finalize()

			hmac_holder = hmac.HMAC(derived_key[32:64], hashes.SHA256(), backend=default_backend())
			hmac_holder.update(ciphertext)
			hmac_to_send = hmac_holder.finalize()

			
			msg_to_send['data'] = dict()
			msg_to_send['data']['ciphertext'] = base64.urlsafe_b64encode(ciphertext)
			msg_to_send['data']['counternonce'] = base64.urlsafe_b64encode(counternonce)
			msg_to_send['data']['hmac'] = base64.urlsafe_b64encode(hmac_to_send)

			if DEBUG:
				print "[ \033[44mCLIENT\033[0m ]: Client-side verification successful at phase 6."
			print "[ \033[44mCLIENT\033[0m ]: Incoming connection from " + msg['src']
			del self.connectedClients[msg_to_send['dst']]['data']['saltA']

		if msg_to_send['phase'] == 7:
			if 'data' in msg:
				if not all (k in msg['data'].keys() for k in ("ciphertext", "counternonce", "hmac")):
					print "Connect message with missing fields"
					return
			else:
				print "Connect message with missing fields"
				return
			
			ciphertext = base64.urlsafe_b64decode(str(msg['data']['ciphertext']))
			received_hmac = base64.urlsafe_b64decode(str(msg['data']['hmac']))

			cipher_algo = algorithms.AES(self.connectedClients[msg_to_send['dst']]['data']['derived_key'][:32])
			counternonce = base64.urlsafe_b64decode(str(msg['data']['counternonce']))


			bc_spec = self.getBlockCipherModeFromSpec(self.connectedClients[msg_to_send['dst']]['chosenSpec'])
			if bc_spec == "CTR":
				ciphermode = modes.CTR(counternonce)
			elif bc_spec == "OFB":
				ciphermode = modes.OFB(counternonce)



			countercipher = Cipher(cipher_algo, ciphermode, backend=default_backend())
			plaintext_gen = countercipher.decryptor()
			plaintext = plaintext_gen.update(ciphertext) + plaintext_gen.finalize()

			hmac_holder = hmac.HMAC(self.connectedClients[msg_to_send['dst']]['data']['derived_key'][32:64], hashes.SHA256(), backend=default_backend())
			hmac_holder.update(ciphertext)
			try:
				hmac_holder.verify(received_hmac)
				self.connectedClients[msg_to_send['dst']]['state'] = STATE_CONNECTED
				self.connectedClients[msg_to_send['dst']]['last'] = True
				self.connectedClients[msg_to_send['dst']]['refreshMeAfter'] = time.time() + MAX_CLIENT_SESSION_SECONDS # Session keys will then be re-exchanged
				self.connectedClients[msg_to_send['dst']]['sent_messages'] = 0
			except:
				print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Client-side verification failed."
				return

			if DEBUG:
				print "[ \033[44mCLIENT\033[0m ]: Client-side verification successful at phase 7."
			print "[ \033[44mCLIENT\033[0m ]: Connected to " + msg['src']
			del self.connectedClients[msg_to_send['dst']]['data']['derived_key']
			
			self.newClientCipherKey({'type' : 'newclientkey', 'src' : self.clientList[self.selectedClient-1]['id'], 'dst': self.uid, 'phase' : 0})


		if msg_to_send['phase'] < 7:
			if DEBUG:
				print "[ \033[41m\033[1m DEBUG \033[0m\033[0m ]: SENDING A CLIENT CONNECT MESSAGE WITH PHASE " + str(msg_to_send['phase']) # DELETEME
			self.sendSecureToServer(msg_to_send)


	def processSecure(self, msg):
		if DEBUG:
			print "[ \033[41m\033[1m DEBUG \033[0m\033[0m ]: INCOMING SECURE MESSAGE!" # DELETEME
		if 'payload' not in msg or 'sa_data' not in msg or 'signature' not in msg['sa_data']:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Secure message with missing fields"
			return

		

		signature = base64.urlsafe_b64decode(str(msg['sa_data']['signature']))
		request_to_ack = copy.deepcopy(msg)
		del msg['sa_data']['signature']
		temp_sa_data = msg['sa_data']
		ack_sa_data = request_to_ack['sa_data']

		msg['sa_data'] = dict()
		request_to_ack['sa_data'] = dict()
		for k in sorted(temp_sa_data.keys()):
				msg['sa_data'][k] = temp_sa_data[k]

		for k in sorted(ack_sa_data.keys()):
				request_to_ack['sa_data'][k] = ack_sa_data[k]

		if common_cert.verifySignature_pss(self.serverCert, signature, json.dumps(msg)):
			print "[ \033[43m\033[1m DEBUG \033[0m\033[0m ]: Secure message successfully verified!"
		else:
			print "[ \033[45m\033[1m SRS ERROR \033[0m\033[0m ]: Bad identity signature!"
			return



		bc_spec = self.getBlockCipherModeFromSpec(self.serverCipherSpec)
		
		cipher_algo = algorithms.AES(self.nextCipherKey[:32])
		counternonce = msg['sa_data']['counternonce']


		hmac_target = base64.urlsafe_b64decode(str(msg['sa_data']['hmac']))
		ciphertext = base64.urlsafe_b64decode(str(msg['payload']))
		counternonce = base64.urlsafe_b64decode(str(msg['sa_data']['counternonce']))

		if bc_spec == "CTR":
			ciphermode = modes.CTR(counternonce)
		elif bc_spec == "OFB":
			ciphermode = modes.OFB(counternonce)

		countercipher = Cipher(cipher_algo, ciphermode, backend=default_backend())
		plaintext_gen = countercipher.decryptor()

		plaintext = plaintext_gen.update(ciphertext) + plaintext_gen.finalize()

		hmac_holder = hmac.HMAC(self.nextCipherKey[32:64], hashes.SHA256(), backend=default_backend())
		hmac_holder.update(ciphertext)



		try:
			hmac_holder.verify(hmac_target)
		except:
			print "[ \033[45m\033[1m SRS ERROR \033[0m\033[0m ]: >    SERVER SIGNATURE VERIRICATION FAILED (processSecure)  <" 
			return


		
		del msg['payload']
		msg['payload'] = json.loads(plaintext)



		if msg['payload']['type'] != 'ack':
			ack_message_digest = SHA256.new()
			ack_message_digest.update(json.dumps(request_to_ack))
			ack_message_digest = ack_message_digest.digest()
			ack_signature = base64.urlsafe_b64encode(
								''.join(chr(signature_byte) for signature_byte in
										self.cardSession.sign(
											self.cardSession.findObjects()[0], ack_message_digest, mecha=PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
										)
								)	
													
							)


			if DEBUG:
				print "[ \033[41m\033[1m DEBUG \033[0m\033[0m ]: Sending ACK for", json.dumps(request_to_ack)

			self.sendSecureToServer({'type' : 'ack', 'message_digest' : base64.urlsafe_b64encode(ack_message_digest), 'signature' : ack_signature})



		to_print = msg['payload']['type']
		if to_print == 'newclientkey':
			to_print += str(msg['payload']['phase'])
		if DEBUG:
			print "[ \033[41m\033[1m DEBUG \033[0m\033[0m ]: MESSAGE PARSED! TYPE: " + to_print + " - " + base64.urlsafe_b64encode(self.nextCipherKey[:32]) # DELETEME

		if msg['payload']['type'] == 'list':
			self.processList(msg['payload']['data'])
		if msg['payload']['type'] == 'client-connect':
			self.processClientConnect(msg['payload'])
		if msg['payload']['type'] == 'newclientkey':
			self.newClientCipherKey(msg['payload'])
		if msg['payload']['type'] == 'client-com':
			self.processMessage(msg['payload'])
		if msg['payload']['type'] == 'client-disconnect':
			self.processDisconnect(msg['payload'])
		if msg['payload']['type'] == 'client-ack':
			self.processClientACK(msg['payload'])
		if msg['payload']['type'] == 'ack':
			self.checkServerAck(msg['payload'])

	def checkServerAck(self, msg):
		if 'message_digest' not in msg or 'signature' not in msg:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Server ACK with missing parameters."
			return

		if str(msg['message_digest']) not in self.waitingForServerACK:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Got an unexpected ACK from server.", str(msg['message_digest'])
			return

		signature = base64.urlsafe_b64decode(str(msg['signature']))
		digest = base64.urlsafe_b64decode(str(msg['message_digest']))

		if common_cert.verifySignature_pss(self.serverCert, signature, digest):
			if DEBUG or True: # Show these for now
				print "[ \033[43m\033[1m DEBUG \033[0m\033[0m ]: ACK from server OK."
		else:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Failed to verify server ACK."

		del self.waitingForServerACK[str(msg['message_digest'])]

	def checkClientAck(self, src, msg):
		if 'message_digest' not in msg or 'signature' not in msg:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Client ACK with missing parameters."
			return

		if str(msg['message_digest']) not in self.connectedClients[src]['waitingForClientACK']:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Got an unexpected ACK from client.", str(msg['message_digest'])
			return

		signature = base64.urlsafe_b64decode(str(msg['signature']))
		digest = base64.urlsafe_b64decode(str(msg['message_digest']))

		if common_cert.verifySignature(self.connectedClients[src]['cert'], signature, digest):
			if DEBUG or True: # Show these for now
				print "[ \033[43m\033[1m DEBUG \033[0m\033[0m ]: ACK from client OK."
		else:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Failed to verify client ACK."

		del self.connectedClients[src]['waitingForClientACK'][str(msg['message_digest'])]


	def sendSecureToServer(self, msg):
		secure_msg = {'type': 'secure'}
		
		bc_spec = self.getBlockCipherModeFromSpec(self.serverCipherSpec)

		cipher_algo = algorithms.AES(self.nextCipherKey[:32])
		counternonce = os.urandom(cipher_algo.block_size/8)

		if bc_spec == "CTR":
			ciphermode = modes.CTR(counternonce)
		elif bc_spec == "OFB":
			ciphermode = modes.OFB(counternonce)

		countercipher = Cipher(cipher_algo, ciphermode, backend=default_backend())
		ciphertext_gen = countercipher.encryptor()
	
		ciphertext = ciphertext_gen.update(json.dumps(msg)) + ciphertext_gen.finalize()
	
		hmac_holder = hmac.HMAC(self.nextCipherKey[32:64], hashes.SHA256(), backend=default_backend())
		hmac_holder.update(ciphertext)
		hmac_to_send = hmac_holder.finalize()


		secure_msg['sa_data'] = dict()
		secure_msg['sa_data']['counternonce'] = base64.urlsafe_b64encode(counternonce)
		secure_msg['sa_data']['hmac'] = base64.urlsafe_b64encode(hmac_to_send)
		secure_msg['payload'] = base64.urlsafe_b64encode(ciphertext)



		secure_msg['sa_data']['signature'] = base64.urlsafe_b64encode(
												''.join(chr(signature_byte) for signature_byte in
														self.cardSession.sign(
															self.cardSession.findObjects()[0], json.dumps(secure_msg), mecha=PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
														)
												)	
												
											 )

		if msg['type'] != 'ack':		 # Don't send an ack of an ack
			message_digest = SHA256.new()
			message_digest.update(json.dumps(secure_msg))
			encoded_digest = base64.urlsafe_b64encode(message_digest.digest())
			self.waitingForServerACK[encoded_digest] = dict()
			self.waitingForServerACK[encoded_digest]['time'] = time.time() 
			self.waitingForServerACK[encoded_digest]['content'] = json.dumps(secure_msg) # Save content in case it needs to be resent

		to_print = msg['type']
		if to_print == 'newclientkey':
			to_print += str(msg['phase'])
		if DEBUG:
			print "[ \033[41m\033[1m DEBUG \033[0m\033[0m ]: CALLING SEND FUNCTION FOR: " + to_print
		self.send(secure_msg)
		if DEBUG:
			print "[ \033[41m\033[1m DEBUG \033[0m\033[0m ]: SENT"
			

	def connect(self, reexchange=False):
		if reexchange == False:
			uid = base64.urlsafe_b64encode(os.urandom(8)) # The user ID itself will be a base64 string so it can be correctly displayed in the console
			self.uid = uid
		else:
			uid = self.uid
		self.send({'type': 'connect', 'phase' : 1, 'name': base64.urlsafe_b64encode(self.userName), 'id' : base64.urlsafe_b64encode(os.urandom(8)), 'uid' : base64.urlsafe_b64encode(uid), 'ciphers' : self.availableCipherSpecs, 're-exchange': reexchange})
		next = self.waitForPhase('connect', 2)
		
		if 'cert' in next:
			server_cert = base64.urlsafe_b64decode(str(next['cert']))
			if common_cert.verifyServerCertificate(server_cert):
				print "[ \033[43mSERVER\033[0m ]: Received a valid certificate from the server."
				self.serverCert = server_cert
			else:
				print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Received an invalid certificate from the server."
				return
		
		if next['ciphers'] != []:
			for spec in self.availableCipherSpecs:
				if spec in next['ciphers']:
					self.serverCipherSpec = spec
					print "[ \033[45m SPEC \033[0m ]:", spec
					self.generateTransportKeyPair(self.getKeyExchangeFromSpec(spec))
					break



		if self.serverCipherSpec == "":
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Unable to reach a cipher agreement with the server."
			return
		
		challenge_to_server = os.urandom(16)


		self.send({'type': 'connect', 'phase' : 3, 're-exchange': reexchange, 'name': base64.urlsafe_b64encode(self.userName), 'id' : base64.urlsafe_b64encode(os.urandom(8)),
				   'uid' : base64.urlsafe_b64encode(uid), 'ciphers' : [self.serverCipherSpec], 'cert' : base64.urlsafe_b64encode(self.userCert),
				   'challenge' :  base64.urlsafe_b64encode(challenge_to_server),
				   'data' : {'pubkey' : self.pubkey_tls.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)} } )
		   
		next = self.waitForPhase('connect', 4)

		if 'response' in next:
			response_from_server = base64.urlsafe_b64decode(str(next['response']))
			if common_cert.verifySignature_pss(self.serverCert, response_from_server, challenge_to_server):
				print "[ \033[43mSERVER\033[0m ]: Server correctly responded to challenge."
				self.serverCert = server_cert
			else:
				print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Server has given an invalid respose to challenge."
				return

		if 'challenge' in next:
			challenge_from_server = base64.urlsafe_b64decode(str(next['challenge']))
			response_to_server = self.cardSession.sign(self.cardSession.findObjects()[0], challenge_from_server, mecha=PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None))
			response_to_server = ''.join(chr(signature_byte) for signature_byte in response_to_server)		
		else:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Server did not provide challenge."
			return

		if 'level' in next:
			self.level = int(next['level'])
		else:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Server did not provide level."
			return

		imported_key = serialization.load_pem_public_key(str(next['data']['pubkey']), backend=default_backend())
		self.secret = self.privkey_tls.exchange(ec.ECDH(), imported_key)
		del self.privkey_tls
		del self.pubkey_tls
		
		connectionSaltA = base64.urlsafe_b64decode(str(next['data']['saltA']))
		connectionSaltB = os.urandom(16)
		
		if DEBUG:
			print "[ \033[43mSERVER\033[0m ]: Shared secret established."
			print "[ \033[43mSERVER\033[0m ]: Server is now verifying client-side key."
		
		
		derived_key = PBKDF2HMAC(algorithm=hashes.SHA512(), length=64, salt=connectionSaltA+connectionSaltB, iterations=100000, backend=default_backend()).derive(self.secret)
		
		plaintext = "Verification OK"+os.urandom(16)
		






		cipher_algo = algorithms.AES(derived_key[:32])
		counternonce = os.urandom(cipher_algo.block_size/8)

		bc_spec = self.getBlockCipherModeFromSpec(self.serverCipherSpec)
		if bc_spec == "CTR":
			ciphermode = modes.CTR(counternonce)
		elif bc_spec == "OFB":
			ciphermode = modes.OFB(counternonce)

		countercipher = Cipher(cipher_algo, ciphermode, backend=default_backend())
		ciphertext_gen = countercipher.encryptor()
		
		ciphertext = ciphertext_gen.update(plaintext) + ciphertext_gen.finalize()
		
		hmac_holder = hmac.HMAC(derived_key[32:64], hashes.SHA256(), backend=default_backend())
		hmac_holder.update(ciphertext)
		hmac_to_send = hmac_holder.finalize()
		
		
		self.send({'type': 'connect', 'phase' : 5, 'name': base64.urlsafe_b64encode(self.userName), 're-exchange': reexchange, 'id' : base64.urlsafe_b64encode(os.urandom(8)),
				   'uid' : base64.urlsafe_b64encode(uid), 'ciphers' : [self.serverCipherSpec], 'response' : base64.urlsafe_b64encode(response_to_server),
				   'data' : {'saltB' : base64.urlsafe_b64encode(connectionSaltB), 'ciphertext' : base64.urlsafe_b64encode(ciphertext),
							 'counternonce' : base64.urlsafe_b64encode(counternonce), 'hmac' : base64.urlsafe_b64encode(hmac_to_send) } } )

							 
		next = self.waitForPhase('connect', 6)
		if DEBUG:
			print "[ \033[43mSERVER\033[0m ]: Server-side verification successful."
			print "[ \033[43mSERVER\033[0m ]: Client is now verifying server-side key."
		

		
		ciphertext = base64.urlsafe_b64decode(str(next['data']['ciphertext']))
		received_hmac = base64.urlsafe_b64decode(str(next['data']['hmac']))

		cipher_algo = algorithms.AES(derived_key[:32])
		counternonce = base64.urlsafe_b64decode(str(next['data']['counternonce']))


		bc_spec = self.getBlockCipherModeFromSpec(self.serverCipherSpec)
		if bc_spec == "CTR":
			ciphermode = modes.CTR(counternonce)
		elif bc_spec == "OFB":
			ciphermode = modes.OFB(counternonce)


		countercipher = Cipher(cipher_algo, ciphermode, backend=default_backend())
		plaintext_gen = countercipher.decryptor()
		plaintext = plaintext_gen.update(ciphertext) + plaintext_gen.finalize()

		hmac_holder = hmac.HMAC(derived_key[32:64], hashes.SHA256(), backend=default_backend())
		hmac_holder.update(ciphertext)
		try:
			hmac_holder.verify(received_hmac)
		except:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Client-side verification failed."
			return

		if DEBUG:
			print "[ \033[43mSERVER\033[0m ]: Client-side verification successful."
		print "[ \033[43mSERVER\033[0m ]: Connected to message server."
		self.resetSecretAfter = time.time() + MAX_SERVER_SESSION_SECONDS
		
	def send(self, msg):
		self.sock.send(json.dumps(msg) + '\n\n')


	def sendClientAck(self, dst, msg):
		msg_to_send = {'type' : 'client-ack', 'src': self.uid, 'dst' : dst}
		

		derived_key = self.connectedClients[msg_to_send['dst']]['data']['nextCipherKey']


		ack_message_digest = SHA256.new()
		ack_message_digest.update(json.dumps(msg))
		ack_message_digest = ack_message_digest.digest()
		ack_signature = base64.urlsafe_b64encode(
							''.join(chr(signature_byte) for signature_byte in
									self.cardSession.sign(
										self.cardSession.findObjects()[0], ack_message_digest, mecha=PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
									)
							)	
												
						)


		if DEBUG:
			print "[ \033[44m\033[1mCLIENT\033[0m\033[0m ]: Sending CLIENT ACK for", json.dumps(msg)

		ack_dict = dict()

		ack_dict['signature'] = ack_signature
		ack_dict['message_digest'] = base64.urlsafe_b64encode(ack_message_digest)

		plaintext = json.dumps(ack_dict)

		cipher_algo = algorithms.AES(derived_key[:32])
		counternonce = os.urandom(cipher_algo.block_size/8)

		bc_spec = self.getBlockCipherModeFromSpec(self.connectedClients[msg_to_send['dst']]['chosenSpec'])
		if bc_spec == "CTR":
			ciphermode = modes.CTR(counternonce)
		elif bc_spec == "OFB":
			ciphermode = modes.OFB(counternonce)


		countercipher = Cipher(cipher_algo, ciphermode, backend=default_backend())
		ciphertext_gen = countercipher.encryptor()

		ciphertext = ciphertext_gen.update(plaintext) + ciphertext_gen.finalize()
		hmac_holder = hmac.HMAC(derived_key[32:64], hashes.SHA256(), backend=default_backend())
		hmac_holder.update(ciphertext)
		hmac_to_send = hmac_holder.finalize()

		msg_to_send['data'] = dict()
		msg_to_send['data']['ciphertext'] = base64.urlsafe_b64encode(ciphertext)
		msg_to_send['data']['counternonce'] = base64.urlsafe_b64encode(counternonce)
		msg_to_send['data']['hmac'] = base64.urlsafe_b64encode(hmac_to_send)


		msg_to_send['data']['signature'] = base64.urlsafe_b64encode(
												''.join(chr(signature_byte) for signature_byte in
														self.cardSession.sign(
															self.cardSession.findObjects()[0], json.dumps(msg_to_send), mecha=PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
														)
												)	
												
											 )



		self.sendSecureToServer(msg_to_send)


	def sendMessage(self, msg):
		if self.selectedClient == -1:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: No client selected."
			return
		msg = msg.replace('\n\n', '')
		if msg == '':
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Empty message not sent."
			return

		msg_to_send = {'type' : 'client-com', 'src' : self.uid, 'dst': self.clientList[self.selectedClient-1]['id']}
		

		if msg_to_send['dst'] not in self.connectedClients:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Client not connected"
			return

		if 'nextCipherKey' not in self.connectedClients[msg_to_send['dst']]['data']:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Client not properly connected. Reconnect."
			return

		derived_key = self.connectedClients[msg_to_send['dst']]['data']['nextCipherKey']
	
		post_verification = dict() # Save some information to save in the logfiles
		post_verification['msg'] = base64.urlsafe_b64encode(msg)
		post_verification['messageno'] = self.connectedClients[msg_to_send['dst']]['sent_messages'] + 1
		if 'lastsignature' in self.connectedClients[msg_to_send['dst']]: # First sent message won't have a "last signature"
			post_verification['lastsignature'] = self.connectedClients[msg_to_send['dst']]['lastsignature']
		post_verification['signature'] = base64.urlsafe_b64encode(
												''.join(chr(signature_byte) for signature_byte in
														self.cardSession.sign(
															self.cardSession.findObjects()[0], json.dumps(post_verification), mecha=PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
														)
												)	
												
											 )
		post_verification['msg'] = "" # Placeholder. Don't delete this, just keep it empty for now

		self.connectedClients[msg_to_send['dst']]['lastsignature'] = post_verification['signature'] # We signed the message already, lastsignature is now the actual signature


		plaintext = msg


		cipher_algo = algorithms.AES(derived_key[:32])
		counternonce = os.urandom(cipher_algo.block_size/8)

		bc_spec = self.getBlockCipherModeFromSpec(self.connectedClients[msg_to_send['dst']]['chosenSpec'])
		if bc_spec == "CTR":
			ciphermode = modes.CTR(counternonce)
		elif bc_spec == "OFB":
			ciphermode = modes.OFB(counternonce)


		countercipher = Cipher(cipher_algo, ciphermode, backend=default_backend())
		ciphertext_gen = countercipher.encryptor()

		ciphertext = ciphertext_gen.update(plaintext) + ciphertext_gen.finalize()
		hmac_holder = hmac.HMAC(derived_key[32:64], hashes.SHA256(), backend=default_backend())
		hmac_holder.update(ciphertext)
		hmac_to_send = hmac_holder.finalize()

		msg_to_send['data'] = dict()
		msg_to_send['data']['ciphertext'] = base64.urlsafe_b64encode(ciphertext)
		msg_to_send['data']['counternonce'] = base64.urlsafe_b64encode(counternonce)
		msg_to_send['data']['hmac'] = base64.urlsafe_b64encode(hmac_to_send)
		msg_to_send['data']['post_verification'] = post_verification
		msg_to_send['data']['signature'] = base64.urlsafe_b64encode(
												''.join(chr(signature_byte) for signature_byte in
														self.cardSession.sign(
															self.cardSession.findObjects()[0], json.dumps(msg_to_send), mecha=PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
														)
												)	
												
											 )
		
		

		if DEBUG:
			print "[ \033[43m\033[1m DEBUG \033[0m\033[0m ]: Expecting ACK for ",json.dumps(msg_to_send) 
	
		message_digest = SHA256.new()
		message_digest.update(json.dumps(msg_to_send))
		encoded_digest = base64.urlsafe_b64encode(message_digest.digest())
		self.connectedClients[msg_to_send['dst']]['waitingForClientACK'][encoded_digest] = dict()
		self.connectedClients[msg_to_send['dst']]['waitingForClientACK'][encoded_digest]['time'] = time.time() 
		self.connectedClients[msg_to_send['dst']]['waitingForClientACK'][encoded_digest]['content'] = json.dumps(msg_to_send)

		print "[ \033[42m\033[1m  YOU  \033[0m\033[0m ]: " + plaintext 
		self.sendSecureToServer(msg_to_send)

		self.connectedClients[msg_to_send['dst']]['sent_messages'] += 1

		
		self.TRADED_MESSAGES += 1
		if self.TRADED_MESSAGES > MAX_SERVER_MESSAGES:
			self.connect(reexchange=True) # Exchange client-server keys
			self.TRADED_MESSAGES = 0

		self.newClientCipherKey({'type' : 'newclientkey', 'src' : self.clientList[self.selectedClient-1]['id'], 'dst': self.uid, 'phase' : 0})


		if self.connectedClients[msg_to_send['dst']]['sent_messages'] >= MAX_ENDPOINT_MESSAGES:
			print "[ \033[44mCLIENT\033[0m ]: Re-exchanging keys for client", msg_to_send['dst']
			self.processClientConnect(None, reexchange=True) # Exchange client-client keys



	def sendDisconnect(self):
		if self.selectedClient == -1:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: No client selected."
			return

		msg_to_send = {'type' : 'client-disconnect', 'src' : self.uid, 'dst': self.clientList[self.selectedClient-1]['id']}

		if msg_to_send['dst'] not in self.connectedClients:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Client not connected"
			return


		print "[ \033[44mCLIENT\033[0m ]: Disconnected from " + self.clientList[self.selectedClient-1]['id']

		del self.connectedClients[msg_to_send['dst']]


		self.sendSecureToServer(msg_to_send)

		
	def processDisconnect(self, msg):
		if not all (k in msg.keys() for k in ("src", "dst")):
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Disconnect message with missing fields"
			return

		if msg['src'] not in self.connectedClients:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Client not connected"
			return


		print "[ \033[44mCLIENT\033[0m ]: Disconnected from " + msg['src']

		del self.connectedClients[msg['src']]


	def processClientACK(self, msg):

		if (not 'data' in msg) or (not all (k in msg['data'].keys() for k in ("ciphertext", "counternonce", "hmac", "signature"))):
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: New key negotiation message with missing fields"
			return
		
		
		signature = base64.urlsafe_b64decode(str(msg['data']['signature']))
		del msg['data']['signature']
		temp_sa_data = msg['data']

		msg['data'] = dict()
		for k in sorted(temp_sa_data.keys()):
				msg['data'][k] = temp_sa_data[k]


		if common_cert.verifySignature(self.connectedClients[msg['src']]['cert'] , signature, json.dumps(msg)):
			print "[ \033[43m\033[1m DEBUG \033[0m\033[0m ]: Client message successfully verified!"
		else:
			print "[ \033[45m\033[1m SRS ERROR \033[0m\033[0m ]: Bad identity signature!!"
			return



		derived_key = self.connectedClients[msg['src']]['data']['nextCipherKey']


		ciphertext = base64.urlsafe_b64decode(str(msg['data']['ciphertext']))
		received_hmac = base64.urlsafe_b64decode(str(msg['data']['hmac']))

		cipher_algo = algorithms.AES(derived_key[:32])
		counternonce = base64.urlsafe_b64decode(str(msg['data']['counternonce']))

		bc_spec = self.getBlockCipherModeFromSpec(self.connectedClients[msg['src']]['chosenSpec'])
		if bc_spec == "CTR":
			ciphermode = modes.CTR(counternonce)
		elif bc_spec == "OFB":
			ciphermode = modes.OFB(counternonce)


		countercipher = Cipher(cipher_algo, ciphermode, backend=default_backend())
		plaintext_gen = countercipher.decryptor()
		plaintext = plaintext_gen.update(ciphertext) + plaintext_gen.finalize()

		hmac_holder = hmac.HMAC(derived_key[32:64], hashes.SHA256(), backend=default_backend())
		hmac_holder.update(ciphertext)
		try:
			hmac_holder.verify(received_hmac)
		except:
			print "[ \033[45m\033[1m SRS ERROR \033[0m\033[0m ]: >    CLIENT-CLIENT MESSAGE VERIRICATION FAILED   <" 
			return

		self.checkClientAck(msg['src'], json.loads(plaintext))



	def processMessage(self, msg):

		if (not 'data' in msg) or (not all (k in msg['data'].keys() for k in ("ciphertext", "counternonce", "hmac", "signature"))):
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: New key negotiation message with missing fields"
			return
		

		signature = base64.urlsafe_b64decode(str(msg['data']['signature']))
		request_to_ack = copy.deepcopy(msg)
		del msg['data']['signature']
		temp_sa_data = msg['data']
		ack_sa_data = request_to_ack['data']


		msg['data'] = dict()
		for k in sorted(temp_sa_data.keys()):
				msg['data'][k] = temp_sa_data[k]

		request_to_ack['data'] = dict()
		for k in sorted(ack_sa_data.keys()):
				request_to_ack['data'][k] = ack_sa_data[k]


		if common_cert.verifySignature(self.connectedClients[msg['src']]['cert'] , signature, json.dumps(msg)):
			print "[ \033[43m\033[1m DEBUG \033[0m\033[0m ]: Client message successfully verified!"
		else:
			print "[ \033[45m\033[1m SRS ERROR \033[0m\033[0m ]: Bad identity signature!!"
			return





		derived_key = self.connectedClients[msg['src']]['data']['nextCipherKey']


		ciphertext = base64.urlsafe_b64decode(str(msg['data']['ciphertext']))
		received_hmac = base64.urlsafe_b64decode(str(msg['data']['hmac']))

		cipher_algo = algorithms.AES(derived_key[:32])
		counternonce = base64.urlsafe_b64decode(str(msg['data']['counternonce']))

		bc_spec = self.getBlockCipherModeFromSpec(self.connectedClients[msg['src']]['chosenSpec'])
		if bc_spec == "CTR":
			ciphermode = modes.CTR(counternonce)
		elif bc_spec == "OFB":
			ciphermode = modes.OFB(counternonce)


		countercipher = Cipher(cipher_algo, ciphermode, backend=default_backend())
		plaintext_gen = countercipher.decryptor()
		plaintext = plaintext_gen.update(ciphertext) + plaintext_gen.finalize()


		hmac_holder = hmac.HMAC(derived_key[32:64], hashes.SHA256(), backend=default_backend())
		hmac_holder.update(ciphertext)




		try:
			hmac_holder.verify(received_hmac)
			print "[ \033[42m" + msg['src'] + "\033[0m ]: " + unicode(plaintext, 'utf-8')

			msg['data']['post_verification']['msg'] = base64.urlsafe_b64encode(plaintext)

			with open(msg['src'], 'a+b') as f:
				f.write(json.dumps(msg['data']['post_verification']) + '\n\n')
				f.close()

			self.TRADED_MESSAGES += 1
			if self.TRADED_MESSAGES > MAX_SERVER_MESSAGES:
				self.connect(reexchange=True)
				self.TRADED_MESSAGES = 0
		except:
			print "[ \033[45m\033[1m SRS ERROR \033[0m\033[0m ]: >    CLIENT-CLIENT MESSAGE VERIRICATION FAILED   <" 
			return	

		self.sendClientAck(msg['src'], request_to_ack)



	def newServerCipherKey(self, message):
		if message is None or message['phase'] == 0:
			msg = {'type': 'newkey', 'phase': 1, 'id' : base64.urlsafe_b64encode(os.urandom(8)),  'ciphers': [self.serverCipherSpec]}
			self.saltB = os.urandom(16)
			self.keyIsVerified = False
			msg['data'] = dict()
			msg['data']['saltB'] = base64.urlsafe_b64encode(self.saltB)
			self.send(msg)
			return
		
		elif not all (k in message.keys() for k in ("data", "id")):
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: New key negotiation message with missing fields"
			return

		msg = {'type': 'newkey', 'phase': message['phase'] + 1, 'ciphers': [self.serverCipherSpec]}

		if msg['phase'] == 3:
			
			saltA = base64.urlsafe_b64decode(str(message['data']['saltA']))
			saltB = self.saltB

		
			ciphertext = base64.urlsafe_b64decode(str(message['data']['ciphertext']))
			received_hmac = base64.urlsafe_b64decode(str(message['data']['hmac']))
			
			
		
			derived_key = PBKDF2HMAC(algorithm=hashes.SHA512(), length=64, salt=saltA+saltB, iterations=100000, backend=default_backend()).derive(self.secret)
			cipher_algo = algorithms.AES(derived_key[:32])
			counternonce = base64.urlsafe_b64decode(str(message['data']['counternonce']))

			bc_spec = self.getBlockCipherModeFromSpec(self.serverCipherSpec)
			if bc_spec == "CTR":
				ciphermode = modes.CTR(counternonce)
			elif bc_spec == "OFB":
				ciphermode = modes.OFB(counternonce)

			countercipher = Cipher(cipher_algo, ciphermode, backend=default_backend())
			plaintext_gen = countercipher.decryptor()
			plaintext = plaintext_gen.update(ciphertext) + plaintext_gen.finalize()
			
			hmac_holder = hmac.HMAC(derived_key[32:64], hashes.SHA256(), backend=default_backend())
			hmac_holder.update(ciphertext)
			try:
				hmac_holder.verify(received_hmac)
				self.keyIsVerified = True
			except InvalidSignature:
				print "[ \033[45m\033[1m SRS ERROR \033[0m\033[0m ]: >    SERVER SIGNATURE VERIRICATION FAILED (3)  <" 
				return	


				

			self.nextCipherKey = derived_key

			plaintext = "Verification OK"+os.urandom(16)

			cipher_algo = algorithms.AES(derived_key[:32])
			counternonce = os.urandom(cipher_algo.block_size/8)

			if bc_spec == "CTR":
				ciphermode = modes.CTR(counternonce)
			elif bc_spec == "OFB":
				ciphermode = modes.OFB(counternonce)

			countercipher = Cipher(cipher_algo, ciphermode, backend=default_backend())
			ciphertext_gen = countercipher.encryptor()

			ciphertext = ciphertext_gen.update(plaintext) + ciphertext_gen.finalize()

			hmac_holder = hmac.HMAC(derived_key[32:64], hashes.SHA256(), backend=default_backend())
			hmac_holder.update(ciphertext)
			hmac_to_send = hmac_holder.finalize()


			self.send({'type': 'newkey', 'phase' : 3, 'id' : base64.urlsafe_b64encode(os.urandom(8)), 'ciphers' : [self.serverCipherSpec],
				   'data' : {'ciphertext' : base64.urlsafe_b64encode(ciphertext),
							 'counternonce' : base64.urlsafe_b64encode(counternonce), 'hmac' : base64.urlsafe_b64encode(hmac_to_send) } } )
			return

	def newClientCipherKey(self, msg):
		#time.sleep(0.2)
		if not all (k in msg.keys() for k in ("phase", "src", "dst")):
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: New key negotiation message with missing fields"
			return
		
		if msg['phase'] != 0:
			self.sendACK(msg['src'])

		msg_to_send = {'type' : 'newclientkey', 'src' : self.uid, 'dst': msg['src'], 'phase' : msg['phase'] + 1}

		if msg_to_send['dst'] not in self.connectedClients or self.connectedClients[msg_to_send['dst']]['state'] != STATE_CONNECTED:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Client not connected!"
			return
			
		if msg_to_send['phase'] == 1:
			self.connectedClients[msg_to_send['dst']]['saltA'] = os.urandom(16)
			self.connectedClients[msg_to_send['dst']]['keyIsVerified'] = False

			msg_to_send['data'] = dict()
			msg_to_send['data']['saltA'] = base64.urlsafe_b64encode(self.connectedClients[msg_to_send['dst']]['saltA'])

		if msg_to_send['phase'] == 2:
			self.connectedClients[msg_to_send['dst']]['saltA'] = base64.urlsafe_b64decode(str(msg['data']['saltA']))
			self.connectedClients[msg_to_send['dst']]['saltB'] = os.urandom(16)
			self.connectedClients[msg_to_send['dst']]['keyIsVerified'] = False
			saltA = self.connectedClients[msg_to_send['dst']]['saltA']
			saltB = self.connectedClients[msg_to_send['dst']]['saltB']

			derived_key = PBKDF2HMAC(algorithm=hashes.SHA512(), length=64, salt=saltA+saltB, iterations=100000,
					backend=default_backend()).derive(self.connectedClients[msg_to_send['dst']]['data']['secret'])


			plaintext = "Negotiation OK"+os.urandom(16)
		
			cipher_algo = algorithms.AES(derived_key[:32])
			counternonce = os.urandom(cipher_algo.block_size/8)


			bc_spec = self.getBlockCipherModeFromSpec(self.connectedClients[msg_to_send['dst']]['chosenSpec'])
			if bc_spec == "CTR":
				ciphermode = modes.CTR(counternonce)
			elif bc_spec == "OFB":
				ciphermode = modes.OFB(counternonce)

			countercipher = Cipher(cipher_algo, ciphermode, backend=default_backend())
			ciphertext_gen = countercipher.encryptor()
		
			ciphertext = ciphertext_gen.update(plaintext) + ciphertext_gen.finalize()
		
			hmac_holder = hmac.HMAC(derived_key[32:64], hashes.SHA256(), backend=default_backend())
			hmac_holder.update(ciphertext)
			hmac_to_send = hmac_holder.finalize()

			self.connectedClients[msg_to_send['dst']]['data']['nextCipherKey'] = derived_key

			msg_to_send['data'] = dict()
			msg_to_send['data']['saltB'] = base64.urlsafe_b64encode(self.connectedClients[msg_to_send['dst']]['saltB'])
			msg_to_send['data']['ciphertext'] = base64.urlsafe_b64encode(ciphertext)
			msg_to_send['data']['counternonce'] = base64.urlsafe_b64encode(counternonce)
			msg_to_send['data']['hmac'] = base64.urlsafe_b64encode(hmac_to_send)
			
		if msg_to_send['phase'] == 3:
			
			self.connectedClients[msg_to_send['dst']]['saltB'] = base64.urlsafe_b64decode(str(msg['data']['saltB']))
			saltA = self.connectedClients[msg_to_send['dst']]['saltA']
			saltB = self.connectedClients[msg_to_send['dst']]['saltB']
		
			ciphertext = base64.urlsafe_b64decode(str(msg['data']['ciphertext']))
			received_hmac = base64.urlsafe_b64decode(str(msg['data']['hmac']))
					
		
			derived_key = PBKDF2HMAC(algorithm=hashes.SHA512(), length=64, salt=saltA+saltB, iterations=100000,
				backend=default_backend()).derive(self.connectedClients[msg_to_send['dst']]['data']['secret'])

			cipher_algo = algorithms.AES(derived_key[:32])

			counternonce = base64.urlsafe_b64decode(str(msg['data']['counternonce']))


			bc_spec = self.getBlockCipherModeFromSpec(self.connectedClients[msg_to_send['dst']]['chosenSpec'])
			if bc_spec == "CTR":
				ciphermode = modes.CTR(counternonce)
			elif bc_spec == "OFB":
				ciphermode = modes.OFB(counternonce)

			countercipher = Cipher(cipher_algo, ciphermode, backend=default_backend())
			plaintext_gen = countercipher.decryptor()
			plaintext = plaintext_gen.update(ciphertext) + plaintext_gen.finalize()
			
			hmac_holder = hmac.HMAC(derived_key[32:64], hashes.SHA256(), backend=default_backend())
			hmac_holder.update(ciphertext)

			try:
				hmac_holder.verify(received_hmac)
				self.connectedClients[msg_to_send['dst']]['keyIsVerified'] = True
				print "[ \033[100m INFO \033[0m ]: New key generated and verified for this conversation."
			except:
				print "[ \033[45m\033[1m SRS ERROR \033[0m\033[0m ]: >    CLIENT-CLIENT SIGNATURE VERIRICATION FAILED   <" 
				return	


			self.connectedClients[msg_to_send['dst']]['data']['nextCipherKey'] = derived_key

			plaintext = "Verification OK"+os.urandom(16)

			cipher_algo = algorithms.AES(derived_key[:32])
			counternonce = os.urandom(cipher_algo.block_size/8)

			if bc_spec == "CTR":
				ciphermode = modes.CTR(counternonce)
			elif bc_spec == "OFB":
				ciphermode = modes.OFB(counternonce)


			countercipher = Cipher(cipher_algo, ciphermode, backend=default_backend())
			ciphertext_gen = countercipher.encryptor()

			ciphertext = ciphertext_gen.update(plaintext) + ciphertext_gen.finalize()

			hmac_holder = hmac.HMAC(derived_key[32:64], hashes.SHA256(), backend=default_backend())
			hmac_holder.update(ciphertext)
			hmac_to_send = hmac_holder.finalize()

			msg_to_send['data'] = dict()
			msg_to_send['data']['saltB'] = base64.urlsafe_b64encode(self.connectedClients[msg_to_send['dst']]['saltB'])
			msg_to_send['data']['ciphertext'] = base64.urlsafe_b64encode(ciphertext)
			msg_to_send['data']['counternonce'] = base64.urlsafe_b64encode(counternonce)
			msg_to_send['data']['hmac'] = base64.urlsafe_b64encode(hmac_to_send)

			del self.connectedClients[msg_to_send['dst']]['saltA']
			del self.connectedClients[msg_to_send['dst']]['saltB']


		if msg_to_send['phase'] == 4:

			ciphertext = base64.urlsafe_b64decode(str(msg['data']['ciphertext']))
			received_hmac = base64.urlsafe_b64decode(str(msg['data']['hmac']))

			cipher_algo = algorithms.AES(self.connectedClients[msg_to_send['dst']]['data']['nextCipherKey'][:32])
			counternonce = base64.urlsafe_b64decode(str(msg['data']['counternonce']))

			bc_spec = self.getBlockCipherModeFromSpec(self.connectedClients[msg_to_send['dst']]['chosenSpec'])
			if bc_spec == "CTR":
				ciphermode = modes.CTR(counternonce)
			elif bc_spec == "OFB":
				ciphermode = modes.OFB(counternonce)


			countercipher = Cipher(cipher_algo, ciphermode, backend=default_backend())
			plaintext_gen = countercipher.decryptor()
			plaintext = plaintext_gen.update(ciphertext) + plaintext_gen.finalize()

			hmac_holder = hmac.HMAC(self.connectedClients[msg_to_send['dst']]['data']['nextCipherKey'][32:64], hashes.SHA256(), backend=default_backend())
			hmac_holder.update(ciphertext)

			try:
				hmac_holder.verify(received_hmac)
				self.connectedClients[msg_to_send['dst']]['keyIsVerified'] = True
				print "[ \033[100m INFO \033[0m ]: New key generated and verified for this conversation."
				del self.connectedClients[msg_to_send['dst']]['saltA']
				del self.connectedClients[msg_to_send['dst']]['saltB']
				return
			except:
				print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Client-side verification failed."
				return			
			
		
		if msg_to_send['phase'] < 4:
			self.sendSecureToServer(msg_to_send)




	def listenLoop(self):
		print "[ \033[100m INFO \033[0m ]: Ready."

		while True:
			while len(self.msgs) != 0:
				if DEBUG:
					sys.stdout.write("[ \033[46m QUEUE \033[0m ]: (" + str(len(self.msgs)) + "): [")
					for debugmsg in self.msgs:
						debugmsg_parsed = self.parseMsg(debugmsg)
						to_print = debugmsg_parsed['type']
						if to_print == 'newkey':
							to_print += str(debugmsg_parsed['phase'])
						sys.stdout.write(to_print + ", ")
					print "]"
				parsed = self.parseMsg(self.msgs.pop(0))
				if parsed['type'].upper() == 'NEWKEY':
					if (self.keyIsVerified == False and parsed['phase'] == 0):
						continue
					self.newServerCipherKey(parsed)
				if parsed['type'].upper() == 'SECURE':
					self.processSecure(parsed)


			(input_list, [], []) = select([self.sock, sys.stdin], [], [], 0.1)
			for input_elem in input_list:
				if input_elem == self.sock:
					data = self.buffer + input_elem.recv(BUFSIZE)
					temp_msgs = data.split("\n\n")
					self.msgs += temp_msgs[:-1]
					self.buffer = temp_msgs[-1]
				elif input_elem == sys.stdin:
					self.processUserInput(sys.stdin.readline().strip())

			current = time.time() # REFRESH
			if current > self.resetSecretAfter and self.resetSecretAfter != -1:
				print "[ \033[43mSERVER\033[0m ]: Re-exchanging client-server keys."
				self.resetSecretAfter = -1
				self.connect(reexchange=True)
				self.TRADED_MESSAGES = 0
			for client in self.connectedClients.keys():
				if 'last' in self.connectedClients[client] and self.connectedClients[client]['last'] == True:
					if current > self.connectedClients[client]['refreshMeAfter'] and self.connectedClients[client]['refreshMeAfter'] != -1:
						print "[ \033[44mCLIENT\033[0m ]: Re-exchanging keys for client", client
						self.connectedClients[client]['refreshMeAfter'] = -1
						self.processClientConnect({'type' : 'client-connect', 'src': client , 'dst': self.uid, 'phase' : 0, 'reexchange': True}, reexchange=True)

			something_changed = False

			while True: # Check if any server messages need to be resent
				resent = False
				for msg in self.waitingForServerACK:
					if 'resent' in self.waitingForServerACK[msg]:
						continue
					if (current - self.waitingForServerACK[msg]['time']) > RESEND_IF_NOT_ACKED:
						self.send(json.loads(self.waitingForServerACK[msg]['content']))
						print "[ \033[43mSERVER\033[0m ]: Resending non-ACKED message (" + json.loads(self.waitingForServerACK[msg]['content'])['type'] + ")"
						self.waitingForServerACK[msg]['resent'] = True
						resent = True
						break
				if not resent:
					break


			for cli in self.connectedClients:
				while True: # Check if any client messages need to be resent
					resent = False
					for msg in self.connectedClients[cli]['waitingForClientACK']:
						if 'resent' in self.connectedClients[cli]['waitingForClientACK'][msg]:
							continue
						if (current - self.connectedClients[cli]['waitingForClientACK'][msg]['time']) > RESEND_IF_NOT_ACKED:
							self.sendSecureToServer(json.loads(self.connectedClients[cli]['waitingForClientACK'][msg]['content']))
							print "[ \033[44mCLIENT\033[0m ]: Resending non-ACKED message (" + json.loads(self.connectedClients[cli]['waitingForClientACK'][msg]['content'])['type'] + ")"
							self.connectedClients[cli]['waitingForClientACK'][msg]['resent'] = True
							resent = True
							break
					if not resent:
						break

	def processUserInput(self, userinput):
		if userinput == 'list':
			self.getList()
			return
		if userinput[:6] == 'select':
			try:
				selected = int(userinput.split(" ")[1])
				print "[ \033[100m INFO \033[0m ]: Selected client %d - %s" % (selected, self.clientList[selected-1]['id'])
				self.selectedClient = selected
			except:
				return
		if userinput == 'connect':
			self.processClientConnect(None)
		if userinput == 'testclient':
			self.newClientCipherKey({'type' : 'newclientkey', 'src' : self.clientList[self.selectedClient-1]['id'], 'dst': self.uid, 'phase' : 0})
		if userinput[:4] == 'say ':
			self.sendMessage(userinput[4:])
		if userinput == 'disconnect':
			self.sendDisconnect()
		if userinput == 'exchange':
			self.connect(reexchange=True)
		if userinput == 'clientexchange':
			self.processClientConnect(None, reexchange=True)
		if userinput == 'whoami':
			print "[ \033[100m INFO \033[0m ]: " + self.uid + " (level " + str(self.level) + ")"
					
					
	def waitForPhase(self, messagetype, phase):
		while True:
		
			for msg in self.msgs:
				temp = self.msgs.pop(0)
				parsed = self.parseMsg(temp)
				if parsed['type'] == messagetype and parsed['phase'] == phase:
					return parsed
				self.msgs.append(temp)
			
			(input_list, [], []) = select([self.sock], [], [], 0.1)
			for input_elem in input_list:
				data = self.buffer + input_elem.recv(BUFSIZE)
				temp_msgs = data.split("\n\n")
				self.msgs += temp_msgs[:-1]
				self.buffer = temp_msgs[-1]
						
	def generateTransportKeyPair(self, algorithm, interclient=False):
		if algorithm == 'ECDHE':
			self.privkey_tls = ec.generate_private_key(ec.SECP256K1, default_backend())
			self.pubkey_tls = self.privkey_tls.public_key()
		if interclient:
			client_keys = dict()
			client_keys['privkey'] = ec.generate_private_key(ec.SECP256K1, default_backend())
			client_keys['pubkey'] = client_keys['privkey'].public_key()
			return client_keys

	def parseMsg(self, data):
		return json.loads(data)
	
if __name__ == "__main__":
		cli = Client('127.0.0.1', 8080)
