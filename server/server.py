#!/usr/bin/env python
# encoding: utf-8
#
# jpbarraca@ua.pt
# jmr@ua.pt 2016

# vim setings:
# :set expandtab ts=4

from socket import *
from select import *
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization, hmac, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature 
import os
import json
import sys
import time
import logging
import base64
import copy
from Crypto.Hash import SHA, SHA256
from OpenSSL.crypto import FILETYPE_ASN1
import common_cc, common_cert



# Server address
HOST = ""   # All available interfaces
PORT = 8080  # The server port

BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"
MAX_BUFSIZE = 64 * 1024

STATE_NONE = 0
STATE_CONNECTED = 1
STATE_DISCONNECTED = 2
STATE_CONNECTING = 3
SERVER_CERTIFICATE_PATH = "certs/server.crt"
PRIVATE_KEY_PATH = "certs/server_k.pem"
USER_LEVEL_FILE = "userlevels"
AVAILABLE_CIPHER_SPECS = ['ECDHE_WITH_AES_256_CTR_SHA256', 'ECDHE_WITH_AES_256_OFB_SHA256']
IGNORE_LIST_COUNT = True
DEBUG = False

class Client:
	count = 0

	def __init__(self, socket, addr):
		self.socket = socket
		self.bufin = ""
		self.bufout = ""
		self.addr = addr
		self.id = None
		self.chosenSpec = None
		self.sa_data = dict()
		self.userCert = None
		self.level = 0
		self.state = STATE_NONE
		self.currentPhase = 0
		self.negotiationPhase = 0
		self.waitingForClientACK = dict()
		self.name = "Unknown"

	def __str__(self):
		""" Converts object into string.
		"""
		return "Client(id=%r addr:%s name:%s level:%d state:%d)" % (self.id, str(self.addr), self.name, self.level, self.state)

	def asDict(self):
		return {'id': self.id, 'level': self.level, 'name' : base64.urlsafe_b64encode(self.name), 'ccID' : self.ccID}

	def setState(self, state):
		if state not in [STATE_CONNECTED, STATE_NONE, STATE_DISCONNECTED, STATE_CONNECTING]:
			return

		self.state = state

	def parseReqs(self, data):
		"""Parse a chunk of data from this client.
		Return any complete requests in a list.
		Leave incomplete requests in the buffer.
		This is called whenever data is available from client socket."""

		if len(self.bufin) + len(data) > MAX_BUFSIZE:
			logging.error("Client (%s) buffer exceeds MAX BUFSIZE. %d > %d", 
				(self, len(self.bufin) + len(data), MAX_BUFSIZE))
			self.bufin = ""

		self.bufin += data
		reqs = self.bufin.split(TERMINATOR)
		#print reqs
		self.bufin = reqs[-1]
		return reqs[:-1]

	def send(self, obj):
		"""Send an object to this client.
		"""
		try:
			self.bufout += json.dumps(obj) + "\n\n"
		except:
			# It should never happen! And not be reported to the client!
			logging.exception("Client.send(%s)", self)

	def close(self):
		"""Shuts down and closes this client's socket.
		Will log error if called on a client with closed socket.
		Never fails.
		"""
		logging.info("Client.close(%s)", self)
		try:
			# Shutdown will fail on a closed socket...
			self.socket.shutdown(SHUT_RDWR)
			self.socket.close()
		except:
			logging.exception("Client.close(%s)", self)

		logging.info("Client Closed")


class ChatError(Exception):
	"""This exception should signal a protocol error in a client request.
	It is not a server error!
	It just means the server must report it to the sender.
	It should be dealt with inside handleRequest.
	(It should allow leaner error handling code.)
	"""
	pass


def ERROR(msg):
	"""Raise a Chat protocol error."""
	raise ChatError(msg)


class Server:
	def __init__(self, host, port):
		common_cc.refreshCertificates()
		self.userLevels = self.loadLevelFile(USER_LEVEL_FILE)
		self.serverCert = self.loadServerCertificate(SERVER_CERTIFICATE_PATH)
		self.ss = socket(AF_INET, SOCK_STREAM)  # the server socket (IP \ TCP)
		self.ss.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		self.ss.bind((host, port))
		self.ss.listen(10)
		print "[ \033[100m INFO \033[0m ]: Secure IM server listening on",  self.ss.getsockname()
		# clients to manage (indexed by socket and by name):
		self.clients = {}	   # clients (key is socket)
		self.id2client = {}   # clients (key is id)

	def stop(self):
		""" Stops the server closing all sockets
		"""
		logging.info("Stopping Server")
		try:
			self.ss.shutdown(SHUT_RDWR)
			self.ss.close()
		except:
			logging.exception("Server.stop")

		for csock in self.clients:
			try:
				self.clients[csock].close()  # Client.close!
			except:
				# this should not happen since close is protected...
				logging.exception("clients[csock].close")

		# If we delClient instead, the following would be unnecessary...
		self.clients.clear()
		self.id2client.clear()

	def loadLevelFile(self, filepath):
		lvlfile = ""
		with open(filepath, 'rb') as f:
			lvlfile = f.read()
			f.close()
		return json.loads(lvlfile)

	def loadServerCertificate(self, filename):
		cert = ""
		with open(filename, 'rb') as f:
			cert = f.read()
			f.close()

		print "[ \033[45m CERT \033[0m ]: Loaded server certificate at", SERVER_CERTIFICATE_PATH 

		return cert

	def addClient(self, csock, addr):
		"""Add a client connecting in csock."""
		if csock in self.clients:
			logging.error("Client NOT Added: %s already exists", self.clients[csock])
			return

		client = Client(csock, addr)
		self.clients[client.socket] = client
		print "[ \033[100m INFO \033[0m ]: Client added:", client

	def delClient(self, csock):
		"""Delete a client connected in csock."""
		if csock not in self.clients:
			logging.error("Client NOT deleted: %s not found", self.clients[csock])
			return

		client = self.clients[csock]
		assert client.socket == csock, "client.socket (%s) should match key (%s)" % (client.socket, csock)
		del self.id2client[client.id]
		del self.clients[client.socket]
		client.close()
		logging.info("Client deleted: %s", client)

	def accept(self):
		"""Accept a new connection.
		"""
		try:
			csock, addr = self.ss.accept()
			self.addClient(csock, addr)
		except:
			logging.exception("Could not accept client")

	def flushin(self, s):
		"""Read a chunk of data from this client.
		Enqueue any complete requests.
		Leave incomplete requests in buffer.
		This is called whenever data is available from client socket.
		"""
		client = self.clients[s]
		data = None
		try:
			data = s.recv(BUFSIZE)
			#logging.info("Received data from %s. Message:\n%r", client, data) DELETEME
		except:
			logging.exception("flushin: recv(%s)", client)
			logging.error("Received invalid data from %s. Closing", client)
			self.delClient(s)
		else:
			if len(data) > 0:
				reqs = client.parseReqs(data)
				for req in reqs:
					self.handleRequest(s, req)
			else:
				self.delClient(s)

	def flushout(self, s):
		"""Write a chunk of data to client.
		This is called whenever client socket is ready to transmit data."""
		if s not in self.clients:
			# this could happen before, because a flushin might have deleted the client
			logging.error("BUG: Flushing out socket that is not on client list! Socket=%s", str(s))
			return

		client = self.clients[s]
		try:
			sent = client.socket.send(client.bufout[:BUFSIZE])
			#logging.info("Sent %d bytes to %s. Message:\n%r", sent, client, client.bufout[:sent]) DELETEME
			client.bufout = client.bufout[sent:]  # leave remaining to be sent later
		except:
			logging.exception("flushout: send(%s)", client)
			# logging.error("Cannot write to client %s. Closing", client)
			self.delClient(client.socket)

	def loop(self):
		while True:
			# sockets to select for reading: (the server socket + every open client connection)
			rlist = [self.ss] + self.clients.keys()
			# sockets to select for writing: (those that have something in bufout)
			wlist = [ sock for sock in self.clients if len(self.clients[sock].bufout)>0 ]
			#logging.debug("select waiting for %dR %dW %dX", len(rlist), len(wlist), len(rlist)) DELETEME
			(rl, wl, xl) = select(rlist, wlist, rlist)
			#logging.debug("select: %s %s %s", rl, wl, xl) DELETEME

			# Deal with incoming data:
			for s in rl:
				if s is self.ss:
					self.accept()
				elif s in self.clients:
					self.flushin(s)
				else:
					logging.error("Incoming, but %s not in clients anymore", s)

			# Deal with outgoing data:
			for s in wl:
				if s in self.clients:
					self.flushout(s)
				else:
					logging.error("Outgoing, but %s not in clients anymore", s)

			for s in xl:
				logging.error("EXCEPTION in %s. Closing", s)
				self.delClient(s)

	def handleRequest(self, s, request):
		"""Handle a request from a client socket.
		"""
		client = self.clients[s]
		try:

			try:
				req = json.loads(request)
			except:
				return

			if not isinstance(req, dict):
				return

			if 'type' not in req:
				return

			if req['type'] == 'ack':
				return

			client.send({'type': 'ack'})

			if req['type'] == 'connect':
				self.processConnect(client, req)
			elif req['type'] == 'secure':
				self.processSecure(client, req)
			elif req['type'] == 'newkey':
				self.processNewCipherKey(client, req)

		except Exception, e:
			logging.exception("Could not handle request")

	def clientList(self):
		"""
		Return the client list
		"""
		cl = []
		for k in self.clients:
			cl.append(self.clients[k].asDict())
		print cl
		return cl

	def getBlockCipherModeFromSpec(self, spec):
		try:
			return spec.split('_')[4]
		except:
			print "Error extracting block cipher mode!"
			return "CTR"

	def getKeyExchangeFromSpec(self, spec):
		try:
			return spec.split('_')[0]
		except:
			print "Error extracting key exchange algorithm!"
			return "ECDHE"

	def processConnect(self, sender, request):
		"""
		Process a connect message from a client
		"""
		if sender.state == STATE_CONNECTED:
			if 're-exchange' in request:
				if request['re-exchange'] == False:
					logging.warning("Client is already connected: %s" % sender)
					return
			else:
				logging.warning("Client is already connected: %s" % sender)
				return
			

		if not all (k in request.keys() for k in ("name", "ciphers", "phase", "uid", "id")):
			logging.warning("Connect message with missing fields")
			return

		if sender.state == STATE_CONNECTING:
			if sender.currentPhase >= request['phase']:
				logging.warning("Incorrect phase in connect message")
			
		msg = {'type': 'connect', 'phase': request['phase'] + 1, 'id': os.urandom(8)}

		
		if msg['phase'] == 6:	# Server should now check the client-side key
			sender.currentPhase = 6

			if 'response' in request:
				if common_cert.verifySignature(sender.userCert, base64.urlsafe_b64decode(str(request['response'])), sender.challenge_given):
					print "[ \033[44mCLIENT\033[0m ]: Successfully verified the identity of \033[1m\033[32m" + base64.urlsafe_b64decode(str(request['name'])) + "\033[0m\033[0m (level: " + str(sender.level) + ")."
				else:
					print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Failed identity verification for \033[1m\033[32m" + base64.urlsafe_b64decode(str(request['name'])) + "\033[0m\033[0m."
					self.delClient(sender.socket)
					return
			else:
				logging.warning("Invalid key exchange message")
				return


			if 'data' in request:
				if not all (k in request['data'].keys() for k in ("saltB", "ciphertext", "counternonce", "hmac")):
					logging.warning("Connect message with missing fields")
					return
			else:
				logging.warning("Connect message with missing fields")
				return
			
		
			connectionSaltB = base64.urlsafe_b64decode(str(request['data']['saltB']))
			ciphertext = base64.urlsafe_b64decode(str(request['data']['ciphertext']))
			received_hmac = base64.urlsafe_b64decode(str(request['data']['hmac']))
			
			
		
			derived_key = PBKDF2HMAC(algorithm=hashes.SHA512(), length=64, salt=sender.sa_data['saltA']+connectionSaltB, iterations=100000, backend=default_backend()).derive(sender.sa_data['secret'])
			cipher_algo = algorithms.AES(derived_key[:32])
			counternonce = base64.urlsafe_b64decode(str(request['data']['counternonce']))


			bc_spec = self.getBlockCipherModeFromSpec(sender.chosenSpec)
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
				logging.warning("Verification failed, removing client.")
				self.delClient(sender)
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

			
			msg['data'] = dict()
			msg['data']['ciphertext'] = base64.urlsafe_b64encode(ciphertext)
			msg['data']['counternonce'] = base64.urlsafe_b64encode(counternonce)
			msg['data']['hmac'] = base64.urlsafe_b64encode(hmac_to_send)
			
			sender.state = STATE_CONNECTED
		
		
		if msg['phase'] == 4:		# Peer's public key and certificate should be inside
			if 'cert' in request:
				temp_cert = base64.urlsafe_b64decode(str(request['cert']))
				if common_cert.verifyUserCertificate(temp_cert, FILETYPE_ASN1):
					print "[ \033[44mCLIENT\033[0m ]: Received a valid certificate from client \033[1m\033[32m" + base64.urlsafe_b64decode(str(request['name'])) + "\033[0m\033[0m."
				else:
					print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Received an invalid certificate from client \033[1m\033[32m" + base64.urlsafe_b64decode(str(request['name'])) + "\033[0m\033[0m."
			else:
				logging.warning("Invalid key exchange message")
				return

			if 'challenge' in request:
				response_to_client = common_cert.sign_pss(PRIVATE_KEY_PATH, base64.urlsafe_b64decode(str(request['challenge'])))
				msg['response'] = base64.urlsafe_b64encode(response_to_client)
			else:
				logging.warning("Invalid key exchange message")
				return

			if 'data' in request:
				if 'pubkey' in request['data']:
					if 'ciphers' not in request:
						logging.warning("Unable to reach a cipher agreement with the client.")
						return
					elif request['ciphers'] == []:
						logging.warning("Unable to reach a cipher agreement with the client.")
						return
					elif request['ciphers'][0] not in AVAILABLE_CIPHER_SPECS:
						logging.warning("Unable to reach a cipher agreement with the client.")
						return
					else:
						chosenSpec = request['ciphers'][0]

					decoded = base64.urlsafe_b64decode(str(request['uid']))
					self.id2client[decoded] = sender
					self.generateTransportKeyPair(self.getKeyExchangeFromSpec(chosenSpec), sender)
				

					imported_key = serialization.load_pem_public_key(str(request['data']['pubkey']), backend=default_backend())

					sender.id = decoded
					sender.name = base64.urlsafe_b64decode(str(request['name']))
					sender.sa_data['secret'] = sender.sa_data['privkey_tls'].exchange(ec.ECDH(), imported_key)
					sender.sa_data['saltA'] = os.urandom(16)
					sender.state = STATE_CONNECTING
					sender.currentPhase = 4
					sender.chosenSpec = chosenSpec
					sender.challenge_given = os.urandom(16)
					sender.userCert = temp_cert

					sender.ccID = common_cc.getID(temp_cert)
					if sender.ccID[2:] in self.userLevels:
						sender.level = self.userLevels[sender.ccID[2:]]
					else:
						sender.level = 1

					print "[ \033[100m INFO \033[0m ]: Client with CC ID " + sender.ccID[2:] + " connecting"

					msg['level'] = sender.level
					msg['challenge'] = base64.urlsafe_b64encode(sender.challenge_given)
					msg['data'] = dict()
					msg['data']['pubkey'] = sender.sa_data['pubkey_tls'].public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
					msg['data']['saltA'] =  base64.urlsafe_b64encode(sender.sa_data['saltA'])
					del sender.sa_data['privkey_tls']
					del sender.sa_data['pubkey_tls']
				else:
					logging.warning("Invalid key exchange message")
					return
				
		if len(request['ciphers']) > 1 or 'NONE' not in request['ciphers']:
			if request['ciphers'] != []:
				if request['phase'] > 2 and len(request['ciphers']) > 1:
					logging.warning("Unable to reach a cipher agreement with the client.")
					return
				else:
					if request['phase'] == 1:
						compatible = []
						for spec in request['ciphers']:
							if spec in AVAILABLE_CIPHER_SPECS:
								compatible.append(spec)
						msg['ciphers'] = compatible
						msg['cert'] = base64.urlsafe_b64encode(self.serverCert)
					#logging.info("Connect continue to phase " + str(msg['phase'])) DELETEME
					msg['id'] = request['id']
					sender.send(msg)
			else:
				return
			return
			



	def generateTransportKeyPair(self, algorithm, client):
		if algorithm == 'ECDHE':
			client.sa_data['privkey_tls'] = ec.generate_private_key(ec.SECP256K1, default_backend())
			client.sa_data['pubkey_tls'] = client.sa_data['privkey_tls'].public_key()
	

	def sendSecure(self, sender, msg):
		to_print = msg['type']
		if to_print == 'newclientkey':
			to_print += str(msg['phase'])
		print "[ \033[41m\033[1m DEBUG \033[0m\033[0m ]: SENDING A SECURE TO: " + sender.id + " (" + to_print + ") - " + base64.urlsafe_b64encode(sender.sa_data['nextCipherKey'][:32]) # delete #Deleteme
		cipher_algo = algorithms.AES(sender.sa_data['nextCipherKey'][:32])
		counternonce = os.urandom(cipher_algo.block_size/8)

		bc_spec = self.getBlockCipherModeFromSpec(sender.chosenSpec)
		if bc_spec == "CTR":
			ciphermode = modes.CTR(counternonce)
		elif bc_spec == "OFB":
			ciphermode = modes.OFB(counternonce)

		countercipher = Cipher(cipher_algo, ciphermode, backend=default_backend())
		ciphertext_gen = countercipher.encryptor()

		ciphertext = ciphertext_gen.update(json.dumps(msg)) + ciphertext_gen.finalize()

		hmac_holder = hmac.HMAC(sender.sa_data['nextCipherKey'][32:64], hashes.SHA256(), backend=default_backend())
		hmac_holder.update(ciphertext)
		hmac_to_send = hmac_holder.finalize()

		secure_msg = dict()
		secure_msg['type'] = 'secure'
		secure_msg['sa_data'] = dict()
		secure_msg['sa_data']['counternonce'] = base64.urlsafe_b64encode(counternonce)
		secure_msg['sa_data']['hmac'] = base64.urlsafe_b64encode(hmac_to_send)
		secure_msg['payload'] = base64.urlsafe_b64encode(ciphertext)



		secure_msg['sa_data']['signature'] = base64.urlsafe_b64encode(
												common_cert.sign_pss(
															PRIVATE_KEY_PATH, json.dumps(secure_msg),
														)
												)	
												
		if msg['type'] != 'ack':
			message_digest = SHA256.new()
			message_digest.update(json.dumps(secure_msg))
			encoded_digest = base64.urlsafe_b64encode(message_digest.digest())
			sender.waitingForClientACK[encoded_digest] = dict()
			sender.waitingForClientACK[encoded_digest]['time'] = time.time() 
			sender.waitingForClientACK[encoded_digest]['content'] = json.dumps(secure_msg)
			if DEBUG:
				print "[ \033[41m\033[1m DEBUG \033[0m\033[0m ]: Expecting ACK with", json.dumps(secure_msg)

		sender.send(secure_msg)
		
		
	def processList(self, sender, request):
		"""
		Process a list message from a client
		"""
		if sender.state != STATE_CONNECTED:
			logging.warning("LIST from disconnected client: %s" % sender)
			return

		parsed_client_list = []
		for client in self.clientList():
			if client['level'] >= sender.level:
				parsed_client_list.append(client)

		payload = {'type': 'list', 'data': json.dumps(parsed_client_list)}
		
		self.sendSecure(sender, payload)

		self.userLevels = self.loadLevelFile(USER_LEVEL_FILE)


	def processNewCipherKey(self, sender, request):
		if sender.state != STATE_CONNECTED:
			logging.warning("Client is not connected: %s" % sender)
			return
			

		if not all (k in request.keys() for k in ("data", "id")):
			logging.warning("New key negotiation message with missing fields")
			return

		if sender.negotiationPhase > (request['phase'] + 1):
			logging.warning("Incorrect phase in negotiation message. STORED PHASE: %d REQUEST PHASE: %d" % (sender.negotiationPhase, request['phase'] + 1) )
			return
		msg = {'type': 'newkey', 'phase': request['phase'] + 1, 'id' : base64.urlsafe_b64encode(os.urandom(8))}
	
		if msg['phase'] == 2:
			sender.negotiationPhase = 2
			sender.sa_data['keyIsValidated'] = False

			if 'nextCipherKey' in sender.sa_data:
				sender.sa_data['oldKey'] = sender.sa_data['nextCipherKey']
			else:
				sender.sa_data['oldKey'] = None

			saltA = os.urandom(16)
			saltB = base64.urlsafe_b64decode(str(request['data']['saltB']))

			derived_key = PBKDF2HMAC(algorithm=hashes.SHA512(), length=64, salt=saltA+saltB, iterations=100000, backend=default_backend()).derive(sender.sa_data['secret'])
		
			plaintext = "Negotiation OK"+os.urandom(16)
		
			cipher_algo = algorithms.AES(derived_key[:32])
			counternonce = os.urandom(cipher_algo.block_size/8)


			bc_spec = self.getBlockCipherModeFromSpec(sender.chosenSpec)
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

			sender.sa_data['nextCipherKey'] = derived_key

			msg['data'] = dict()

			msg['data']['saltA'] = base64.urlsafe_b64encode(saltA)
			msg['data']['ciphertext'] = base64.urlsafe_b64encode(ciphertext)
			msg['data']['counternonce'] = base64.urlsafe_b64encode(counternonce)
			msg['data']['hmac'] = base64.urlsafe_b64encode(hmac_to_send)

		if msg['phase'] == 4:
			sender.negotiationPhase = 4
			ciphertext = base64.urlsafe_b64decode(str(request['data']['ciphertext']))
			received_hmac = base64.urlsafe_b64decode(str(request['data']['hmac']))

			cipher_algo = algorithms.AES(sender.sa_data['nextCipherKey'][:32])
			counternonce = base64.urlsafe_b64decode(str(request['data']['counternonce']))

			bc_spec = self.getBlockCipherModeFromSpec(sender.chosenSpec)
			if bc_spec == "CTR":
				ciphermode = modes.CTR(counternonce)
			elif bc_spec == "OFB":
				ciphermode = modes.OFB(counternonce)


			countercipher = Cipher(cipher_algo, ciphermode, backend=default_backend())
			plaintext_gen = countercipher.decryptor()
			plaintext = plaintext_gen.update(ciphertext) + plaintext_gen.finalize()

			hmac_holder = hmac.HMAC(sender.sa_data['nextCipherKey'][32:64], hashes.SHA256(), backend=default_backend())
			hmac_holder.update(ciphertext)

			try:
				hmac_holder.verify(received_hmac)
				sender.sa_data['keyIsValidated'] = True
				del sender.sa_data['oldKey']
				sender.negotiationPhase = 0
				#print "delete: NEW KEY ESTABLISHED!! %s" %  sender.sa_data['nextCipherKey']
				return
			except:
				print "Client-side verification failed."
				return			

		sender.send(msg)

	def checkClientAck(self, sender, msg):
		if 'message_digest' not in msg or 'signature' not in msg:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Client ACK with missing parameters."
			return

		if str(msg['message_digest']) not in sender.waitingForClientACK:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Got an unexpected ACK from client.", str(msg['message_digest'])
			return

		signature = base64.urlsafe_b64decode(str(msg['signature']))
		digest = base64.urlsafe_b64decode(str(msg['message_digest']))

		if common_cert.verifySignature(sender.userCert, signature, digest):
			if DEBUG or True: #DELETEME
				print "[ \033[43m\033[1m DEBUG \033[0m\033[0m ]: ACK from client OK."
		else:
			print "[ \033[41m\033[1m ERROR \033[0m\033[0m ]: Failed to verify client ACK."

		del sender.waitingForClientACK[str(msg['message_digest'])]

	def processSecure(self, sender, request):
		"""
		Process a secure message from a client
		"""
		if sender.state != STATE_CONNECTED:
			logging.warning("SECURE from disconnected client: %s" % sender)
			return

		if 'payload' not in request or 'sa_data' not in request or 'signature' not in request['sa_data']:
			logging.warning("Secure message with missing fields")
			return


		if 'oldKey' in sender.sa_data and sender.sa_data['oldKey'] is not None:
			key_to_use = sender.sa_data['oldKey']
		else:
			key_to_use = sender.sa_data['nextCipherKey']

		print "[ \033[41m\033[1m DEBUG \033[0m\033[0m ]: GOT A SECURE FROM " + sender.id + " - " + base64.urlsafe_b64encode(key_to_use[:32]) # delete

		signature = base64.urlsafe_b64decode(str(request['sa_data']['signature']))
		request_to_ack = copy.deepcopy(request)
		del request['sa_data']['signature']
		temp_sa_data = request['sa_data']
		ack_sa_data = request_to_ack['sa_data']
		request['sa_data'] = dict()
		request_to_ack['sa_data'] = dict()

		for k in sorted(temp_sa_data.keys()):
				request['sa_data'][k] = temp_sa_data[k]

		for k in sorted(ack_sa_data.keys()): # Re-order keys to match message sent by client
				request_to_ack['sa_data'][k] = ack_sa_data[k]

		if common_cert.verifySignature(sender.userCert, signature, json.dumps(request)):
			print "[ \033[43m\033[1m DEBUG \033[0m\033[0m ]: Secure message successfully verified!"
		else:
			print "[ \033[45m\033[1m SRS ERROR \033[0m\033[0m ]: Bad identity signature!"
			return

		hmac_target = base64.urlsafe_b64decode(str(request['sa_data']['hmac']))
		ciphertext = base64.urlsafe_b64decode(str(request['payload']))
		counternonce = base64.urlsafe_b64decode(str(request['sa_data']['counternonce']))

		bc_spec = self.getBlockCipherModeFromSpec(sender.chosenSpec)
		if bc_spec == "CTR":
			ciphermode = modes.CTR(counternonce)
		elif bc_spec == "OFB":
			ciphermode = modes.OFB(counternonce)


		cipher_algo = algorithms.AES(key_to_use[:32])

		countercipher = Cipher(cipher_algo, ciphermode, backend=default_backend())
		plaintext_gen = countercipher.decryptor()
	
		plaintext = plaintext_gen.update(ciphertext) + plaintext_gen.finalize()
	
		hmac_holder = hmac.HMAC(key_to_use[32:64], hashes.SHA256(), backend=default_backend())
		hmac_holder.update(ciphertext)

		try:
			hmac_holder.verify(hmac_target)
		except InvalidSignature:
			print "[ \033[45m\033[1m SRS ERROR \033[0m\033[0m ]: >    SERVER SIGNATURE VERIFICATION FAILED    <" +  base64.urlsafe_b64encode(key_to_use[:32]) #delete
			return	
	
		

		del request['payload']
		request['payload'] = json.loads(plaintext)

		global IGNORE_LIST_COUNT
		if IGNORE_LIST_COUNT and request['payload']['type'] == 'list':
			IGNORE_LIST_COUNT = False
			return

		# This is a secure message.
		# TODO: Inner message is encrypted for us. Must decrypt and validate.

		if not 'type' in request['payload'].keys():
			logging.warning("Secure message without inner frame type")
			return


		if request['payload']['type'] != 'ack':
			ack_message_digest = SHA256.new()
			ack_message_digest.update(json.dumps(request_to_ack))
			ack_message_digest = ack_message_digest.digest()
			ack_signature = common_cert.sign_pss(PRIVATE_KEY_PATH, ack_message_digest)


			if DEBUG:
				print "[ \033[41m\033[1m DEBUG \033[0m\033[0m ]: Sending ACK for", json.dumps(request_to_ack)

			self.sendSecure(sender, {'type' : 'ack', 'message_digest' : base64.urlsafe_b64encode(ack_message_digest), 'signature' : base64.urlsafe_b64encode(ack_signature)})




		to_print = request['payload']['type']
		if to_print == 'newclientkey':
			to_print += str(request['payload']['phase'])
		print "[ \033[41m\033[1m DEBUG \033[0m\033[0m ]: IT'S A : " + to_print

		if request['payload']['type'] == 'ack':
			self.checkClientAck(sender, request['payload'])
			return

		if request['payload']['type'] == 'list':
			self.processList(sender, request['payload'])
			sender.send({'type' : 'newkey', 'phase' : 0});
			return

		if request['payload']['type'] == 'client-ack':
			self.sendSecure(self.id2client[request['payload']['dst']], request['payload'])
			return

		if not all (k in request['payload'].keys() for k in ("src", "dst")):
			return

		if request['payload']['src'] != sender.id:
			return

		if not request['payload']['dst'] in self.id2client.keys():
			logging.warning("Message to unknown client: %s" % request['payload']['dst'])
			return

		dst = self.id2client[request['payload']['dst']]



		if request['payload']['type'] == 'client-com' and int(sender.level) > int(dst.level):
			print "[ \033[44mCLIENT\033[0m ]: Blocked message from \033[1m\033[32m" + sender.name + "\033[0m\033[0m to \033[1m\033[32m" + dst.name + "\033[0m\033[0m."
			return



		sender.send({'type' : 'newkey', 'phase' : 0});
		self.sendSecure(dst, request['payload'])
		dst.send({'type' : 'newkey', 'phase' : 0});

if __name__ == "__main__":
	if len(sys.argv) > 1:
		PORT = int(sys.argv[1])

	logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, formatter=logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

	serv = None
	while True:
		try:
			serv = Server(HOST, PORT)
			serv.loop()
		except KeyboardInterrupt:
			serv.stop()
			try:
				logging.info("Press CTRL-C again within 2 sec to quit")
				time.sleep(2)
			except KeyboardInterrupt:
				logging.info("CTRL-C pressed twice: Quitting!")
				break
		except:
			logging.exception("Server ERROR")
			if serv is not (None):
				serv.stop()
			time.sleep(1)
