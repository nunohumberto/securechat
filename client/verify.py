#!/usr/bin/env python
# encoding: utf-8

import os
import sys
import common_cert
import base64
import json

def chooseLog():
	certs = []
	logs = []
	for file in os.listdir("."):
	    if file.endswith(".crt"):
	        certs.append(file[:-4])
	for file in os.listdir("."):
		if file in certs:
			logs.append(file)
	if logs == []:
		return None
	print "Choose a chat log:\n"
	counter = 1
	for log in logs:
		print str(counter) + " - " + log
		try:
			with open(log, 'rb') as f:
				header = json.loads(f.read().split("\n\n")[0])
				f.close()
		except:
			print "Invalid log."
			continue
		print "\t\tName: \033[1m\033[32m" + base64.urlsafe_b64decode(str(header['name'])) + "\033[0m\033[0m"
		print "\t\tHWID: \033[36m" + header['hwid'] + "\033[0m\n"
		counter += 1
	chosen = raw_input("\nPick a log: ")

	try:
		chosen = int(chosen)
	except:
		print "Invalid log."
		return

	if chosen > len(logs) or chosen < 1:
		print "Invalid log."
		return
	else:
		return logs[chosen-1]

if __name__ == '__main__':
	log = chooseLog()
	if log == None:
		sys.exit()
	messages = []
	with open(log, 'rb') as f:
		messages = f.read().split("\n\n")
		f.close()

	if len(messages) == 0:
		print "No messages to display."
		sys.exit()

	cert = ""
	with open(log + ".crt", 'rb') as f:
		cert = f.read()
		f.close()

	chain_last_signature = None
	first = True
	one_fail = False
	if len(messages) < 3:
		print "No messages to show."
		sys.exit()
	for message in messages:
		if first:
			first = False
			continue
		fail = False
		if len(message) == 0:
			continue
		try:
			loaded = json.loads(message)
		except:
			print "Invalid log file."
			sys.exit()
		try:
			signature = base64.urlsafe_b64decode(str(loaded['signature']))
		except:
			continue
		if chain_last_signature != None:
			if 'lastsignature' not in message:
				fail = True
			else:
				lastsignature_decoded = base64.urlsafe_b64decode(str(loaded['lastsignature']))
				if chain_last_signature != lastsignature_decoded:
					fail = True
		del loaded['signature']
		re_dumped = json.dumps(loaded)
		chain_last_signature = signature
		if not common_cert.verifySignature(cert, signature, re_dumped):
			fail = True

		sys.stdout.write(str(loaded['messageno']) + " - " + base64.urlsafe_b64decode(str(loaded['msg'])) + " - ")
		if fail:
			print "\033[31m\033[1mFAIL\033[0m\033[0m"
			one_fail = True
		else:
			print "\033[32m\033[1mOK\033[0m\033[0m"

	if one_fail:
		print "\nMessage chain validation \033[31m\033[1mfailed\033[0m\033[0m."
	else:
		print "\nMessage chain validation \033[32m\033[1msucceeded\033[0m\033[0m."
