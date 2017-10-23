#!/usr/bin/env python
from pyasn1_modules import pem, rfc2459
from pyasn1.codec.der import decoder as der_decoder
from select import select
import PyKCS11
import urllib2
import platform
import sys
import os
import base64
import time

def getGivenName(session): # "nome proprio"
	obj = session.findObjects()[1]
	all_attributes = [cka_attribute for cka_attribute in PyKCS11.CKA.keys() if isinstance(cka_attribute, int)]
	attributes = session.getAttributeValue(obj, all_attributes, allAsBinary=True)
	for q, a in zip(all_attributes, attributes):
		if PyKCS11.CKA[q] == "CKA_VALUE":
			certif = ''.join(chr(i) for i in a)
			cert = der_decoder.decode(certif, asn1Spec=rfc2459.Certificate())[0]
			subj = cert.getComponentByName('tbsCertificate').getComponentByName('subject')[0]
			commonname_val = [attr[0].getComponentByName('value') for attr in subj if attr[0].getComponentByName('type') == rfc2459.id_at_givenName][0]
			commonname_val = der_decoder.decode(commonname_val, asn1Spec=rfc2459.DirectoryString())[0]
			commname = str(commonname_val.getComponent())
			try:
				unicode(commname, "ascii")
			except UnicodeError:
				commname = unicode(commname, "utf-8")
			else:
				pass
			return commname	

def refreshCertificates(): # Asks if the user wants to refresh the certificate and CRL cache
	proceed = raw_input("[ \033[100m INFO \033[0m ]: Refresh certificate data? ")
	if proceed.upper() != 'Y' and proceed.upper() != 'S':
		return
	counter = 1
	while 1:
		counterstring = str(counter)
		if counter < 10:
			counterstring = '0' + counterstring
		if counter < 100:
			counterstring = '0' + counterstring

		dl_url = 'https://pki.cartaodecidadao.pt/publico/certificado/cc_ec_cidadao/Cartao%20de%20Cidadao%20' + counterstring + '.cer'

		try:
			res = urllib2.urlopen(dl_url)
		except:
			break


		sys.stderr.write("\033[2K\r[ \033[100m INFO \033[0m ]: Downloading...    " + 'eccidadao' + counterstring + '.cer')
		with open('./certs/eccidadao' + counterstring + '.cer', 'wb') as f:
			f.write(res.read())
			f.close()

		subcounter = 1
		while 1:
			subcounterstring = str(subcounter)
			if subcounter < 10:
				subcounterstring = '0' + subcounterstring
			if subcounter < 100:
				subcounterstring = '0' + subcounterstring

			dl_url = 'https://pki.cartaodecidadao.pt/publico/lrc/cc_ec_cidadao_crl' + subcounterstring + '_crl.crl'

			try:
				res = urllib2.urlopen(dl_url)
			except:
				break

			sys.stderr.write("\033[2K\r[ \033[100m INFO \033[0m ]: Downloading...    " + 'eccidadao' + subcounterstring + '.crl')
			with open('./certs/eccidadao' + subcounterstring + '.crl', 'wb') as f:
				f.write(res.read())
				f.close()
			subcounter+=1

		counter+=1


	counter = 1
	while 1:
		counterstring = str(counter)
		if counter < 10:
			counterstring = '0' + counterstring
		if counter < 100:
			counterstring = '0' + counterstring
		if counter < 1000:
			counterstring = '0' + counterstring

		dl_url = 'https://pki.cartaodecidadao.pt/publico/certificado/cc_ec_cidadao_autenticacao/EC%20de%20Autenticacao%20do%20Cartao%20de%20Cidadao%20' + counterstring + '.cer'

		try:
			res = urllib2.urlopen(dl_url)
		except:
			break

		sys.stderr.write("\033[2K\r[ \033[100m INFO \033[0m ]: Downloading...    " + 'ecauth' + counterstring + '.cer')
		with open('./certs/ecauth' + counterstring + '.cer', 'wb') as f:
			f.write(res.read())
			f.close()

		subcounter = 1
		while 1:
			subcounterstring = str(subcounter)
			if subcounter < 10:
				subcounterstring = '0' + subcounterstring
			if subcounter < 100:
				subcounterstring = '0' + subcounterstring
			if subcounter < 1000:
				subcounterstring = '0' + subcounterstring

			if counterstring == '0001' or counterstring == '0002':
				dl_url = 'https://pki.cartaodecidadao.pt/publico/lrc/cc_sub-ec_cidadao_autenticacao_crl' + counterstring + '.crl'
			else:
				dl_url = 'https://pki.cartaodecidadao.pt/publico/lrc/cc_sub-ec_cidadao_autenticacao_crl' + counterstring + '_p' + subcounterstring + '.crl'

			try:
				res = urllib2.urlopen(dl_url)
			except:
				break

			sys.stderr.write("\033[2K\r[ \033[100m INFO \033[0m ]: Downloading...    " + 'ecauth' + counterstring + '_' + subcounterstring + '.crl')
			with open('./certs/ecauth' + counterstring + '_' + subcounterstring + '.crl', 'wb') as f:
				f.write(res.read())
				f.close()

			if counterstring == '0001' or counterstring == '0002':
				dl_url = 'https://pki.cartaodecidadao.pt/publico/lrc/cc_sub-ec_cidadao_autenticacao_crl' + counterstring + '_delta.crl'
			else:
				dl_url = 'https://pki.cartaodecidadao.pt/publico/lrc/cc_sub-ec_cidadao_autenticacao_crl' + counterstring + '_delta_p' + subcounterstring + '.crl'

			try:
				res = urllib2.urlopen(dl_url)
			except:
				break

			sys.stderr.write("\033[2K\r[ \033[100m INFO \033[0m ]: Downloading...    " + 'ecauth' + counterstring + '_' + subcounterstring + '_delta.crl')
			with open('./certs/ecauth' + counterstring + '_' + subcounterstring + '_delta.crl', 'wb') as f:
				f.write(res.read())
				f.close()

			if counterstring == '0001' or counterstring == '0002':
				break

			subcounter+=1
		counter+=1
	sys.stderr.write("\033[2K\r[ \033[100m INFO \033[0m ]: Successfully updated certificates and CRLs.\n")

def getFullName(session):
	obj = session.findObjects()[1]
	all_attributes = [cka_attribute for cka_attribute in PyKCS11.CKA.keys() if isinstance(cka_attribute, int)]
	attributes = session.getAttributeValue(obj, all_attributes, allAsBinary=True)
	for q, a in zip(all_attributes, attributes):
		if PyKCS11.CKA[q] == "CKA_VALUE":
			certif = ''.join(chr(i) for i in a)
			cert = der_decoder.decode(certif, asn1Spec=rfc2459.Certificate())[0]
			subj = cert.getComponentByName('tbsCertificate').getComponentByName('subject')[0]
			commonname_val = [attr[0].getComponentByName('value') for attr in subj if attr[0].getComponentByName('type') == rfc2459.id_at_commonName][0]
			commonname_val = der_decoder.decode(commonname_val, asn1Spec=rfc2459.DirectoryString())[0]
			commname = str(commonname_val.getComponent())
			try:
				unicode(commname, "ascii")
			except UnicodeError:
				commname = unicode(commname, "utf-8")
			else:
				pass
			return commname	

def getID(cert_str): # returns id number, 'BI' prefix is included!
		cert = der_decoder.decode(cert_str, asn1Spec=rfc2459.Certificate())[0]
		subj = cert.getComponentByName('tbsCertificate').getComponentByName('subject')[0]
		serialno = [attr[0].getComponentByName('value') for attr in subj if attr[0].getComponentByName('type') == (2,5,4,5)][0]
		serialno = der_decoder.decode(serialno, asn1Spec=rfc2459.DirectoryString())[0]
		return str(serialno.getComponent())

def getLeafCertificate(session): # returns user certificate
	obj = session.findObjects()[1]
	all_attributes = [cka_attribute for cka_attribute in PyKCS11.CKA.keys() if isinstance(cka_attribute, int)]
	attributes = session.getAttributeValue(obj, all_attributes, allAsBinary=True)
	for q, a in zip(all_attributes, attributes):
		if PyKCS11.CKA[q] == "CKA_VALUE":
			certif = ''.join(chr(i) for i in a)
			return certif
		