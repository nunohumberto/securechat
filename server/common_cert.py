#!/usr/bin/env python
from select import select
import PyKCS11
import urllib2
import platform
import sys
import os
import base64
import time
import OpenSSL
from Crypto.Signature import PKCS1_PSS, PKCS1_v1_5
from Crypto.Hash import SHA, SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
from OpenSSL.crypto import load_certificate, load_crl, PKey, FILETYPE_ASN1, FILETYPE_PEM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from OpenSSL.crypto import X509Store, X509StoreContext, X509StoreContextError

def readCertFromFile(filename, cert_format):
	cert = ""
	with open(filename, 'rb') as f:
		cert = f.read()
		f.close()
	return load_certificate(cert_format, cert)
		
def readCRLFromFile(filename):
	crl = ""
	with open(filename, 'rb') as f:
		crl = f.read()
		f.close()
	return load_crl(FILETYPE_ASN1, crl)


def verifyUserCertificate(cert, cert_format):
	cert_to_verify = load_certificate(cert_format, cert)

	auth_number = ""
	for c in cert_to_verify.get_issuer().get_components():
		if c[0] == 'CN':
			auth_number = c[1][-4:]
			break

	ec_auth = readCertFromFile('certs/ecauth' + auth_number + '.cer', FILETYPE_ASN1)

	auth_crls_to_add = []

	auth_counter = 1
	while True:
		try:
			auth_crls_to_add.append(readCRLFromFile('certs/ecauth' + auth_number + '_' + "%04d" % auth_counter + '.crl'))
			auth_crls_to_add.append(readCRLFromFile('certs/ecauth' + auth_number + '_' + "%04d" % auth_counter + '_delta.crl'))
		except:
			break
		auth_counter += 1

	ec_cc_number = ""
	for c in ec_auth.get_issuer().get_components():
		if c[0] == 'CN':
			ec_cc_number = c[1][-3:]
			break

	ec_cc = readCertFromFile('certs/eccidadao' + ec_cc_number + '.cer', FILETYPE_ASN1)
	ec_cc_crl = readCRLFromFile('certs/eccidadao' + ec_cc_number + '.crl')

	raiz_estado = readCertFromFile('certs/ECRaizEstado.crt', FILETYPE_PEM)
	root = readCertFromFile('certs/BaltimoreCyberTrustRoot.der', FILETYPE_ASN1)




	cert_store = X509Store()
	cert_store.add_cert(root)
	cert_store.add_cert(raiz_estado)
	cert_store.add_cert(ec_cc)
	cert_store.add_crl(ec_cc_crl)
	cert_store.set_flags(OpenSSL.crypto.X509StoreFlags.CRL_CHECK | OpenSSL.crypto.X509StoreFlags.IGNORE_CRITICAL)
	context = X509StoreContext(cert_store, ec_auth)

	try:
		context.verify_certificate()
	except:
		return False

	cert_store.add_cert(ec_auth)

	for crl in auth_crls_to_add:
		cert_store.add_crl(crl)

	context = X509StoreContext(cert_store, cert_to_verify)

	try:
		context.verify_certificate()
	except:
		return False

	return True
	
def verifyServerCertificate(cert):
	cert_to_verify = load_certificate(FILETYPE_PEM, cert)


	serverCA = readCertFromFile('certs/serverCA.crt', FILETYPE_PEM)


	cert_store = X509Store()
	cert_store.add_cert(serverCA)
	context = X509StoreContext(cert_store, cert_to_verify)

	try:
		context.verify_certificate()
	except:
		return False

	return True

def verifySignature(cert_str, signature, data):
	cert = load_certificate(FILETYPE_ASN1, cert_str)
	pub_key = OpenSSL.crypto.dump_publickey(FILETYPE_PEM, cert.get_pubkey())
	pub_key = RSA.importKey(pub_key)
	data_hash = SHA.new()
	data_hash.update(data)
	signature_verifier = PKCS1_v1_5.new(pub_key)
	if signature_verifier.verify(data_hash, signature):
		return True
	else:
		return False

def verifySignature_pss(cert_str, signature, data):
	cert = load_certificate(FILETYPE_PEM, cert_str)
	pub_key = OpenSSL.crypto.dump_publickey(FILETYPE_PEM, cert.get_pubkey())
	pub_key = RSA.importKey(pub_key)
	data_hash = SHA.new()
	data_hash.update(data)
	signature_verifier = PKCS1_PSS.new(pub_key)
	if signature_verifier.verify(data_hash, signature):
		return True
	else:
		return False

def sign_pss(key_filename, data):
	priv_key = RSA.importKey(open(key_filename).read())
	data_hash = SHA.new()
	data_hash.update(data)
	data_signer = PKCS1_PSS.new(priv_key)
	return data_signer.sign(data_hash)

