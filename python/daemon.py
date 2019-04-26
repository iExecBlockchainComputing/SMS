#!/usr/bin/python3

import argparse
import json
import hashlib
import uuid
import base64

import requests
import subprocess
import docker
import re
import os
import random
import string

import web3
from web3                 import Web3, HTTPProvider
from web3.contract        import Contract
from eth_account.messages import defunct_hash_message
from flask                import Flask, jsonify, make_response, request
from flask_restful        import Api, Resource, reqparse
from flask_sqlalchemy     import SQLAlchemy
from Crypto.PublicKey     import RSA
from string import Template

MAXSIZE = 4096
SALT = "iexec_sms_secret:"

# TODO: put in config
confTemplatePath            = "./palaemonConfTemplate.txt"
casAddress                  = "127.0.0.1:8081"
iexec_enclave_fspf_tag      = "1d7b6434975be521a07ae686f8145d59"
iexec_enclave_fspf_key      = "d0e0f60f67ceb28c0010c5b2effbf5865ec538e8d9f9e95bac1ea30bf44dc50b"

# +---------------------------------------------------------------------------+
# |                           ENVIRONMENT VARIABLES                           |
# +---------------------------------------------------------------------------+
app = Flask("SMS prototype - v1")
app.config['SQLALCHEMY_DATABASE_URI'       ] = "sqlite:///:memory:" # overwritten by config.database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
api = Api(app)
db  = SQLAlchemy(app)

# +---------------------------------------------------------------------------+
# |                                 DB MODELS                                 |
# +---------------------------------------------------------------------------+

### DB STORE: generic secret format for accounts and contracts
class Secret(db.Model):
	address = db.Column(db.String(42),    primary_key=True)
	secret  = db.Column(db.UnicodeText(), unique=False, nullable=True) # MAXSIZE

	def __repr__(self):
		return self.secret

### DB STORE: ethereum keypair for enclave attestation
class KeyPair(db.Model):
	address = db.Column(db.String(42), primary_key=True)
	private = db.Column(db.String(66), unique=True,  nullable=False)
	dealid  = db.Column(db.String(66), unique=False, nullable=False)

	def __repr__(self):
		return self.private

# +---------------------------------------------------------------------------+
# |                               APP ENDPOINTS                               |
# +---------------------------------------------------------------------------+

class RevertError(Exception):
	pass

def jsonifySuccess(data): return jsonify({ 'ok': True,  'errorMessage': "",  'data': data })
def jsonifyFailure(msg):  return jsonify({ 'ok': False, 'errorMessage': msg, 'data': {}   })

# +---------------------------------------------------------------------------+
# |                               APP ENDPOINTS                               |
# +---------------------------------------------------------------------------+
@app.route('/', methods=['GET'])
def index():
	return "This is a test SMS service"

@app.errorhandler(404)
def not_found(error):
	return make_response(jsonify({'error': 'Not found'}), 404)

### APP ENDPOINT: secret storing & hash retreival
# Secrets are strings: it is recommand to base64encode the actual object before storing it.
class SecretAPI(Resource):
	def __init__(self):
		super(SecretAPI, self).__init__()
		self.reqparse = reqparse.RequestParser()
		self.reqparse.add_argument('secret', type=str, location='json', required=True)
		self.reqparse.add_argument('sign',   type=str, location='json', required=True)

	def get(self, address):
		entry = Secret.query.filter_by(address=address).first()
		if entry:
			return jsonifySuccess({
				'address': address,
				'hash':    hashlib.sha256(entry.secret.encode()).hexdigest()
			})
		else:
			return jsonifyFailure("No secret found")

	def post(self, address):
		print (request.is_json) # TODO: cleanup prints
		print (request.get_json()) # TODO: cleanup prints
		args = self.reqparse.parse_args()
		if len(args.secret) > MAXSIZE:
			return jsonifyFailure('secret is to large.')
		elif blockchaininterface.checkIdentity(address, defunct_hash_message(text=SALT+args.secret), args.sign):
  		if config.test: # TODO: cleanup prints
				print("New secret pushed:") # TODO: cleanup prints
				print(args.secret) # TODO: cleanup prints
			db.session.merge(Secret(address=address, secret=args.secret))
			db.session.commit()
			return jsonifySuccess({
				'address': address,
				'hash':    hashlib.sha256(args.secret.encode()).hexdigest(),
			})
		else:
			return jsonifyFailure("invalid signature")

### APP ENDPOINT: enclave attestation provisionning
class GenerateAPI(Resource):
	def __init__(self):
		super(GenerateAPI, self).__init__()

	def get(self, dealid):
		print("generate") # TODO: cleanup prints
		print(dealid) # TODO: cleanup prints
		Ke = KeyPair.query.filter_by(dealid=dealid).first()
		if Ke is not None:
			return jsonifySuccess({ 'address': Ke.address, 'dealid': dealid })

		account = blockchaininterface.w3.eth.account.create()
		db.session.merge(KeyPair(                                             \
			address=account.address,                                          \
			private=blockchaininterface.w3.toHex(account.privateKey),         \
			dealid=dealid                                                     \
		))
		db.session.commit()
		return jsonifySuccess({ 'address': account.address, 'dealid': dealid })

### APP ENDPOINT: enclave attestation verification
class VerifyAPI(Resource):
	def __init__(self):
		super(VerifyAPI, self).__init__()

	def get(self, address):
		entry = KeyPair.query.filter_by(address=address).first()
		if entry:
			return jsonifySuccess({ 'address': address, 'dealid': entry.dealid })
		else:
			return jsonifyFailure({})

### APP ENDPOINT: secret retreival by enclave
class SecureAPI(Resource):
	def __init__(self):
		super(SecureAPI, self).__init__()
		# TODO: RequestParser for auth

	def post(self):
		try:
			return jsonifySuccess(blockchaininterface.validateAndGetKeys(request.json['auth']))
		except RevertError as e:
			return jsonifyFailure(str(e))
		except web3.exceptions.BadFunctionCallOutput:
			return jsonifyFailure("blockchain error (BadFunctionCallOutput)")

### APP ENDPOINT: Palaemon conf file generation
class SessionAPI(Resource):
	def __init__(self):
		super(SessionAPI, self).__init__()

	def post(self):
		try:
			print (request.get_json()) # TODO: cleanup prints
			return jsonifySuccess(blockchaininterface.setPalaemonConf(request.json['auth']))
		except RevertError as e:
			return jsonifyFailure(str(e))


# +---------------------------------------------------------------------------+
# |                           BLOCKCHAIN INTERFACE                            |
# +---------------------------------------------------------------------------+
class BlockchainInterface(object):
	def __init__(self, config):
		super(BlockchainInterface, self).__init__()
		self.w3 = Web3(HTTPProvider(config.gateway))
		self.ABIs = {                                                                    \
			'Ownable':    json.load(open(f'{config.contracts}/Ownable.json'   ))['abi'], \
			'App':        json.load(open(f'{config.contracts}/App.json'       ))['abi'], \
			'IexecClerk': json.load(open(f'{config.contracts}/IexecClerk.json'))['abi'], \
			'IexecHub':   json.load(open(f'{config.contracts}/IexecHub.json'  ))['abi'], \
			'IERC1271':   json.load(open(f'{config.contracts}/IERC1271.json'  ))['abi'], \
		}
		self.IexecHub = self.getContract(
			address=config.hub,
			abiname='IexecHub'
		)
		self.IexecClerk = self.getContract(
			address=self.IexecHub.functions.iexecclerk().call(),
			abiname='IexecClerk'
		)
		self.test       = config.test


	def getContract(self, address, abiname):
		return self.w3.eth.contract(                                          \
			address=address,                                                  \
			abi=self.ABIs[abiname],                                           \
			ContractFactoryClass=Contract,                                    \
		)

	def verifySignature(self, identity, hash, signature):
		try:
			if identity.lower() == self.w3.eth.account.recoverHash(message_hash=hash, signature=signature).lower():
				return True
			elif self.getContract(address=identity, abiname='IERC1271').functions.isValidSignature(hash, signature).call():
				return True
			else:
				return False
		except:
			return False

	def checkIdentity(self, identity, hash, signature):
		try:
			if self.verifySignature(identity, hash, signature):
				return True
			elif self.verifySignature(self.getContract(address=identity, abiname='Ownable').functions.owner().call(), hash, signature):
				return True
			else:
				return False
		except:
			return False

	def validateAndGetKeys(self, auth):
		# Get task details

		taskid = auth['taskid']
		task = self.IexecHub.functions.viewTaskABILegacy(taskid).call()
		# task = self.IexecHub.functions.viewTask(taskid).call()
		# print(task)

		# CHECK 1: Task must be Active
		if not task[0] == 1:
			raise RevertError("Task is not active")

		# Get deal details
		dealid = task[1]

		# deal = self.IexecClerk.functions.viewDeal(dealid).call()
		# print(deal)
		deal = self.IexecClerk.functions.viewDealABILegacy_pt1(dealid).call() \
		     + self.IexecClerk.functions.viewDealABILegacy_pt2(dealid).call()

		app         = deal[0]
		dataset     = deal[3]
		scheduler   = deal[7]
		tag         = deal[10]
		beneficiary = deal[12]
		params      = deal[14]

		# CHECK 2: Authorisation to contribute must be authentic
		# web3 v4.8.2 → soliditySha3
		# web3 v5.0.0 → solidityKeccak
		hash = defunct_hash_message(self.w3.soliditySha3([                    \
			'address',                                                        \
			'bytes32',                                                        \
			'address'                                                         \
		], [                                                                  \
			self.w3.toChecksumAddress(auth['worker']),                        \
			auth['taskid'],                                                   \
			self.w3.toChecksumAddress(auth['enclave'])                        \
		]))

		if not self.verifySignature(scheduler, hash, auth['sign']):
			raise RevertError("Invalid scheduler signature")

		if not self.verifySignature(auth['worker'], hash, auth['workersign']):
			raise RevertError("Invalid worker signature")

		# CHECK 3: MREnclave verification (only if part of the deal)
		if tag[31] & 0x01:
			# Get enclave secret
			ExpectedMREnclave = self.getContract(address=app, abiname='App').functions.m_appMREnclave().call()
			# print(f'MREnclave: {MREnclave}')
			raise RevertError('MREnclave verification not implemented')

		secrets = {}
		if dataset != "0x0000000000000000000000000000000000000000":
			Kd = Secret.query.filter_by(address=dataset).first()
			secrets['dataset'] = { 'address': dataset, 'secret': str(Kd) if Kd else None }

		if beneficiary != "0x0000000000000000000000000000000000000000":
			Kb = Secret.query.filter_by(address=beneficiary).first()
			secrets['beneficiary'] = { 'address': beneficiary, 'secret': str(Kb) if Kb else None }

		if auth['enclave'] != "0x0000000000000000000000000000000000000000":
			Ke = KeyPair.query.filter_by(address=auth['enclave'], dealid=dealid).first()
			secrets['enclave'] = { 'address': auth['enclave'], 'secret': str(Ke) if Ke else None }

		return { 'secrets': secrets, 'params':  params }

	def setPalaemonConf(self, auth):
		if self.test:
			task = {
				'dealid':      		"0x94757d256ec07228a010ebf3f04048487583f2818121bcef961268f4fb8db560",
				'app':         		"0x570280a48EA01a466ea5a88d0f1C16C124BCDc3E",
				'dataset':     		"0xAAdC3C643b79dbf8b761bA62283fF105930B20eb",
				'beneficiary': 		"0xC08C3def622Af1476f2Db0E3CC8CcaeAd07BE3bB",
				'params':      		"blob",
				'id':				auth['taskid'],
				'worker_address':	auth['worker']
			}
			deal = ""


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('--host',      type=str, default='0.0.0.0',               help='REST api host - default: 0.0.0.0'             )
	parser.add_argument('--port',      type=int, default=5000,                    help='REST api port - default: 5000'                )
	parser.add_argument('--gateway',   type=str, default='http://localhost:8545', help='web3 gateway - default: http://localhost:8545')
	parser.add_argument('--database',  type=str, default='sqlite:////tmp/sms.db', help='SMS database - default: sqlite:///:memory:'   ) # for persistency use 'sqlite:////tmp/sms.db'
	parser.add_argument('--contracts', type=str, default='contracts',             help='iExec SC folder - default: ./contracts'       )
	parser.add_argument('--hub',       type=str, required=True,                   help='iExecHub address'                             )
	parser.add_argument('--test',      action="store_true")
	config = parser.parse_args()

	# CREATE BLOCKCHAIN INTERFACE
	blockchaininterface = BlockchainInterface(config=config)

	# DATABASE SETTINGS
	app.config['SQLALCHEMY_DATABASE_URI'] = config.database

	# SETUP ENDPOINTS
	api.add_resource(SecretAPI,   '/secret/<string:address>',              endpoint='secret'  ) # address: account or ressource SC
	api.add_resource(GenerateAPI, '/attestation/generate/<string:dealid>', endpoint='generate') # dealid
	api.add_resource(VerifyAPI,   '/attestation/verify/<string:address>',  endpoint='verify'  ) # address: enclaveChallenge
	api.add_resource(SecureAPI,   '/secure',                               endpoint='secure'  )
	api.add_resource(SessionAPI,  '/securesession/generate',               endpoint='sessiongenerate'  )

	# RUN DAEMON
	db.create_all()
	app.run(host=config.host, port=config.port, debug=False)
	# db.drop_all() # Don't drop
