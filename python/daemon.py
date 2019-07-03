#!/usr/bin/python3

import web3

import argparse
import json
import hashlib
import uuid
import base64

import requests
import subprocess
import re
import os, sys
import random
import string


from string import Template
from scone_cli            import fspf
from web3                 import Web3, HTTPProvider
from web3.contract        import Contract
from eth_account.messages import defunct_hash_message
from flask                import Flask, jsonify, make_response, request
from flask_restful        import Api, Resource, reqparse
from flask_sqlalchemy     import SQLAlchemy

MAXSIZE                     = 4096
SALT                        = "iexec_sms_secret:"
confTemplatePath            = "./python/palaemonConfTemplate.txt" # WARNING: RELATIVE PATH
certificats                 = ("./python/client.crt", "./python/client-key.key") # WARNING: RELATIVE PATH
iexec_enclave_fspf_tag      = "1d7b6434975be521a07ae686f8145d59"
iexec_enclave_fspf_key      = "d0e0f60f67ceb28c0010c5b2effbf5865ec538e8d9f9e95bac1ea30bf44dc50b"
# +---------------------------------------------------------------------------+
# |                           ENVIRONMENT VARIABLES                           |
# +---------------------------------------------------------------------------+
app = Flask("SMS scone - v1")
app.config['SQLALCHEMY_DATABASE_URI'       ] = "sqlite:///:memory:" # overwritten by params.database
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
	taskid  = db.Column(db.String(66), unique=False, nullable=False)

	def __repr__(self):
		return self.private

# +---------------------------------------------------------------------------+
# |                               APP ENDPOINTS                               |
# +---------------------------------------------------------------------------+

class RevertError(Exception):
	print(super)
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
		args = self.reqparse.parse_args()
		if len(args.secret) > MAXSIZE:
			return jsonifyFailure('secret is to large.')
		elif blockchaininterface.checkIdentity(address, defunct_hash_message(text=SALT+args.secret), args.sign):
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

	def get(self, taskid):
		Ke = KeyPair.query.filter_by(taskid=taskid).first()
		if Ke is not None:
			return jsonifySuccess({ 'address': Ke.address, 'taskid': taskid })

		account = blockchaininterface.w3.eth.account.create()
		db.session.merge(KeyPair(                                             \
			address=account.address,                                          \
			private=blockchaininterface.w3.toHex(account.privateKey),         \
			taskid=taskid                                                     \
		))
		db.session.commit()
		return jsonifySuccess({ 'address': account.address, 'taskid': taskid })

### APP ENDPOINT: enclave attestation verification
class VerifyAPI(Resource):
	def __init__(self):
		super(VerifyAPI, self).__init__()

	def get(self, address):
	# KeyPair.query.filter_by(address=address, dealid=dealid).first() # Ke
		dealid = "0x23e9a6c8621582399a2626b67c2c11d3058c26eeabf97911fdf507a25beede6a"
		entry = KeyPair.query.filter_by(address=address, dealid=dealid).first()
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
		self.config = config
		self.w3 = Web3(HTTPProvider(config.gateway))
		self.ABIs = {                                                                    \
			'Ownable':    json.load(open(f'{config.contracts}/Ownable.json'   ))['abi'], \
			'App':        json.load(open(f'{config.contracts}/App.json'       ))['abi'], \
			'IexecClerk': json.load(open(f'{config.contracts}/IexecClerk.json'))['abi'], \
			'IexecHub':   json.load(open(f'{config.contracts}/IexecHub.json'  ))['abi'], \
			'IERC1271':   json.load(open(f'{config.contracts}/IERC1271.json'  ))['abi'], \
		}
		self.IexecHub = self.getContract(
			address = self.w3.toChecksumAddress(config.hub),
			abiname = 'IexecHub'
		)
		self.IexecClerk = self.getContract(
			address = self.IexecHub.functions.iexecclerk().call(),
			abiname = 'IexecClerk'
		)

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
		# task = self.IexecHub.functions.viewTask(taskid).call()
		# print(task)
		task = self.IexecHub.functions.viewTaskABILegacy(taskid).call()

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

		# If TEE tag is enable, use scone
		if tag[31] & 0x01:
			# Get enclave secret
			confInfo = self.getConfInfo(
				taskid      = taskid,
				dealid      = dealid,
				app         = app,
				dataset     = dataset,
				beneficiary = beneficiary,
				params      = params,
				worker      = auth['worker']
			)

			requests.post(
				'https://{}/session'.format(self.config.casAddress),
				data   = self.generatePalaemonConfFile(confInfo),
				cert   = certificats,
				verify = False
			)

			return {
				'sessionId':       confInfo['session_id'],
				'sconeVolumeFspf': confInfo['scone_volume_fspf'],
				'beneficiaryKey':  confInfo['beneficiary_key']
			}

		# Otherwise send secret in the answer
		else:
			secrets = {}
			if dataset != "0x0000000000000000000000000000000000000000":
				Kd = Secret.query.filter_by(address=dataset).first()
				secrets['dataset'] = { 'address': dataset, 'secret': str(Kd) if Kd else None }

			if beneficiary != "0x0000000000000000000000000000000000000000":
				Kb = Secret.query.filter_by(address=beneficiary).first()
				secrets['beneficiary'] = { 'address': beneficiary, 'secret': str(Kb) if Kb else None }

			if auth['enclave'] != "0x0000000000000000000000000000000000000000":
				Ke = KeyPair.query.filter_by(address=auth['enclave'], taskid=taskid).first()
				secrets['enclave'] = { 'address': auth['enclave'], 'secret': str(Ke) if Ke else None }

			return { 'secrets': secrets, 'params':  params }

	def getConfInfo(self, taskid, dealid, app, dataset, beneficiary, params, worker):
		#now gathering different info for building Palaemon conf
		confInfo = dict()

		#info for dApp (MREnclave for different heap size, fspf_tag, fspf_key)
		confInfo.update(self.getAppInfo(app))

		#info for dataset (dataset_fspf_key, dataset_fspf_tag)
		confInfo.update(self.getDatasetInfo(dataset))

		#info for output volume encryption (used by scone runtime)
		beneficiaryKey = Secret.query.filter_by(address=beneficiary).first().secret
		confInfo.update(self.getSconeVolumeInfo(beneficiary, beneficiaryKey))

		confInfo['enclave_challenge_key'] = KeyPair.query.filter_by(taskid=taskid).first().private
		confInfo['session_id']            = str(uuid.uuid4())
		confInfo['command']               = params
		confInfo['task_id']               = taskid
		confInfo['worker_address']        = self.w3.toChecksumAddress(worker)

		return confInfo

	def getAppInfo(self, dAppAddress):
		dAppFingerprint = self.getContract(address=dAppAddress, abiname='App').functions.m_appMREnclave().call()
		if dAppFingerprint is None:
			raise RevertError("Couldn't find dAppFingerprint")
		[fspf_key, fspf_tag, MREnclave] = dAppFingerprint.decode("utf-8").split("|")[:3]

		return {
			"fspf_key":  fspf_key,
			"fspf_tag":  fspf_tag,
			"MREnclave": MREnclave
		}

	def getDatasetInfo(self, dataset):
		secret = Secret.query.filter_by(address=dataset).first()
		if secret is None:
			raise RevertError("Couldn't find dataset info")
		[data_fspf_key, data_fspf_tag] = secret.secret.split("|")[:2]

		return {
			'data_fspf_key': data_fspf_key,
			'data_fspf_tag': data_fspf_tag,
			'address':       dataset
		}

	#return dict containing output_fspf (as a string), output_fspf_tag, output_fspf_key, and  output_fspf_key encrypted with beneficiary key.
	#not secure, we write everything on disk, need to do all this inside enclave.
	def getSconeVolumeInfo(self, beneficiary, beneficiaryKey):
		#shell script to launch docker scone-cli, to create fspf and encrypt it.
		beneficiaryDirPath = "scone_volume_fspf/{}".format(beneficiary) # WARNING: RELATIVE PATH
		try:
			os.stat(beneficiaryDirPath)
		except:
			os.mkdir(beneficiaryDirPath)

		#here we need to call scone libraries
		fspfPath = "scone_volume_fspf/{}/volume.fspf".format(beneficiary) # WARNING: RELATIVE PATH

		(key, tag) = fspf.create_empty_volume_encr(fspfPath)

		with open(fspfPath, "rb") as file:
			fspfFile = file.read() #encrypted fspf (binary) should we encode in base64

		return {
			'scone_volume_fspf':     base64.b64encode(fspfFile).decode('ascii'),
			'scone_volume_fspf_key': key.hex(),
			'scone_volume_fspf_tag': tag.hex(),
			'beneficiary_key':       beneficiaryKey
		}

	def generatePalaemonConfFile(self, confInfo):
		#insecure, better to hardcode it.
		template = Template(open(confTemplatePath,"r").read())
		return template.substitute(
			MRENCLAVE              = confInfo['MREnclave'],
			SESSION_ID             = confInfo['session_id'],
			COMMAND                = confInfo['command'],
			SCONE_FSPF_KEY         = confInfo['scone_volume_fspf_key'],
			SCONE_FSPF_TAG         = confInfo['scone_volume_fspf_tag'],
			DATA_FSPF_KEY          = confInfo['data_fspf_key'],
			DATA_FSPF_TAG          = confInfo['data_fspf_tag'],
			FSPF_KEY               = confInfo['fspf_key'],
			FSPF_TAG               = confInfo['fspf_tag'],
			IEXEC_ENCLAVE_FSPF_KEY = iexec_enclave_fspf_key,
			IEXEC_ENCLAVE_FSPF_TAG = iexec_enclave_fspf_tag,
			ENCLAVE_KEY            = confInfo['enclave_challenge_key'],
			TASK_ID                = confInfo['task_id'],
			WORKER_ADDRESS         = confInfo['worker_address']
		)

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('--host',      type=str, default='0.0.0.0',                                      help='REST api host - default: 0.0.0.0'             )
	parser.add_argument('--port',      type=int, default=5000,                                           help='REST api port - default: 5000'                )
	parser.add_argument('--gateway',   type=str, default='https://rpckovan1w7wagudqhtw5khzsdtv.iex.ec/', help='web3 gateway - default: http://localhost:8545')
	parser.add_argument('--database',  type=str, default='sqlite:///:memory:',                         	 help='SMS database - default: sqlite:///:memory:'   ) # for persistency use 'sqlite:////tmp/sms.db'
	parser.add_argument('--contracts', type=str, default='contracts',                                    help='iExec SC folder - default: ./contracts'       )
	parser.add_argument('--hub',       type=str, required=True,                                          help='iExecHub address'                             )
	parser.add_argument('--casAddress',type=str, required=True,                                          help='CAS address'                             	 )
	params = parser.parse_args()

	# CREATE BLOCKCHAIN INTERFACE
	blockchaininterface = BlockchainInterface(config=params)

	# DATABASE SETTINGS
	app.config['SQLALCHEMY_DATABASE_URI'] = params.database

	# SETUP ENDPOINTS
	api.add_resource(SecretAPI,   '/secret/<string:address>',              endpoint='secret'         ) # address: account or ressource SC
	api.add_resource(GenerateAPI, '/attestation/generate/<string:taskid>', endpoint='generate'       ) # taskid
	api.add_resource(VerifyAPI,   '/attestation/verify/<string:address>',  endpoint='verify'         ) # address: enclaveChallenge
	api.add_resource(SecureAPI,   '/secure',                               endpoint='secure'         )
	api.add_resource(SessionAPI,  '/securesession/generate',               endpoint='sessiongenerate')


	# RUN DAEMON
	db.create_all()
	app.run(host=params.host, port=params.port, debug=False)
	# db.drop_all() # Don't drop
