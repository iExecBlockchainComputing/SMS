#!/usr/bin/python3

import argparse
import json
import hashlib

import web3
from web3                 import Web3, HTTPProvider
from web3.contract        import Contract
from eth_account.messages import defunct_hash_message
from flask                import Flask, jsonify, make_response, request
from flask_restful        import Api, Resource, reqparse
from flask_sqlalchemy     import SQLAlchemy

MAXSIZE = 4096
SALT = "iexec_sms_secret:"

# +---------------------------------------------------------------------------+
# |                           ENVIRONMENT VARIABLES                           |
# +---------------------------------------------------------------------------+
app = Flask("SMS prototype - v1")
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

	def get(self, dealid):
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

		# CHECK 3: MREnclave verification (only if part of the deal)
		if tag[31] & 0x01:
			# Get enclave secret
			ExpectedMREnclave = self.getContract(address=app, abiname='App').functions.m_appMREnclave().call()
			# print(f'MREnclave: {MREnclave}')
			raise RevertError('MREnclave verification not implemented')

		secrets = {}
		if dataset != "0x0000000000000000000000000000000000000000":
			secrets['dataset'] = {
				'address': dataset,
				'secret':  str(Secret.query.filter_by(address=dataset).first()) # Kd
			}

		if beneficiary != "0x0000000000000000000000000000000000000000":
			secrets['beneficiary'] = {
				'address': beneficiary,
				'secret':  str(Secret.query.filter_by(address=beneficiary).first()) # Kd
			}

		if auth['enclave'] != "0x0000000000000000000000000000000000000000":
			secrets['enclave'] = {
				'address': auth['enclave'],
				'secret':  str(KeyPair.query.filter_by(address=auth['enclave'], dealid=dealid).first()) # Ke
			}

		return {
			'secrets': { key: value if value else None for key, value in secrets.items() },
			'params':  params,
		}



if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('--host',      type=str, default='0.0.0.0',               help='REST api host - default: 0.0.0.0'             )
	parser.add_argument('--port',      type=int, default=5000,                    help='REST api port - default: 5000'                )
	parser.add_argument('--gateway',   type=str, default='http://localhost:8545', help='web3 gateway - default: http://localhost:8545')
	parser.add_argument('--database',  type=str, default='sqlite:///:memory:',    help='SMS database - default: sqlite:///:memory:'   ) # for persistency use 'sqlite:////tmp/sms.db'
	parser.add_argument('--contracts', type=str, default='contracts',             help='iExec SC folder - default: ./contracts'       )
	parser.add_argument('--hub',       type=str, required=True,                   help='iExecHub address'                             )
	params = parser.parse_args()

	# CREATE BLOCKCHAIN INTERFACE
	blockchaininterface = BlockchainInterface(config=params)

	# DATABASE SETTINGS
	app.config['SQLALCHEMY_DATABASE_URI'] = params.database

	# SETUP ENDPOINTS
	api.add_resource(SecretAPI,   '/secret/<string:address>',              endpoint='secret'  ) # address: account or ressource SC
	api.add_resource(GenerateAPI, '/attestation/generate/<string:dealid>', endpoint='generate') # dealid
	api.add_resource(VerifyAPI,   '/attestation/verify/<string:address>',  endpoint='verify'  ) # address: enclaveChallenge
	api.add_resource(SecureAPI,   '/secure',                               endpoint='secure'  )

	# RUN DAEMON
	db.create_all()
	app.run(host=params.host, port=params.port, debug=False)
	# db.drop_all() # Don't drop
