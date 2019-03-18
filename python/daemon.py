#!/usr/bin/python3

import argparse
import json
import hashlib

from web3                 import Web3, HTTPProvider
from web3.contract        import Contract
from eth_account.messages import defunct_hash_message
from flask                import Flask, jsonify, make_response, request
from flask_restful        import Api, Resource, reqparse
from flask_sqlalchemy     import SQLAlchemy

MAXSIZE = 4096

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

	def jsonify(self):
		# return { 'address': self.address, 'secret': self.secret }
		return self.secret

### DB STORE: ethereum keypair for enclave attestation
class KeyPair(db.Model):
	address = db.Column(db.String(42), primary_key=True)
	private = db.Column(db.String(66), unique=True,  nullable=False)
	app     = db.Column(db.String(42), unique=False, nullable=False)

	def jsonify(self):
		# return { 'address': self.address, 'private': self.private }
		return self.private

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
			return jsonify({                                                  \
				'address': address,                                           \
				'hash':    hashlib.sha256(entry.secret.encode()).hexdigest()  \
			})
		else:
			return jsonify({})

	def post(self, address):
		args = self.reqparse.parse_args()
		if len(args.secret) > MAXSIZE:
			return jsonify({ 'error': 'secret is to large.' }) # TODO: add error code?
		elif blockchaininterface.checkIdentity(address, defunct_hash_message(text=args.secret), args.sign):
			db.session.merge(Secret(address=address, secret=args.secret))
			db.session.commit()
			return jsonify({                                                  \
				'address': address,                                           \
				'hash':    hashlib.sha256(args.secret.encode()).hexdigest(),  \
			})
		else:
			return jsonify({ 'error': 'invalid signature' }) # TODO: add error code?

### APP ENDPOINT: enclave attestation provisionning
class GenerateAPI(Resource):
	def __init__(self):
		super(GenerateAPI, self).__init__()

	def get(self, address):
		Ke = KeyPair.query.filter_by(app=address).first()
		if Ke is not None:
			return jsonify({ 'address': Ke.address })

		account = blockchaininterface.w3.eth.account.create()
		db.session.merge(KeyPair(                                             \
			address=account.address,                                          \
			private=blockchaininterface.w3.toHex(account.privateKey),         \
			app=address                                                       \
		))
		db.session.commit()
		return jsonify({ 'address': account.address })

### APP ENDPOINT: enclave attestation verification
class VerifyAPI(Resource):
	def __init__(self):
		super(VerifyAPI, self).__init__()

	def get(self, address):
		entry = KeyPair.query.filter_by(address=address).first()
		if entry:
			return jsonify({ 'address': address, 'app': entry.app })
		else:
			return jsonify({})

### APP ENDPOINT: secret retreival by enclave
class SecureAPI(Resource):
	def __init__(self):
		super(SecureAPI, self).__init__()
		# TODO: RequestParser for auth

	def get(self):
		try:
			return jsonify(blockchaininterface.validateAndGetKeys(request.json['auth']))
		except AssertionError:
			return jsonify({ 'error': 'access denied' })

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
		self.IexecClerk = self.getContract(address=config.clerk, abiname='IexecClerk')
		self.IexecHub   = self.getContract(address=config.hub,   abiname='IexecHub'  )

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
		assert(task[0] == 1)

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
		hash = defunct_hash_message(self.w3.solidityKeccak([                  \
			'address',                                                        \
			'bytes32',                                                        \
			'address'                                                         \
		], [                                                                  \
			auth['worker'],                                                   \
			auth['taskid'],                                                   \
			auth['enclave']                                                   \
		]))
		assert(scheduler      == self.w3.eth.account.recoverHash(message_hash=hash, signature=auth['sign']))
		assert(auth['worker'] == self.w3.eth.account.recoverHash(message_hash=hash, signature=auth['workersign']))

		# CHECK 3: MREnclave verification (only if part of the deal)
		if tag[31] & 0x01:
			# Get enclave secret
			ExpectedMREnclave = self.getContract(address=app, abiname='App').functions.m_appMREnclave().call()
			# print(f'MREnclave: {MREnclave}')
			raise NotImplementedError('MREnclave verification not implemented')

		secrets = {}
		secrets[dataset]         = Secret.query.filter_by (address=dataset                 ).first() # Kd
		secrets[beneficiary]     = Secret.query.filter_by (address=beneficiary             ).first() # Kb
		secrets[auth['enclave']] = KeyPair.query.filter_by(address=auth['enclave'], app=app).first() # Ke

		return {
			'secrets': { key: value.jsonify() if value else None for key, value in secrets.items() },
			'params':  params,
		}



if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('--host',      type=str, default='0.0.0.0',               help='REST api host - default: 0.0.0.0'             )
	parser.add_argument('--port',      type=int, default=5000,                    help='REST api port - default: 5000'                )
	parser.add_argument('--gateway',   type=str, default='http://localhost:8545', help='web3 gateway - default: http://localhost:8545')
	parser.add_argument('--database',  type=str, default='sqlite:///:memory:',    help='SMS database - default: sqlite:///:memory:'   ) # for persistency use 'sqlite:////tmp/sms.db'
	parser.add_argument('--contracts', type=str, default='contracts',             help='iExec SC folder - default: ./contracts'       )
	parser.add_argument('--clerk',     type=str, required=True,                   help='iExecClerk address'                           )
	parser.add_argument('--hub',       type=str, required=True,                   help='iExecHub address'                             )
	params = parser.parse_args()

	# CREATE BLOCKCHAIN INTERFACE
	blockchaininterface = BlockchainInterface(config=params)

	# DATABASE SETTINGS
	app.config['SQLALCHEMY_DATABASE_URI'] = params.database

	# SETUP ENDPOINTS
	api.add_resource(SecretAPI,   '/secret/<string:address>',               endpoint='secret'  ) # address: account or ressource SC
	api.add_resource(GenerateAPI, '/attestation/generate/<string:address>', endpoint='generate') # address: appid
	api.add_resource(VerifyAPI,   '/attestation/verify/<string:address>',   endpoint='verify'  ) # address: enclaveChallenge
	api.add_resource(SecureAPI,   '/secure',                                endpoint='secure'  )

	# RUN DAEMON
	db.create_all()
	app.run(host=params.host, port=params.port, debug=False)
	# db.drop_all() # Don't drop
