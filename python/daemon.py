#!/usr/bin/python3

import argparse
import json
import hashlib
import requests
import subprocess
import docker
import re
import os
import random
import string

from string import Template
from web3                 import Web3, HTTPProvider
from web3.contract        import Contract
from eth_account.messages import defunct_hash_message
from flask                import Flask, jsonify, make_response, request
from flask_restful        import Api, Resource, reqparse
from flask_sqlalchemy     import SQLAlchemy
from Crypto.PublicKey     import RSA

MAXSIZE = 4096
confTemplatePath            = "./palaemonConfTemplate.txt"
casAddress                  = "127.0.0.1:2390"
iexec_enclave_fspf_tag      = "b9b43b7425324d59114323bcb2224793"
iexec_enclave_fspf_key      = "9e2d0cbd3ee6b8882e464880af2bd721d25b4ed279313632286df2067d38444b"

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
    dealid  = db.Column(db.String(66), unique=False, nullable=False)

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
        print (request.is_json)
        content = request.get_json()
        print (content)
        args = self.reqparse.parse_args()
        if len(args.secret) > MAXSIZE:
            return jsonify({ 'error': 'secret is to large.' }) # TODO: add error code?
        elif blockchaininterface.checkIdentity(address, defunct_hash_message(text=args.secret), args.sign):
            if params.mode == "test":
                print("New secret pushed:")
                print(args.secret)
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

    def get(self, dealid):
        print("generate")
        print(dealid)
        Ke = KeyPair.query.filter_by(dealid=dealid).first()
        if Ke is not None:
            return jsonify({ 'addressa': Ke.address })

        account = blockchaininterface.w3.eth.account.create()
        db.session.merge(KeyPair(                                             \
            address=account.address,                                          \
            private=blockchaininterface.w3.toHex(account.privateKey),         \
            dealid=dealid                                                       \
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

### APP ENDPOINT: Palaemon conf file generation
class SessionAPI(Resource):
    def __init__(self):
        super(SessionAPI, self).__init__()

    def post(self):
        try:
            print (request.get_json())
            return jsonify(blockchaininterface.setPalaemonConf(request.json['auth']))
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
        self.mode       = config.mode

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

    def setPalaemonConf(self, auth):
        if self.mode == "test":
            task = {
                'dealid'       :   "0x94757d256ec07228a010ebf3f04048487583f2818121bcef961268f4fb8db560",
                'app'          :   "0x63C8De22025a7A463acd6c89C50b27013eCa6472",
                'dataset'      :   "0x4b40D43da477bBcf69f5fd26467384355a1686d6",
                'beneficiary'  :   "0xC08C3def622Af1476f2Db0E3CC8CcaeAd07BE3bB",
                'params'       :   ""
            }
            deal = ""

        else:
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
            hash = self.w3.solidityKeccak([                                       \
                'address',                                                        \
                'bytes32',                                                        \
                'address'                                                         \
            ], [                                                                  \
                auth['worker'],                                                   \
                auth['taskid'],                                                   \
                auth['enclave']                                                   \
            ])
            signer = self.w3.eth.account.recoverHash(                             \
                message_hash=defunct_hash_message(hash),                          \
                vrs=(auth['sign']['v'], auth['sign']['r'], auth['sign']['s'])     \
            )
            assert(signer == scheduler)

        confInfo = self.getConfInfo(task, deal)
        print(confInfo)
        if 'error' in confInfo:
            return {"error", confInfo["error"]}

        conf = self.generatePalaemonConfFile(confInfo)

        #Post session to Palaemon, over https. this is not secure, we need to attest Palaemon.
        response = requests.post('https://' + casAddress + '/session', data=conf, verify=False)

        sessionId = self.parseSessionId(response)

        assert(sessionId == confInfo['sessionId'])

        return {
            'session_id'         : confInfo['session_id'],
            'output_fspf'        : confInfo['output_fspf'],
            'beneficiary_key'    : confInfo['beneficiary_key']
        }

    def parseSessionId(response):
        return re.findall(r"id=([\w-]+)", response)

    def generatePalaemonConfFile(self, confInfo):
        #insecure, better to hardcode it.
        template = Template(open(confTemplatePath,"r").read())
        return template.substitute(
            MRENCLAVE                   = confInfo['MREnclave'],
            SESSION_ID                  = confInfo['session_id'],
            COMMAND                     = confInfo['command'],
            OUTPUT_FSPF_KEY             = confInfo['output_fspf_key'],
            OUTPUT_FSPF_TAG             = confInfo['output_fspf_tag'],
            DATA_FSPF_KEY               = confInfo['data_fspf_key'],
            DATA_FSPF_TAG               = confInfo['data_fspf_tag'],
            FSPF_KEY                    = confInfo['fspf_key'],
            FSPF_TAG                    = confInfo['fspf_tag'],
            IEXEC_ENCLAVE_FSPF_KEY      = iexec_enclave_fspf_key,
            IEXEC_ENCLAVE_FSPF_TAG      = iexec_enclave_fspf_tag
        )

    def getConfInfo(self, task, deal):

        if self.mode == "test":
            app         = task['app']
            dataset     = task['dataset']
            beneficiary = task['beneficiary']
            dealid      = task['dealid']
            params      = "blob"
        else:
            app         = deal[0]
            dataset     = deal[3]
            beneficiary = deal[12]

        #now gathering different info for building Palaemon conf
        confInfo = dict()

        #info for dApp (MREnclave for different heap size, fspf_tag, fspf_key)
        appInfo = self.getdAppInfo(app)
        if 'error' in appInfo:
            return {'error' : appInfo['error']}
        print("AppInfo:")
        print(appInfo)
        confInfo.update(appInfo)

        #info for dataset (dataset_fspf_key, dataset_fspf_tag)
        datasetInfo = self.getDatasetInfo(dataset)
        if 'error' in datasetInfo:
            return {'error' : datasetInfo['error']}
        print("Dataset info:")
        print(datasetInfo)
        confInfo.update(datasetInfo)

        #info for output volume encryption (used by scone runtime)
        beneficiaryKey =  Secret.query.filter_by (address=beneficiary).first().secret;
        outputVolumeInfo = self.getOutputVolumeInfo(beneficiary, beneficiaryKey)
        if 'error' in outputVolumeInfo:
            return {"error", outputVolumeInfo["error"]}
        confInfo.update(outputVolumeInfo)

        #key for enclave challenge/ execution attestation
        confInfo["enclaveChallengeKey"] = KeyPair.query.filter_by(dealid=dealid).first()

        #session id generation (shameless copy past from stack overflow)
        confInfo["session_id"] = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(30))

        confInfo["command"] = params

        return confInfo

    #return dict containing output_fspf (as a string), output_fspf_tag, output_fspf_key, and  output_fspf_key encrypted with beneficiary key.
    #not secure, we write everything on disk, need to do all this inside enclave.
    def getOutputVolumeInfo(self, beneficiary, beneficiaryKey):
        #shell script to launch docker scone-cli, to create fspf and encrypt it.
        beneficiaryDirPath="./output_fspf/"+beneficiary
        try:
            os.stat(beneficiaryDirPath)
        except:
            os.mkdir(beneficiaryDirPath)

        subprocess.call(['./create_output_fspf.sh', beneficiary])

        file = open("./output_fspf/" + beneficiary + "/fspf.pb", "rb")
        fspf = file.read() #encrypted fspf (binary) should we encode in base64
        file.close()

        file = open("./output_fspf/" + beneficiary + "/keytag", "r")
        key, tag = file.read().split("|")
        file.close()

        return {
            'fspf'                             :     base64.b64encode(fspf),
            'output_fspf_key'                  :     key,
            'output_fspf_tag'                  :     tag,
        }

    def getDatasetInfo(self, dataset):
        secret = Secret.query.filter_by (address=dataset                 ).first()
        if secret is None:
            return {'error' : "there is no info for this dataset"}

        infos = secret.secret.split("|")

        return {
            'data_fspf_key' : infos[0],
            'data_fspf_tag' : infos[1],
            'address' : dataset
        }

    def getdAppInfo(self,dAppAddress):
        dAppFingerprint = self.getContract(address=dAppAddress, abiname='App').functions.m_appMREnclave().call()
        if dAppFingerprint is None:
            return {
                'error' : "Couldn't find dAppFingerprint"
            }
        infos = dAppFingerprint.decode("utf-8").split("|")
        return {
            "fspf_key"   :     infos[0],
            "fspf_tag"   :     infos[1],
            "MREnclave"  :     infos[2]
        }

    def validateAndGetKeys(self, auth):
        # Get task details
        if self.mode == "test":
            app          =   "0x63C8De22025a7A463acd6c89C50b27013eCa6472"
            dataset      =   "0x4b40D43da477bBcf69f5fd26467384355a1686d6"
            beneficiary  =   "0xC08C3def622Af1476f2Db0E3CC8CcaeAd07BE3bB"
            dealid      =    "0x94757d256ec07228a010ebf3f04048487583f2818121bcef961268f4fb8db560"
            params      = "blob"
        else:
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
            hash = defunct_hash_message(self.w3.soliditySha3([                  \
                "address",                                                      \
                "bytes32",                                                      \
                "address",                                                      \
                ],[ \
                auth['worker'],                                                   \
                auth['taskid'],                                                   \
                auth['enclave'],                                                  \
            ]))
            #assert(scheduler      == self.w3.eth.account.recoverHash(message_hash=hash, signature=auth['sign']))
            #assert(auth['worker'] == self.w3.eth.account.recoverHash(message_hash=hash, signature=auth['workersign']))

            # CHECK 3: MREnclave verification (only if part of the deal)
            if tag[31] & 0x01:
                # Get enclave secret
                ExpectedMREnclave = self.getContract(address=app, abiname='App').functions.m_appMREnclave().call()
                # print(f'MREnclave: {MREnclave}')
                raise NotImplementedError('MREnclave verification not implemented')
        print(type(dataset))
        secrets = {}
        secrets[dataset]         = Secret.query.filter_by (address=dataset    ).first() # Kd
        secrets[beneficiary]     = Secret.query.filter_by (address=beneficiary).first() # Kb
        secrets[auth['enclave']] = KeyPair.query.filter_by(dealid =dealid      ).first() # Ke

        return {
            'secrets': { key: value.jsonify() if value else None for key, value in secrets.items() },
            'params':  params,
        }



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host',      type=str, default='0.0.0.0',               help='REST api host - default: 0.0.0.0'             )
    parser.add_argument('--port',      type=int, default=5000,                    help='REST api port - default: 5000'                )
    parser.add_argument('--gateway',   type=str, default='http://localhost:8545', help='web3 gateway - default: http://localhost:8545')
    parser.add_argument('--database',  type=str, default='sqlite:////tmp/sms.db',    help='SMS database - default: sqlite:///:memory:'   ) # for persistency use 'sqlite:////tmp/sms.db'
    parser.add_argument('--contracts', type=str, default='contracts',             help='iExec SC folder - default: ./contracts'       )
    parser.add_argument('--clerk',     type=str, required=True,                   help='iExecClerk address'                           )
    parser.add_argument('--hub',       type=str, required=True,                   help='iExecHub address'                             )
    parser.add_argument('--mode',      type=str, default='test')
    params = parser.parse_args()

    # CREATE BLOCKCHAIN INTERFACE
    blockchaininterface = BlockchainInterface(config=params)

    # DATABASE SETTINGS
    app.config['SQLALCHEMY_DATABASE_URI'] = params.database

    # SETUP ENDPOINTS
    api.add_resource(SecretAPI,   '/secret/<string:address>',               endpoint='secret'  ) # address: account or ressource SC
    api.add_resource(GenerateAPI, '/attestation/generate/<string:dealid>',  endpoint='generate') # address: appid
    api.add_resource(VerifyAPI,   '/attestation/verify/<string:address>',   endpoint='verify'  ) # address: enclaveChallenge
    api.add_resource(SecureAPI,   '/secure',                                endpoint='secure'  )
    api.add_resource(SessionAPI,  '/securesession/generate',                endpoint='sessiongenerate'  )

    # RUN DAEMON
    db.create_all()
    app.run(host=params.host, port=params.port, debug=False)
    # db.drop_all() # Don't drop
