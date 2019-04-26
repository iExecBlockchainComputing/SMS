import os
import sys
import attrdict
import json
import zipfile
import random
import traceback
import gnupg

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from web3.auto import w3
from eth_account.messages import defunct_hash_message


os.environ['enclave_key'] = "e"
os.environ['worker']      = "0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E"
os.environ['taskid'] = "0x2ef06b8bbad022ca2dd29795902ceb588d06d1cfd10cb6e687db0dbb837865e9"
os.environ['digest'] = "0x2f228f9f539aa27c7319959a2b742263ca3c5c519177bebfbe6e00e46f74bbd4"

keccak256 = w3.soliditySha3
debug = True

class DigestSigner:
    def __init__(self, enclaveKey, worker, taskid, digest):
        self.result     = digest;
        self.resultHash = keccak256([ "bytes32", "bytes32" ], [ taskid, digest ])
        self.resultSalt = keccak256([ "address", "bytes32", "bytes32" ], [ worker, taskid, digest ])
        hash = defunct_hash_message(keccak256([ "bytes32", "bytes32" ], [ self.resultHash, self.resultSalt ]))
        self.signature = w3.eth.account.signHash(hash, private_key=enclaveKey).signature

    def jsonify(self):
        return json.dumps({
            'result':     self.result,
            'resultHash': self.resultHash.hex(),
            'resultSalt': self.resultSalt.hex(),
            'signature':  self.signature.hex(),
        })

def WriteEncryptedKey(symmetricKey):
    print("Encrypting symmetric key")
    try:
        key = open('iexec_out/public.key', 'rb');
        pubKeyObj =  RSA.importKey(key.read())
        key.close()
        encryptor = PKCS1_OAEP.new(pubKeyObj)
        encrypted = encryptor.encrypt(symmetricKey)
        with open('iexec_out/encrypted_key', 'wb+') as output:
            output.write(encrypted)
        if debug:
            with open('iexec_out/plaintext_key', 'wb+') as output:
                output.write(symmetricKey)

    except:
        print('Error with opening key!')
        traceback.print_exc()
        key.close()

def WriteInitializationVector(iv):
    print("Writing iv on disk")
    try:
        ivfile = open('iexec_out/iv', 'wb+')
    except:
        traceback.print_exc()
        print(ex)
    else:
        ivfile.write(iv)
    finally:
        ivfile.close()

def TestReadEncryptedKey():
    try:
        with open('iexec_out/private.key', 'rb') as input:
            binKey = input.read()
            priKeyObj = RSA.importKey(binKey)
        with open('iexec_out/encrypted_key', 'rb') as encrypted:
            encrypted_key = encrypted.read()
        with open('iexec_out/plaintext_key', 'rb') as original:
            original_key = original.read()
    except:
        print('Error reading key')
        traceback.print_exc()
    else:
        decryptor = PKCS1_OAEP.new(priKeyObj)
        key = decryptor.decrypt(encrypted_key)
        assert key == original_key, "Keys don't match"
        return key

def TestEncryptedOutput(symmetricKey):
    try:
        with open('iexec_out/result.zip.aes', 'rb') as input, open('iexec_out/iv','rb') as ivfile:
            iv = input.read(16)
            ivfromfile = ivfile.read()
            assert iv == ivfromfile, "Init vector don't match"
            encryptedOutput = input.read()
    except:
        print('Error reading encrypted output')
        traceback.print_exc()
    else:
        decryptedOutput = DecryptOutput(encryptedOutput, symmetricKey, iv)
        padNb = decryptedOutput[-1:]

        #test padding
        assert bytearray(decryptedOutput[-padNb[0]:]) == bytearray(padNb * padNb[0]), "Padding not right!"
        print("boom")
        print(decryptedOutput[len(decryptedOutput) - padNb[0]:])
        #test decrypted equal to original
        decryptedOutput = decryptedOutput[:len(decryptedOutput) - padNb[0]]
        ZipOutput()
        with open('iexec_out/result.zip', 'rb') as input:
            originalZip = input.read()
            assert(decryptedOutput == originalZip)
        with open('iexec_out/result.test.zip', 'wb+') as output:
            output.write(decryptedOutput)
        zip_ref = zipfile.ZipFile('iexec_out/result.test.zip', 'r')
        zip_ref.extractall('iexec_out')
        zip_ref.close()

def DecryptOutput(encryptedOutput, key, iv):
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.decrypt(encryptedOutput)

def ZipOutput():
    print("Starting zipping files")
    zipf = zipfile.ZipFile('iexec_out/result.zip', 'a', zipfile.ZIP_DEFLATED)
    # ziph is zipfile handle
    for root, dirs, files in os.walk('output'):
        for file in files:
            print("Writing file " + file + " to zip archive.")
            zipf.write(os.path.join(root, file))
    zipf.close()

def PadZippedOutput():
    print("Padding zipped output")
    try:
        input = open('iexec_out/result.zip', 'ab')
        zipSize = os.path.getsize('iexec_out/result.zip')
        blockSize = 128
        nb = blockSize - zipSize % blockSize
        input.write(bytearray(bytes([nb]) * nb))

    except Exception as ex:
        traceback.print_exc()
        print(ex)

def EncryptZippedOutput():
    try:
        input = open('iexec_out/result.zip', 'rb')
        output = open('iexec_out/result.zip.aes', 'wb+')

        #generate initalization vector for AES and prepend it to output
        iv = os.urandom(16)
        output.write(iv)
        WriteInitializationVector(iv)

        #generate AES key and encrypt it/write it on disk
        key = os.urandom(16)
        WriteEncryptedKey(key)

        aes = AES.new(key, AES.MODE_CBC, iv)
        buffer_size = 8192
        #chunks = iter(lambda: input.read(buffer_size), '')
        result = input.read()
        #for chunk in chunks:
        output.write(aes.encrypt(result))

    except Exception as ex:
        traceback.print_exc()
        print(ex)

    #destroy plaintext zip
    os.remove('iexec_out/result.zip')

def WriteEnclaveSign():
    import hashlib, os
    SHAhash = hashlib.sha1()
    try:
        input = open('iexec_out/result.zip', 'rb')
        while 1:
            # Read file in as little chunks
            buf = input.read(4096)
            if not buf : break
            SHAhash.update(buf)
        input.close()
        digest = "0x" + SHAhash.hexdigest()
        enclaveKey = b"\xb2\\}\xb3\x1f\xee\xd9\x12''\xbf\t9\xdcv\x9a\x96VK-\xe4\xc4rm\x03[6\xec\xf1\xe5\xb3d"
        taskid = os.environ['taskid']
        worker = os.environ['worker']
        result = DigestSigner(
            enclaveKey = enclaveKey,
            worker     = worker,
            taskid     = taskid,
            digest     = digest,
        ).jsonify()
        print(result)
        with open('iexec_out/enclaveSig.iexec', 'w+') as outfile:
            outfile.write(result)

    except Exception as ex:
        traceback.print_exc()
        print(ex)

if __name__ == '__main__':
    print("Starting signing enclave!")
    #os.remove('iexec_out/result.zip')
    if sys.argv[1] == "decrypt":
        k=TestReadEncryptedKey()
        TestEncryptedOutput(k)
    else:
        ZipOutput()
        WriteEnclaveSign()
        PadZippedOutput()
        EncryptZippedOutput()
