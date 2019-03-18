Python SMS prototype API
========================

The prototype SMS server is a Python3 application that uses Flask, SQLAlchemy and Web3 to provide secret and keypair management for the iExec platform. Its services are accessible through an HTTP API. The API endpoint are the as follows:

POST /secret/\<string:address\>
-------------------------------

This endpoint is used to provision a secret for the ressource pointed to by the address. The ressource is an ethereum address that can be a simple account, in which case the ressource is relative to the owner (for example a users' encryption key), or an `Ownable` smart contract, in which case the ressource is relative to the ressource described by the smart contract (for example a dataset encryption key).

To set a secret, the new value must be signed by the owner of the pointed ressource. This post method comes with metadata containing the secret and the ethereum signature.

**Return value:**

If the signature is correct, the server returns the address or the secret and the hash (sha256) of the secret. If the signature is incorrect, the server return an error `{"error":"invalid signature"}`

**Example 1:**

A user with address `0x9a43BB008b7A657e1936ebf5d8e28e5c5E021596` sends the secret `cGVyc29uYWxTZWNyZXQ=`

```
$ curl -H "Content-Type: application/json" -X POST -d '{
	"sign": "0x18c6a2efa4cfcaf89fc08835d33fbcb2c66610a774b23654f6f714d3e0ed02891cbb86e346a6753671a97aadf1b139331da2e3d36973f963879aea54d0592fb200",
	"secret": "cGVyc29uYWxTZWNyZXQ="
}' http://localhost:5000/secret/0x9a43BB008b7A657e1936ebf5d8e28e5c5E021596
{"address":"0x9a43BB008b7A657e1936ebf5d8e28e5c5E021596","hash":"14c24f251b4a23971ba10d31999ebdb6342069e8f659561a75e5a736a291bf0b"}
```

**Example 2:**

A smart contract at address `0x385fFe1c9Ec3d6a0798eD7a13445Cb2B2de9fd09` is owned by the account `0xbC11Bf07a83c7e04daef3dd5C6F9a046F8c5fA7b`. The owner sets the secret to `ZGF0YXNldFNlY3JldA==`

```
$ curl -H "Content-Type: application/json" -X POST -d '{
	"sign": "0xda0a9c12ccd39088f080f59038e1422fa5d7ce0ef7a486ab06f16b90e4c22d8061aae6061dfa7fb38cd640e10b5c8a7b3f84bf9a4a227b45c65c5cea9d77a84701",
	"secret": "ZGF0YXNldFNlY3JldA=="
}' http://localhost:5000/secret/0x385fFe1c9Ec3d6a0798eD7a13445Cb2B2de9fd09
{"address":"0x385fFe1c9Ec3d6a0798eD7a13445Cb2B2de9fd09","hash":"7277c4ad7b8a076ba750939f9c8601720a92d6fed7cf194601fa182c647c55da"}
```

GET /secret/\<string:address\>
------------------------------

This endpoint is used to check if a secret is set for the corresponding address.

**Return value:**

If a secret is set, it returns its hash (sha256). Otherwize it returns an emply json object

**Example:**

```
$ curl -H "Content-Type: application/json" -X GET -d '' http://localhost:5000/secret/0x385fFe1c9Ec3d6a0798eD7a13445Cb2B2de9fd09
{"address":"0x385fFe1c9Ec3d6a0798eD7a13445Cb2B2de9fd09","hash":"7277c4ad7b8a076ba750939f9c8601720a92d6fed7cf194601fa182c647c55da"}
```

```
$ curl -H "Content-Type: application/json" -X GET -d '' http://localhost:5000/secret/0x385fFe1c9Ec3d6a0798eD7a13445Cb2B2de9fd08
{}
```

GET /attestation/generate/\<string:address\>
--------------------------------------------

This endpoint is used to obtain the public address of an ethereum keypair used for the enclave attestation of runs involving the application designated by the address. Only certified runs of this application will be able to obtain the private part of the keypair

**Return value:**

The public part (address) of the key pair.

**Example:**

```
$ curl -H "Content-Type: application/json" -X GET -d '' http://localhost:5000/attestation/generate/0x60c1eBfBEE22687339D1c9Ff4b361cF6727241fF
{"address":"0x3E04a05575731Fbf21d82C72D72a5DD8b20FaF38"}
```

GET /attestation/verify/\<string:address\>
------------------------------------------

This endpoint is used to check which application is authorized to obtain the private part of the keypair described by the addesss.

**Return value:**

If the given address corresponds to a keypair managed by the SMS, then it returns the address of corresponding application. Otherize it returns an empty json object.

**Example:**

```
$ curl -H "Content-Type: application/json" -X GET -d '' http://localhost:5000/attestation/verify/0x3E04a05575731Fbf21d82C72D72a5DD8b20FaF38
{"address":"0x3E04a05575731Fbf21d82C72D72a5DD8b20FaF38","app":"0x60c1eBfBEE22687339D1c9Ff4b361cF6727241fF"}
```

```
$ curl -H "Content-Type: application/json" -X GET -d '' http://localhost:5000/attestation/verify/0x3E04a05575731Fbf21d82C72D72a5DD8b20FaF39
{}
```

GET /secure
-----------

This endpoint is used to get the secret corresponding to a taskid. Contrary to the other methods that answered to any caller, this method verifies that the call originates from an application running in an enclave with the MREnclave specified in the app smart contract.

This transaction comes with extra data containing the signed authorisation to contribute (signed by the scheduler). This authorisation points to a specific taskid that must correspond to a valid execution:

1. The taskid must correspond to an active execution.
2. The authorization must be signed by the scheduler owning the workerpool.
3. The transaction must origine from an enclave that matched the MREnclave specified in the application smartcontract. (TODO)

**Return value:**

If the verification steps are successfull, a json object containing secrets for Kb (the beneficiary), Kd (the dataset) and Ke (the enclave attestation). If no secret is set for this entity on this SMS, null is returned.

If the verification failled, the server returns `{"error":"access denied"}`

**Example 1:**

```
$ curl -H "Content-Type: application/json" -X GET -d '{
	"auth":
	{
		"worker": "0x748e091bf16048cb5103E0E10F9D5a8b7fBDd860",
		"taskid": "0x098f400f58acd32ac4016fe3f95aaf9b3718d3906dd975fe8a65c7648e72954d",
		"enclave": "0x3E04a05575731Fbf21d82C72D72a5DD8b20FaF38",
		"sign":
		{
			"r": "0x0000000000000000000000000000000000000000000000000000000000000000",
			"s": "0x0000000000000000000000000000000000000000000000000000000000000000",
			"v": 0
		}
	}
}' http://localhost:5000/secure
{"error":"access denied"}
```

**Example 2:**

```
$ curl -H "Content-Type: application/json" -X GET -d '{
	"auth":
	{
		"worker": "0x748e091bf16048cb5103E0E10F9D5a8b7fBDd860",
		"taskid": "0x098f400f58acd32ac4016fe3f95aaf9b3718d3906dd975fe8a65c7648e72954d",
		"enclave": "0x3E04a05575731Fbf21d82C72D72a5DD8b20FaF38",
		"sign":
		{
			"r": "0x80530f73ad3c6de390ea3fcc46ace2fa038cdff69a6de0b25772d9fabe4c1bd1",
			"s": "0x00c44ee34460f103f71b6a855f15626ccc2214e147ccede5c745b38fe841cee5",
			"v": 27
		}
	}
}' http://localhost:5000/secure
{"Kb":{"address":"0x9a43BB008b7A657e1936ebf5d8e28e5c5E021596","secret":"cGVyc29uYWxTZWNyZXQ="},"Kd":{"address":"0x385fFe1c9Ec3d6a0798eD7a13445Cb2B2de9fd09","secret":"ZGF0YXNldFNlY3JldA=="},"Ke":{"address":"0x3E04a05575731Fbf21d82C72D72a5DD8b20FaF38","private":"0xe746b4556c7d320215a407cfcc61eab9cd493d972d638495857c4c26c494b05f"}}
```
