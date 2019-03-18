#!/usr/bin/bash

curl -H "Content-Type: application/json" -X POST -d '{
	"sign": "0xda0a9c12ccd39088f080f59038e1422fa5d7ce0ef7a486ab06f16b90e4c22d8061aae6061dfa7fb38cd640e10b5c8a7b3f84bf9a4a227b45c65c5cea9d77a84701",
	"secret": "ZGF0YXNldFNlY3JldA=="
}' http://localhost:5000/secret/0x385fFe1c9Ec3d6a0798eD7a13445Cb2B2de9fd09
