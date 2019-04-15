#!/bin/bash

curl -H "Content-Type: application/json" -X GET -d '{
	"auth":
	{
		"worker":     "0x748e091bf16048cb5103E0E10F9D5a8b7fBDd860",
		"taskid":     "0x94757d256ec07228a010ebf3f04048487583f2818121bcef961268f4fb8db560",
		"enclave":    "0x6eE03A566C1ED6cB6530737DFE0C5b15c8c5d6c6",
		"sign":       "0x0210143b084a6748c38c48ae545a1edcff0e74b9d8342b4d36e47fcfd538c1983fbfde4ab41e5059928d91699f92cd33b05d10df0801c0384527fa0ebc9d48c701",
		"workersign": "0xa9943bac0b4021221ce25639af212b9230ee1d372ef699bf323d9a3f3780727c1d1fcc067e325d9d1b444690c73f893b28c570c90181256a96eaea223561e6f300"
	}
}' http://localhost:5000/secure
