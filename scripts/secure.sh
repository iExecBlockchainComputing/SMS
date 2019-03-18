#!/usr/bin/bash

curl -H "Content-Type: application/json" -X GET -d '{
	"auth":
	{
		"worker": "0x748e091bf16048cb5103E0E10F9D5a8b7fBDd860",
		"taskid": "0x94757d256ec07228a010ebf3f04048487583f2818121bcef961268f4fb8db560",
		"enclave": "0x51792FFbf6C1ccA5c9A9E6e227529b265254599b",
		"sign": "0x67ca2444150a4f31885851c70a633c5c6b5a57f0668ca89d144b34a9ca637aa5065467c20833713ba0eeecf93c7b71473cb1107210b834ff5da42bdbfd5804de00",
		"workersign": "0xfbebeb31f781488c9ff59291c77fc469bfa4597151e21a4d2220ceb448beba301c5cad8ebff291ef59cd165127e8a72e7d733b506ed4487f26329ec143c94d4800"
	}
}' http://localhost:5000/secure
