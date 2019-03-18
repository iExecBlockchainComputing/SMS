#!/usr/bin/bash

curl -H "Content-Type: application/json" -X POST -d '{
	"sign": "0x18c6a2efa4cfcaf89fc08835d33fbcb2c66610a774b23654f6f714d3e0ed02891cbb86e346a6753671a97aadf1b139331da2e3d36973f963879aea54d0592fb200",
	"secret": "cGVyc29uYWxTZWNyZXQ="
}' http://localhost:5000/secret/0x9a43BB008b7A657e1936ebf5d8e28e5c5E021596
