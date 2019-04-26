#!/bin/bash

curl -H "Content-Type: application/json" -X POST -d '{
	"sign": "0x896bc9079f14ef72439942f8861c613d441792edb6fb6605dde14b92b789dd67467fdf8f5934c36c852a92def58baea931a959b920e9015a0d65514b15f3735100",
	"secret": "cGVyc29uYWxTZWNyZXQ="
}' http://localhost:5000/secret/0x9a43BB008b7A657e1936ebf5d8e28e5c5E021596
