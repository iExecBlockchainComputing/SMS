#!/bin/bash

curl -H "Content-Type: application/json" -X POST -d '{
	"sign": "0xcb29cad59f678e843f070689852274e6d178039fb20b2023a528d7936fdcf34c65cb5e00b95f1fe096dabbc60bac8a9f4a231e35b08933f3854529fea4f28b9c00",
	"secret": "ZGF0YXNldFNlY3JldA=="
}' http://localhost:5000/secret/0x385fFe1c9Ec3d6a0798eD7a13445Cb2B2de9fd09
