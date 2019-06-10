#!/bin/sh

result=$(curl -H "Content-Type: application/json" -X POST -d '{
	"auth":
	{"worker":"0x748e091bf16048cb5103E0E10F9D5a8b7fBDd860","taskid":"0x7ec772a8d4be1bb7dfabdbb1d4acaf2b9f9714d482d4d68f86740880545afe53","enclave":"0x0000000000000000000000000000000000000000","sign":"0x81cba9d46245c75aa657ed322c9c170ed0984066f300436131cd06d898d3346530d9eda3c0ddd788549fb48b77d3929c192b793d3732b6dfd56c6e7292a9358d00","workersign":"0x1250d80cf7c854876c6b0dd6c54ac3ad1b19982b200e3cd04fc047ed5880f42e028da0043dd94e44ffc7f457b7e4b143a5bcc040d056b03d65d1ba4525e1040600"}
}' http://sgx-server.iex.ec:5000/securesession/generate)

echo $result

fspf=$(echo $result | sed --silent -r 's/.*"outputFspf":"([A-Za-z0-9\+\/=]+)".*/\1/p') 


sessionId=$(echo $result | sed --silent -r 's/.*"sessionId":"([A-Za-z0-9\+\/=\-]+)".*/\1/p')

echo "sessionId: $sessionId"

echo $fspf | base64 -di -w 0 > /home/charles/SGX/dApp/clean_test/output/volume.fspf
