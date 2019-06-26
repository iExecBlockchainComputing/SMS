#!/bin/sh

curl -H "Content-Type: application/json" -X POST -d '{
	"auth":
	{"worker":"0x748e091bf16048cb5103E0E10F9D5a8b7fBDd860","taskid":"0x94757d256ec07228a010ebf3f04048487583f2818121bcef961268f4fb8db560","enclave":"0x359E020aE248cE356B4Ed6F9cf5D39D157dAC77d","sign":"0x8362e9042efd6040f4d82cc1b7ba19de1c29771c3d1da6dba68ba07e1292313d2992923895165471f98530117974356ffcdbb800b3c688a09bc44bedd3cbb68601","workersign":"0xa8e100919bf85fd58446e307ab479e90e5af07ddfc59b39dd7eb7ddc2b57a4ec1e8aab8a2b651b51edbdd53b84df462c80fdbabafb19c7fc285d89740547589e01"}

}' http://localhost:5000/secure
