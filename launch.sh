#!/bin/bash

python3 sms/daemon.py                                      \
	--hub 0x60e25c038d70a15364dac11a042db1dd7a2cccbc            \
	--contracts sms/node_modules/iexec-poco/build/contracts         \
	--test
	$@
