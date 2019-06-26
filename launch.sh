#!/bin/bash

python3 python/daemon.py                                      \
	--hub 0xb3901d04CF645747b99DBbe8f2eE9cb41A89CeBF            \
	--contracts sms/node_modules/iexec-poco/build/contracts         \
	$@
