#!/bin/bash

python3 sms/daemon.py                                      \
	--hub 0x7C788C2B85E20B4Fa25bd579A6B1D0218D86BDd1            \
	--contracts node_modules/iexec-poco/build/contracts         \
	$@
