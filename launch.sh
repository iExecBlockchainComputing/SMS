#!/bin/bash

python3 python/daemon.py                                      \
	--contracts /node_modules/iexec-poco/build/contracts         \
	$@
