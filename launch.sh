#!/usr/bin/bash


python3 python/daemon.py                                      \
	--clerk 0x8BE59dA9Bf70e75Aa56bF29A3e55d22e882F91bA          \
	--hub 0x7C788C2B85E20B4Fa25bd579A6B1D0218D86BDd1            \
	--contracts /home/amxx/Work/iExec/code/PoCo/build/contracts \
	$@
