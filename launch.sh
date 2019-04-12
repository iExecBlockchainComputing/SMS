#!/bin/bash


python3 python/daemon.py                                      \
	--hub 0x7C788C2B85E20B4Fa25bd579A6B1D0218D86BDd1            \
	--contracts contracts \
	$@
