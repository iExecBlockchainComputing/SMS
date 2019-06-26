#!/bin/bash

python3 python/daemon.py                                      \
	--hub $HUB                                                  \
	--contracts contracts                                       \
	--database sqlite:////sms/sms.db                            \
	--gateway $GATEWAY
