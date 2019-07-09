#!/bin/bash

python3 /python/daemon.py \
          --hub $HUB \
          --gateway $GATEWAY \
          --casAddress $CAS \
          --database $DATABASE \
          --contracts /node_modules/iexec-poco/build/contracts
          $@
