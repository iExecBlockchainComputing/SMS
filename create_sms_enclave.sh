#!/bin/bash

docker build -f SmsFirstBuild -t sms_scone .

docker run -v $PWD/python:/python sms_scone sh -c \
"cp -r /usr/lib/python3.6 /python;"

export MRENCLAVE="$(docker run --device=/dev/isgx -e SCONE_HEAP=500M -e SCONE_HASH=1 -e SCONE_ALPINE=1 test)"

docker run  -v "$PWD/app:/app" -v "$PWD/python/python3.6:/usr/lib/python3.6" -v "$PWD/conf:/conf"  -v "$PWD/signer:/signer" sconecuratedimages/iexec:crosscompilers sh -c \
"scone fspf create conf/fspf.pb; \
scone fspf addr conf/fspf.pb /  --not-protected --kernel /; \
scone fspf addr conf/fspf.pb /usr/lib/python3.6 --authenticated --kernel /usr/lib/python3.6; \
scone fspf addf conf/fspf.pb /usr/lib/python3.6 /usr/lib/python3.6;\
scone fspf addr conf/fspf.pb /usr/bin --authenticated --kernel /usr/bin; \
scone fspf addf conf/fspf.pb /usr/bin /usr/bin;\
scone fspf addr conf/fspf.pb /sms --authenticated --kernel /sms; \
scone fspf addf conf/fspf.pb /sms /sms;\
scone fspf addr conf/fspf.pb /db --encrypted --kernel /db; \
scone fspf encrypt ./conf/fspf.pb > /conf/keytag;"

export FSPF_TAG=$(cat conf/keytag | awk '{print $9}')
export FSPF_KEY=$(cat conf/keytag | awk '{print $11}')

FINGERPRINT="$FSPF_KEY|$FSPF_TAG|$MRENCLAVE"

echo "Fingerprint: $FINGERPRINT"

docker build -f SmsSecondBuild -t sms_scone .
