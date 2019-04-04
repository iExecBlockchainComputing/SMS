#!/bin/sh

beneficiary=$1

docker run -v "$PWD/output_fspf/$beneficiary:/conf" sconecuratedimages/iexec:crosscompilers sh -c \
"scone fspf create conf/volume.fspf; \
scone fspf addr conf/volume.fspf . --encrypted --kernel .; \
scone fspf encrypt ./conf/volume.fspf > /conf/keytag;"

cp -R ./output_fspf/$beneficiary/volume.fspf ../SGX/dApp/output/volume.fspf

keytag=$(cat ./output_fspf/$beneficiary/keytag)

export data_fspf_key=$(echo $keytag | awk '{print $11}')
export data_fspf_tag=$(echo $keytag | awk '{print $9}')

echo "$data_fspf_key|$data_fspf_tag" >  ./output_fspf/$beneficiary/keytag

#gpg --import public.key

#gpg --encrypt --recipient user@iex.ec -o $PWD/output_fspf/$beneficiary/keytag.gpg keytag
