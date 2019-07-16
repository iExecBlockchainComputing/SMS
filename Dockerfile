FROM iexechub/python-scone

RUN apk update && apk add gcc musl-dev
RUN cp /usr/bin/python3.6 /usr/bin/python3
RUN pip install web3 flask flask_restful flask_sqlalchemy

COPY libscone-cli.so /usr/lib/libscone-cli.so
COPY python/scone_cli /usr/lib/python3.6/scone_cli
RUN mkdir scone_volume_fspf

COPY python /python
COPY node_modules /node_modules
COPY docker-entrypoint.sh /docker-entrypoint.sh

RUN chmod +x /docker-entrypoint.sh
ENTRYPOINT /bin/sh /docker-entrypoint.sh

# docker image build -t nexus.iex.ec/sms:<tag> .

# docker run -it --name sms \
#     -e GATEWAY=http://localhost:8545 \
#     -e CAS=localhost:18765 \
#     -e HUB=0x60E25C038D70A15364DAc11A042DB1dD7A2cccBC \
#     -p 5000:5000 \
#     --device=/dev/isgx:/dev/isgx \
#     nexus.iex.ec/sms:<tag>

