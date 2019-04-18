FROM python:3.7.2

RUN pip3 install web3 eth_account flask flask_restful flask_sqlalchemy

RUN mkdir /sms
COPY docker-launch.sh                        /sms/docker-launch.sh
COPY python                                  /sms/python
COPY node_modules/iexec-poco/build/contracts /sms/contracts
WORKDIR /sms

ENTRYPOINT ["./docker-launch.sh"]

# docker image build -t iexechub/sms .
# docker run -it -e HUB=0x60E25C038D70A15364DAc11A042DB1dD7A2cccBC -e GATEWAY=http://127.0.0.1:8545 -p 5000:5000 --name sms iexechub/sms:latest
