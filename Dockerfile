FROM python:3.7.2

#RUN apt update && apt install -y curl git ca-certificates
RUN pip3 install web3 eth_account flask flask_restful flask_sqlalchemy


RUN mkdir /sms
COPY . /sms
RUN mkdir /poco-contracts

#######
### need to copy a builded PoCo-dev in SMSproto folder
#######
COPY ./PoCo-dev/build/contracts /poco-contracts

WORKDIR /sms

ENTRYPOINT ["./docker-launch.sh"]

# docker image build -t iexechub/sms .

# docker run -it -e CLERK=0xDf62b3FddA0B2C9bc282f058eB80A270d80D25f2 -e HUB=0x60E25C038D70A15364DAc11A042DB1dD7A2cccBC -e GATEWAY=http://127.0.0.1:8545 -p 5000:5000 --name sms iexechub/sms:latest