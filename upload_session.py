import requests
casAddress = "127.0.0.1:8081"
conf=open('session.yml', 'r').read()

print("Uploading session...")
response = requests.post(
		'https://' + casAddress + '/session',
		data=conf,
		cert=('./sms/client.crt', './sms/client-key.key'),
		verify=False
	)

print(response.content)
