import boto3
import json

def get_security_groups():
	client = boto3.client("ec2")
	response = client.describe_security_groups()
	jresp = json.dumps(response)
	print(jresp)

if __name__ == '__main__':
    get_security_groups() 