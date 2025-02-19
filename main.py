import boto3
import json

def get_security_groups():
	client = boto3.client("ec2")
	response = client.describe_security_groups()
	results = []
    for securityGroups in response['SecurityGroups']:
        groupName = securityGroups['GroupName']
        groupId = securityGroups['GroupId']

        for permissions in securityGroups.get('IpPermissions', []):
            if 'IpRanges' in permissions:
                for ipRange in permissions['IpRanges']:
                    if ipRange['CidrIp'] == '0.0.0.0/0':  # Public access detected
                        results.append({
                            "Security Group": groupName,
                            "Group ID": groupId,
                            "Open Port": permissions.get('FromPort', 'All'),
                            "Risk": "Public access detected, open ports"
                        })

    return results


	#jresp = json.dumps(response, indent=4)
	#print(jresp)

def save_to_json_file(data):
	with open('securityResults.json', 'w') as f:
		json.dump(data, f, indet=4)
	print("Security scan results saved to securityResults.json")
	

if __name__ == '__main__':
    get_security_groups() 