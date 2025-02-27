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
                    if ipRange['CidrIp'] == '0.0.0.0/0':# Public access detected
                        from_port = permissions.get('FromPort', 'All')
                        if from_port in (22, 23, 25, 139, 445, 3389, 5900, 6379, 9200, 27017):
                            risk = "Public access detected, Critical!" 
                        elif from_port in (21, 53, 80, 110, 143, 389, 3306):
                            risk = "Public access detected, High!"
                        else:
                            risk = "Public access detected, Medium"
                        results.append({
                            "Security Group": groupName,
                            "Group ID": groupId,
                            "Open Port": permissions.get('FromPort', 'All'),
                            "Risk": risk
                        })

    return results


#jresp = json.dumps(response, indent=4)
#print(jresp)

def save_to_json_file(data):
    with open('securityResults.json', 'w') as f:
        json.dump(data, f, indent=4)
    print("Security scan results saved to securityResults.json")


def sg_main():
    results = get_security_groups()

    if results :
        print("Potential Security Risks Found:")
        for r in results:
            print(f"{r['Security Group']}, {r['Group ID']} (Port {r['Open Port']}): {r['Risk']}")
        save_to_json_file(results)
    else:
        print("No security risks detected!")


    