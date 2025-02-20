import boto3
import json

def get_IAM_policies():
    iamPoli = boto3.client("iam")
    response = iamPoli.list_policies(Scope='All')
    results = []
    for policies in response['Policies']:
        pName = policies['PolicyName']
        if "AdministratorAccess" in pName:
            risk = "Critical" if pName == "AdministratorAccess" else "High"
            results.append({
                "Policy Name": pName,
                "Risk": "Overly permissive Iam policy, " + risk
            })

    return results


#jresp = json.dumps(response, indent=4)
#print(jresp)

def save_to_json_file(data):
    with open('IAMpoliciesResults.json', 'w') as f:
        json.dump(data, f, indent=4)
    print("Security scan results saved to IAMpoliciesResults.json")


if __name__ == '__main__':
    results = get_IAM_policies()

    if results :
        print("Potential Security Risks Found:")
        for r in results:
            print(f"{r['Arn']} {r['Policy Name']} {r['Risk']}")
        save_to_json_file(results)
    else:
        print("No security risks detected!")

