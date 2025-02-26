import boto3
import json

def get_s3_buckets():
    s3 = boto3.client("s3")
    response = s3.list_buckets()
    results = []

    for buckets in response.get('Buckets', []):
        bucketName = buckets['Name']
        risk = []
        acls = s3.get_bucket_acl(Bucket=bucketName)
        publicAccess = s3.get_public_access_block(Bucket=bucketName)
    

        #check block public access (bucket settings)
        config = publicAccess.get('PublicAccessBlockConfiguration',{})
        if config:
            if all(config.values()):
                risk.append("(Bucket setting) Public Access is blocked")

            elif not all(config.values()):
                risk.append("(Bucket setting) CRITICAL: Public Access is OPEN!")
            else:
                risk.append("(Bucket Setting) CRITICAL: Not all Public Access settings are blocked, check configurations!")

        else:
            risk.append("(Bucket setting) CRITICAL: No Public Access block setting found!")

        #check acls
        public = False
        users = False

        for grants in acls['Grants']:
            grantee = grants.get('Grantee',{}).get('URI','')

            if "AllUsers" in grantee:
                public = True
            if "AuthenticatedUsers" in grantee:
                users = True


        if public:
            risk.append("(ACL) CRITICAL: Public Access!")
        elif users:
            risk.append("(ACL) HIGH: All Authenticated Users have access!")
        else:
            risk.append("(ACL) Secure ACL configurations")

        results.append({
                "Bucket Name": bucketName,
                "Risk": risk
                })

        

    return results


#jresp = json.dumps(response, indent=4)
#print(jresp)

def save_to_json_file(data):
    with open('s3Results.json', 'w') as f:
        json.dump(data, f, indent=4)
    print("Security scan results saved to s3Results.json")


def s3_main():
    results = get_s3_buckets()

    if results :
        print("Potential Security Risks Found:")
        for r in results:
            print(f"{r['Bucket Name']}:")
            for risk in r['Risk']:
                print(f"  - {risk}")
        save_to_json_file(results)
    else:
        print("No security risks detected!")

