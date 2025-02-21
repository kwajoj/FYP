import boto3
import json

def get_s3_buckets():
    s3 = boto3.client("s3")
    response = s3.list_buckets()
    results = []

    for buckets in response['Buckets']:
        bucketName = buckets['Name']
        acls = s3.get_bucket_acl(Bucket=bucketName)
        publicAccess = s3.get_public_access_block(Bucket=bucketName)
        public = False
        users = False

        #check block public access (bucket settings)
        config = publicAccess.get('PublicAccessBlockConfiguration',{})
        if all(config.values()):
            results.append({
                "Bucket Name": bucketName,
                "Risk": "(Bucket setting) public Access is blocked"
             })

        elif not all(config.values()):
            results.append({
                "Bucket Name": bucketName,
                "Risk": "(Bucket setting) CRITICAL: public Access is open"
             })

        else:
            results.append({
                "Bucket Name": bucketName,
                "Risk": "(Bucket Setting) CRITICAL: Not all public Access settings are blocked blocked"
            })



        #check acls
        for grants in acls['Grants']:
            grantee = grants.get('Grantee',{}).get('URI','')

            if "AllUsers" in grantee:
                public = True
            if "AuthenticatedUsers" in grantee:
                users = True


        if public and users:
            risk = "(ACL) CRITICAL: Public Access and All Users have access"
        elif public:
            risk = "(ACL) CRITICAL: Public Access"
        elif users:
            risk = "(ACL) HIGH: All Users have access"

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
            print(f"{r['Bucket Name']} {r['Risk']}")
        save_to_json_file(results)
    else:
        print("No security risks detected!")

