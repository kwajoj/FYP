
import argparse
from SG import sg_main
from IAM import IAM_main
from s3buckets import s3_main


def main():
	parser = argparse.ArgumentParser(description='Cloud security scanner, scan for Security Groups, IAM policies and S3 buckets')
	parser.add_argument("-sg", help="Check Security Groups",action="store_true")
	parser.add_argument("-iam", help="Check IAM Policies", action="store_true")
	parser.add_argument("-s3", help="Check S3 Buckets", action="store_true")

	args = parser.parse_args()

	if args.sg:
		print("Scanning Security Groups...")
		results = sg_main()
		print(results)

	if args.iam:
		print("Scanning IAM policies...")
		results = IAM_main()
		print(results)

	if args.s3:
		print("Scanning S3 Buckets...")
		results = s3_main()
		print(results)


if __name__ == '__main__':
	main()

