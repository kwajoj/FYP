
import argparse
from Scanner.SG import sg_main
from Scanner.IAM import IAM_main
from Scanner.s3buckets import s3_main


def main():
	parser = argparse.ArgumentParser(description='Cloud security scanner, scan for Security Groups, IAM policies and S3 buckets')
	parser.add_argument("-sg", help="Check Security Groups",action="store_true")
	parser.add_argument("-iam", help="Check IAM Policies", action="store_true")
	parser.add_argument("-s3", help="Check S3 Buckets", action="store_true")
	parser.add_argument("-all", help="Check for all (s3, IAM, Security Groups)", action="store_true")

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

	if args.all:
		print("Scanning Security Groups...")
		resultsSG = sg_main()
		print(resultsSG)
		print("Scanning IAM policies...")
		resultsIAM = IAM_main()
		print(resultsIAM)
		print("Scanning S3 Buckets...")
		resultsS3 = s3_main()
		print(resultsS3)



if __name__ == '__main__':
	main()

