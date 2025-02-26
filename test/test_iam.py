import pytest
from IAM import get_IAM_polocies

def test_iam_policies(mocker):
	mock_boto = mocker.patch("s3buckets.boto3.client")
	mock_s3 = mock_boto.return_value
	mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "testOpenBucket"}]}
	mock_s3.get_bucket_acl.return_value = {"Grants": [{"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]}

	result = get_s3_buckets()

	assert len(result) == 1
	assert "Public Access!" in result[0]["Risk"][1]
	mock_s3.list_buckets.assert_called_once()
	mock_s3.get_bucket_acl.assert_called_once_with(Bucket="testOpenBucket")