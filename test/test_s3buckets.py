import pytest
from Scanner.s3buckets import get_s3_buckets

def test_open_buckets_for_public_ACL(mocker):
	mock_boto = mocker.patch("Scanner.s3buckets.boto3.client")
	mock_s3 = mock_boto.return_value
	mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "testOpenBucketACL"}]}
	mock_s3.get_bucket_acl.return_value = {"Grants": [{"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]}

	result = get_s3_buckets()

	assert len(result) == 1
	assert "CRITICAL: Public Access!" in result[0]["Risk"][1]
	mock_s3.list_buckets.assert_called_once()
	mock_s3.get_bucket_acl.assert_called_once_with(Bucket="testOpenBucketACL")

def test_open_buckets_for_AuthenticatedUsers_ACL(mocker):
	mock_boto = mocker.patch("s3buckets.boto3.client")
	mock_s3 = mock_boto.return_value
	mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "testOpenauthBucketACL"}]}
	mock_s3.get_bucket_acl.return_value = {"Grants": [{"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUAuthenticatedUsers"}}]}

	result = get_s3_buckets()

	assert len(result) == 1
	assert "HIGH: All Authenticated Users have access!" in result[0]["Risk"][1]
	mock_s3.list_buckets.assert_called_once()
	mock_s3.get_bucket_acl.assert_called_once_with(Bucket="testOpenauthBucketACL")

def test_for_secure_buckets_ACL(mocker):
	mock_boto = mocker.patch("s3buckets.boto3.client")
	mock_s3 = mock_boto.return_value
	mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "testSecureBucketACL"}]}
	mock_s3.get_bucket_acl.return_value = {"Grants": [{"Grantee": {"Type": "Group"}}]}

	result = get_s3_buckets()

	assert len(result) == 1
	assert "Secure ACL configurations" in result[0]["Risk"][1]
	mock_s3.list_buckets.assert_called_once()
	mock_s3.get_bucket_acl.assert_called_once_with(Bucket="testSecureBucketACL")


def test_open_buckets_bucketsetting(mocker):
	mock_boto = mocker.patch("s3buckets.boto3.client")
	mock_s3 = mock_boto.return_value
	mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "testOpenBucketBS"}]}
	mock_s3.get_bucket_acl.return_value = {"Grants": [{"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]}
	mock_s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": False,
            "BlockPublicPolicy": False,
            "IgnorePublicAcls": False,
            "RestrictPublicBuckets": False
        }
    }
	result = get_s3_buckets()

	assert len(result) == 1
	assert "CRITICAL: Not all or partial Public Access settings are blocked, check configurations!" in result[0]["Risk"][0]
	mock_s3.list_buckets.assert_called_once()
	mock_s3.get_public_access_block.assert_called_once_with(Bucket="testOpenBucketBS")

def test_missing_bucketsetting(mocker):
	mock_boto = mocker.patch("s3buckets.boto3.client")
	mock_s3 = mock_boto.return_value
	mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "testMissingBucketBS"}]}
	mock_s3.get_bucket_acl.return_value = {"Grants": [{"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]}
	mock_s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "BlockPublicPolicy": False,
            "IgnorePublicAcls": False,
            "RestrictPublicBuckets": False
        }
    }
	result = get_s3_buckets()

	assert len(result) == 1
	assert "CRITICAL: Not all or partial Public Access settings are blocked, check configurations!" in result[0]["Risk"][0]
	mock_s3.list_buckets.assert_called_once()
	mock_s3.get_public_access_block.assert_called_once_with(Bucket="testMissingBucketBS")

def test_secure_bucket(mocker):
	mock_boto = mocker.patch("s3buckets.boto3.client")
	mock_s3 = mock_boto.return_value
	mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "testSecureBucketBS"}]}
	mock_s3.get_bucket_acl.return_value = {"Grants": [{"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]}
	mock_s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True
        }
    }
	result = get_s3_buckets()

	assert len(result) == 1
	assert "Public Access is blocked" in result[0]["Risk"][0]
	mock_s3.list_buckets.assert_called_once()
	mock_s3.get_public_access_block.assert_called_once_with(Bucket="testSecureBucketBS")


