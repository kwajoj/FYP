import pytest
from Scanner.IAM import get_IAM_policies

def test_iam_policies(mocker):
	mock_boto = mocker.patch("Scanner.IAM.boto3.client")
	mock_iam = mock_boto.return_value
	mock_iam.list_policies.return_value = {"Policies": [{"PolicyName": "AdministratorAccess"}]}

	result = get_IAM_policies()

	assert len(result) == 1
	assert "Overly permissive IAM policy" in result[0]["Risk"][0]
	mock_iam.list_policies.assert_called_once()