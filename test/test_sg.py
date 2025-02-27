import pytest
from Scanner.SG import get_security_groups

def test_sg_critical_open_port(mocker):
	mock_boto = mocker.patch("Scanner.SG.boto3.client")
	mock_iam = mock_boto.return_value
	mock_iam.describe_security_groups.return_value = {
    "SecurityGroups": [
        {
            "GroupId": "sg-0d157c9f9c7004ba1",
            "GroupName": "tesSecuritygroup",
            
            # Inbound Rule: Allow SSH (port 22) from anywhere
            "IpPermissions": [
                {
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]  # Allow SSH from any IP
                }
            ]
        }
    ]
}

	result = get_security_groups()

	assert len(result) == 1
	assert "Public access detected, Critical!" in result[0]["Risk"]
	mock_iam.describe_security_groups.assert_called_once()


def test_sg_High_open_port(mocker):
    mock_boto = mocker.patch("Scanner.SG.boto3.client")
    mock_iam = mock_boto.return_value
    mock_iam.describe_security_groups.return_value = {
    "SecurityGroups": [
        {
            "GroupId": "sg-0d157c9f9c7004ba2",
            "GroupName": "tesSecuritygrouP",
            
            # Inbound Rule: Allow SSH (port 22) from anywhere
            "IpPermissions": [
                {
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]  # Allow SSH from any IP
                }
            ]
        }
    ]
}

    result = get_security_groups()

    assert len(result) == 1
    assert "Public access detected, High!" in result[0]["Risk"]
    mock_iam.describe_security_groups.assert_called_once()

def test_sg_Medium_open_port(mocker):
    mock_boto = mocker.patch("Scanner.SG.boto3.client")
    mock_iam = mock_boto.return_value
    mock_iam.describe_security_groups.return_value = {
    "SecurityGroups": [
        {
            "GroupId": "sg-0d157c9f9c7004ba2",
            "GroupName": "tesSecuritygrouP",
            
            # Inbound Rule: Allow SSH (port 22) from anywhere
            "IpPermissions": [
                {
                    "FromPort": 100,
                    "ToPort": 100,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]  # Allow SSH from any IP
                }
            ]
        }
    ]
}

    result = get_security_groups()

    assert len(result) == 1
    assert "Public access detected, Medium" in result[0]["Risk"]
    mock_iam.describe_security_groups.assert_called_once()
