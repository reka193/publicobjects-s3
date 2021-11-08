# publicobjects-s3

This project was built to detect public objects in non-public S3 buckets. 

Without the 'block all public access' feature, even if a bucket is not configured as public, it is possible to create public objects within that bucket. With the help of this script, these objects can be identified and an email notification will be triggered - using the Simple Email Service (SES) from AWS.

Prerequisites:
1. In the account which you would like to scan, you need to create a role with the following IAM policy attached:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": [
                "s3:GetBucketPolicyStatus",
                "s3:GetObjectAcl",
                "s3:ListAllMyBuckets",
                "s3:ListBucket",
                "s3:GetBucketLocation",
                "s3:GetAccountPublicAccessBlock",
                "s3:GetBucketPublicAccessBlock"
            ],
            "Resource": "*"
        }
    ]
}
```
2. The IAM user or the instance profile where the script is run from, needs permissions to assume the above role (which might be in a different account).

(If two different accounts are used, don't forget to add the first account as a trusted entity.)

In the config file, you need to specify:

- email_address: the email address for notifications
- aws_account_number: the account to be scanned
- aws_monitoring_role_arn: the arn of the role that can be assumed with the necessary permissions                                                                                                          
  
