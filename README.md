# publicobjects-s3

This project was built to detect public objects in non-public S3 buckets. 

Without the 'block all public access' feature, even if a bucket is not configured as public, it is possible to create public objects within that bucket. With the help of this script, these objects can be identified and an email notification will be triggered - using the Simple Email Service (SES) from AWS.

