import boto3
import sys
import json
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime
from botocore.credentials import RefreshableCredentials
from botocore.credentials import InstanceMetadataProvider, InstanceMetadataFetcher
from botocore.session import get_session


class PublicObjectCheck:
    def __init__(self):
        self.config_data = load_config("config.json")
        self.session_credentials = RefreshableCredentials.create_from_metadata(
            metadata=self.refresh_credentials(),
            refresh_using=self.refresh_credentials,
            method="sts-assume-role"
        )
        self.session = self.set_session()
        self.file_results = open("./result_objects_{}.txt".format(self.config_data["account_id"]), "w")
        self.ses_client = boto3.client('ses', region_name=self.config_data["region_ses"])
        self.s3_client = self.session.client('s3', region_name=self.config_data["region_s3"])
        self.s3_resource = self.session.resource('s3', region_name=self.config_data["region_s3"])
        self.no_of_objects_checked = 0
        self.no_of_objects_checked_total = 0
        self.current_bucket = None
        self.file_start_after_object = open("./cont_tokens.txt", "w")
        self.current_region = None

    # Method to automatically refresh credentials after one hour
    def refresh_credentials(self):
        config_data = self.config_data
        params = {
            "RoleArn": config_data["role_arn"],
            "RoleSessionName": 'session',
            "DurationSeconds": 3600,
        }
        # Use credentials from instance metadata
        provider = InstanceMetadataProvider(iam_role_fetcher=InstanceMetadataFetcher(timeout=1000, num_attempts=2))
        instance_credentials = provider.load().get_frozen_credentials()

        client_external = boto3.client('sts', aws_access_key_id=instance_credentials.access_key,
                                       aws_secret_access_key=instance_credentials.secret_key,
                                       aws_session_token=instance_credentials.token)
        # Refresh credentials
        response = client_external.assume_role(**params).get("Credentials")
        credentials = {
            "access_key": response.get("AccessKeyId"),
            "secret_key": response.get("SecretAccessKey"),
            "token": response.get("SessionToken"),
            "expiry_time": response.get("Expiration").isoformat(),
        }
        return credentials

    # Method to set session and refresh credentials automatically
    def set_session(self):
        session = get_session()
        session._credentials = self.session_credentials
        aws_region = "us-east-1"
        session.set_config_variable("region", aws_region)
        auto_refresh_session = boto3.Session(botocore_session=session)
        return auto_refresh_session

    # Returns True if public access block is enabled on the account level, otherwise False
    def access_block_account_level(self):
        s3control = self.session.client('s3control')
        try:
            access_block = s3control.get_public_access_block(AccountId=self.config_data["account_id"])
            access_block = access_block['PublicAccessBlockConfiguration']
            if access_block['IgnorePublicAcls'] and access_block['RestrictPublicBuckets']:
                return True
        except:
            return False

    # Returns True if public access block is enabled on the bucket level, otherwise False
    def access_block_bucket_level(self, bucket):
        try:
            access_block = self.s3_client.get_public_access_block(Bucket=bucket)
            access_block = access_block['PublicAccessBlockConfiguration']
            if access_block['IgnorePublicAcls'] and access_block['RestrictPublicBuckets']:
                return True
        except:
            return False

    # Method to run the public object check
    def s3_public_object_check(self):
        # Check public access block on the account level
        if self.access_block_account_level():
            print("Public access block is enabled for the account {}, no buckets/objects can be public.\n".format(self.config_data["account_id"]))
            self.file_results.write("Public access block is enabled on the account level, no buckets/objects can be public.\n")
            return

        buckets = self.s3_client.list_buckets()['Buckets']
        for bucket in buckets:
            bucket_name = bucket['Name']
            print("Checking {}...".format(bucket_name))
            self.file_results.write("Checking {}...\n".format(bucket_name))
            self.file_start_after_object.write("Next bucket: {}\n".format(bucket_name))
            self.current_bucket = bucket_name
            self.no_of_objects_checked = 0

            self.current_region = self.s3_client.get_bucket_location(Bucket=bucket_name)['LocationConstraint']

            kwargs = {'Bucket': bucket_name}
            while True:
                keys = []
                resp = self.s3_client.list_objects_v2(**kwargs)
                try:
                    for obj in resp['Contents']:
                        keys.append(obj['Key'])
                except KeyError:
                    print("Bucket is empty.")

                executor = concurrent.futures.ThreadPoolExecutor(10)
                futures = [executor.submit(self.one_object_check, item) for item in keys]
                concurrent.futures.wait(futures)

                try:
                    kwargs['ContinuationToken'] = resp['NextContinuationToken']
                except KeyError:
                    break

            print("{} objects checked in bucket {}".format(self.no_of_objects_checked, bucket_name))
            self.file_results.write("{} objects checked in bucket {}\n".format(self.no_of_objects_checked, bucket_name))
            self.no_of_objects_checked_total += self.no_of_objects_checked

    def one_object_check(self, key):
        if key[-1] == "/":
            return
        self.no_of_objects_checked += 1
        if self.no_of_objects_checked % 10000 == 0:
            now = datetime.now()
            print("{} objects checked at {}".format(self.no_of_objects_checked, now))
            self.file_results.write("{} objects checked at {}\n".format(self.no_of_objects_checked, now))
            self.file_start_after_object.write(str(key) + "\n")
        try:
            acl = self.s3_resource.ObjectAcl(self.current_bucket, key)
            try:
                for grant in acl.grants:
                    try:
                        grantee = grant['Grantee']
                        permission = grant['Permission']
                        uri = grantee['URI']
                        if uri.endswith('/AllUsers'):
                            # need to be changed to send notification
                            print("yes, bucket ACL makes it public")
                            url = "https://{}.s3.amazonaws.com/{}".format(self.current_bucket, key)
                            message = "You have received this message because a new public object has been " \
                                      "inspected in an AWS account, please, verify if it's accessible from the internet.\n\n" \
                                      "Account ID: {}\n" \
                                      "Bucket name: {}\n" \
                                      "Object name: {}\n" \
                                      "URL: {}\n" \
                                      "Permission: {}".format(self.config_data["account_id"], self.current_bucket, key, url,
                                                              permission)
                            subject = "Public object [{}] in [{}] AWS account".format(key,
                                                                                      self.config_data["account_id"])
                            self.send_mail(message=message, subject=subject)
                    except KeyError:
                        pass
            except AttributeError:
                pass
        except Exception as err:
            print(err)

    # Method to send emails, message and subject need to be specified
    def send_mail(self, message, subject):
        email = self.config_data["email"]
        sender = "AWS Notification <{}>".format(email)
        recipient = email

        try:
            # Provide the contents of the email.
            response = self.ses_client.send_email(
                Destination={
                    'ToAddresses': [
                        recipient,
                    ],
                },
                Message={
                    'Body': {
                        'Text': {
                            'Charset': 'UTF-8',
                            'Data': message,
                        },
                    },
                    'Subject': {
                        'Charset': 'UTF-8',
                        'Data': subject,
                    },
                },
                Source=sender,
            )
        except ClientError as e:
            print(e.response['Error']['Message'])
        else:
            print("Email sent! Message ID:"),
            print(response['MessageId'])


# Function to load data from config file
def load_config(config_file):
    try:
        with open(config_file, 'r') as file:
            try:
                config_json = json.load(file)
                config_data = {"email": config_json["email_address"], "account_id": config_json["aws_account_number"],
                               "role_arn": config_json["aws_monitoring_role_arn"]}
                return config_data
            except Exception as e:
                print("Error parsing config file: {}".format(e))
                sys.exit()
    except IOError:
        print("Config file not found! (config.json)")
        sys.exit()


def main():
    # Load config file data // If changed, change in refresh_credentials() as well!!
    object_check = PublicObjectCheck()

    print('The starting time is:')
    print(datetime.now())
    object_check.file_results.write('The starting time is: ' + str(datetime.now()) + '\n')
    object_check.s3_public_object_check()
    print('Finished at:')
    print(datetime.now())
    object_check.file_results.write('Finished at: ' + str(datetime.now()) + '\n')
    print("In total {} objects checked in account {}.".format(object_check.no_of_objects_checked_total, object_check.config_data["account_id"]))
    object_check.file_results.write("In total {} objects checked in account {}.\n".format(object_check.no_of_objects_checked_total, object_check.config_data["account_id"]))


if __name__ == "__main__":
    main()

