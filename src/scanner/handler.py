import json
import boto3
import os
from datetime import datetime, timezone

ec2 = boto3.client('ec2')
s3 = boto3.client('s3')
iam = boto3.client('iam')
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')
TABLE_NAME = os.environ['TABLE_NAME']
TOPIC_ARN = os.environ['TOPIC_ARN']

def lambda_handler(event, context):
    table = dynamodb.Table(TABLE_NAME)
    findings = []
    scan_date = datetime.now(timezone.utc).isoformat()
    sgs = ec2.describe_security_groups()['SecurityGroups']
    for sg in sgs:
        for rule in sg.get('IpPermissions', []):
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    port = rule.get('FromPort', 'All')
                    findings.append({'findingId': 'SG-' + sg['GroupId'] + '-' + str(port), 'scanDate': scan_date, 'type': 'OPEN_SECURITY_GROUP', 'severity': 'HIGH' if port in [22, 3389] else 'MEDIUM', 'resource': sg['GroupId'], 'detail': 'Port ' + str(port) + ' open to 0.0.0.0/0'})
    buckets = s3.list_buckets().get('Buckets', [])
    for bucket in buckets:
        try:
            acl = s3.get_bucket_acl(Bucket=bucket['Name'])
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    findings.append({'findingId': 'S3-' + bucket['Name'], 'scanDate': scan_date, 'type': 'PUBLIC_S3_BUCKET', 'severity': 'HIGH', 'resource': bucket['Name'], 'detail': 'Bucket has public ACL'})
        except Exception:
            pass
    users = iam.list_users().get('Users', [])
    for user in users:
        keys = iam.list_access_keys(UserName=user['UserName']).get('AccessKeyMetadata', [])
        for key in keys:
            age = (datetime.now(timezone.utc) - key['CreateDate']).days
            if age > 90:
                findings.append({'findingId': 'IAM-' + key['AccessKeyId'], 'scanDate': scan_date, 'type': 'OLD_ACCESS_KEY', 'severity': 'MEDIUM', 'resource': user['UserName'], 'detail': 'Access key is ' + str(age) + ' days old'})
    for finding in findings:
        table.put_item(Item=finding)
    if findings:
        report = 'Security Scan Report - ' + scan_date + '

Findings: ' + str(len(findings)) + '

'
        for f in findings:
            report = report + '[' + f['severity'] + '] ' + f['type'] + ' - ' + f['resource'] + ': ' + f['detail'] + '
'
    else:
        report = 'Security Scan Report - ' + scan_date + '

No issues found. All clear!'
    sns.publish(TopicArn=TOPIC_ARN, Subject='AWS Security Scan Report', Message=report)
    return {'statusCode': 200, 'body': json.dumps({'findings': len(findings)})}
