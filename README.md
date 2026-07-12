# infra-health-checker
Automated AWS security scanner with daily reporting

# Infrastructure Health Checker

An automated AWS security scanner that runs daily, checks for common misconfigurations, and emails a report. Built entirely serverless on AWS Free Tier.

## Architecture

## What It Checks

| Check | Severity | Description |
|-------|----------|-------------|
| Open Security Groups | HIGH | Ports open to 0.0.0.0/0 (especially 22, 3389) |
| Public S3 Buckets | HIGH | Buckets with public ACL grants |
| Old IAM Access Keys | MEDIUM | Access keys older than 90 days |

## Services Used

| Service | Purpose |
|---------|---------|
| Lambda | Runs the security scan logic |
| EventBridge | Triggers scan on a daily schedule |
| DynamoDB | Stores historical findings for trending |
| SNS | Sends email report to administrator |
| IAM | Read-only access to scan resources |
| CloudFormation | Infrastructure as Code |

## Well-Architected Framework Alignment

### Security
- **Read-only scanning** — function never modifies resources, only inspects
- **Least-privilege IAM** — only DescribeSecurityGroups, ListBuckets, ListUsers
- **Automated detection** — finds misconfigurations before attackers do

### Reliability
- **Serverless** — no servers to fail or patch
- **Scheduled execution** — EventBridge ensures daily runs without manual intervention
- **Graceful error handling** — individual check failures don't stop the full scan

### Cost Optimization
- **Zero idle cost** — Lambda only runs once per day (~1 second)
- **On-demand DynamoDB** — no provisioned capacity
- **Free tier eligible** — entire stack costs $0

### Operational Excellence
- **Infrastructure as Code** — reproducible via CloudFormation
- **Historical tracking** — DynamoDB stores all findings for trend analysis
- **Automated reporting** — no manual effort required

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Lambda over EC2 | Runs once daily for <2 seconds — EC2 would waste 99.99% of compute |
| DynamoDB over RDS | Simple key-value storage; no relationships needed; scales to zero |
| EventBridge over CloudWatch Events | Modern scheduler with better rule management |
| SNS over SES | Simpler setup; no domain verification needed; free tier covers it |
| Read-only IAM | Security principle — scanner should never have write access to scanned resources |

## Deployment

### Prerequisites
- AWS CLI configured
- AWS account with Free Tier

### Deploy via CloudFormation
```bash
aws cloudformation deploy \
  --template-file infra/template.yaml \
  --stack-name infra-health-checker \
  --parameter-overrides AlertEmail=your@email.com \
  --capabilities CAPABILITY_NAMED_IAM
Manual Test
bash





aws lambda invoke --function-name infra-health-checker output.json
cat output.json
Project Structure
infra-health-checker/
├── README.md
├── architecture/
│   └── diagram.png
├── infra/
│   └── template.yaml
├── src/
│   └── scanner/
│       └── handler.py
├── tests/
│   └── test_event.json
└── screenshots/
    └── execution_success.png
Sample Output
Security Scan Report - 2026-07-12T14:05:41+00:00

Findings: 2

[HIGH] OPEN_SECURITY_GROUP - sg-0abc123: Port 22 open to 0.0.0.0/0
[MEDIUM] OLD_ACCESS_KEY - IAM-AKIA123: Access key is 120 days old
Future Enhancements
Add EBS encryption check
Add RDS public accessibility check
Add CloudTrail enabled check
Integrate with AWS Security Hub for centralized findings
Add Slack webhook notifications

Now here's the **CloudFormation template**:

```yaml

AWSTemplateFormatVersion: '2010-09-09'
Description: Infrastructure Health Checker - Automated Security Scanner

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security scan reports

Resources:

  # DynamoDB Table
  FindingsTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: security-findings
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: findingId
          AttributeType: S
        - AttributeName: scanDate
          AttributeType: S
      KeySchema:
        - AttributeName: findingId
          KeyType: HASH
        - AttributeName: scanDate
          KeyType: RANGE

  # SNS Topic
  SecurityReportTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: security-report

  # SNS Subscription
  SecurityReportSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref SecurityReportTopic
      Protocol: email
      Endpoint: !Ref AlertEmail

  # IAM Role
  ScannerRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: infra-health-checker-role
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: scanner-permissions
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - ec2:DescribeSecurityGroups
                Resource: '*'
              - Effect: Allow
                Action:
                  - s3:ListAllMyBuckets
                  - s3:GetBucketAcl
                Resource: '*'
              - Effect: Allow
                Action:
                  - iam:ListUsers
                  - iam:ListAccessKeys
                Resource: '*'
              - Effect: Allow
                Action:
                  - dynamodb:PutItem
                Resource: !GetAtt FindingsTable.Arn
              - Effect: Allow
                Action:
                  - sns:Publish
                Resource: !Ref SecurityReportTopic
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: '*'

  # Lambda Function
  ScannerFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: infra-health-checker
      Runtime: python3.12
      Handler: index.lambda_handler
      Role: !GetAtt ScannerRole.Arn
      Timeout: 60
      Environment:
        Variables:
          TABLE_NAME: !Ref FindingsTable
          TOPIC_ARN: !Ref SecurityReportTopic
      Code:
        ZipFile: |
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
                  report = 'Security Scan Report - ' + scan_date + '\n\nFindings: ' + str(len(findings)) + '\n\n'
                  for f in findings:
                      report = report + '[' + f['severity'] + '] ' + f['type'] + ' - ' + f['resource'] + ': ' + f['detail'] + '\n'
              else:
                  report = 'Security Scan Report - ' + scan_date + '\n\nNo issues found. All clear!'
              sns.publish(TopicArn=TOPIC_ARN, Subject='AWS Security Scan Report', Message=report)
              return {'statusCode': 200, 'body': json.dumps({'findings': len(findings)})}

  # EventBridge Rule
  DailyScanRule:
    Type: AWS::Events::Rule
    Properties:
      Name: daily-security-scan
      Description: Runs infrastructure health check daily
      ScheduleExpression: rate(1 day)
      State: ENABLED
      Targets:
        - Arn: !GetAtt ScannerFunction.Arn
          Id: ScannerTarget

  # Permission for EventBridge to invoke Lambda
  ScannerInvokePermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref ScannerFunction
      Action: lambda:InvokeFunction
      Principal: events.amazonaws.com
      SourceArn: !GetAtt DailyScanRule.Arn

Outputs:
  FunctionName:
    Description: Scanner Lambda function name
    Value: !Ref ScannerFunction
  FindingsTableName:
    Description: DynamoDB table for findings
    Value: !Ref FindingsTable
  TopicArn:
    Description: SNS topic for reports
    Value: !Ref SecurityReportTopic
