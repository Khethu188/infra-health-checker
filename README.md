# Infrastructure Health Checker

An automated AWS security scanner that runs daily, checks for common misconfigurations, and emails a report. Built entirely serverless on AWS Free Tier.

## Architecture
EventBridge (daily schedule) ↓ Lambda (scanner) ↓ DynamoDB (findings store) ↓ SNS (email report)


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
├── infra/
│   └── template.yaml
├── src/
│   └── scanner/
│       └── handler.py
├── tests/
│   └── test_event.json
└── screenshots/
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
Author
Khethukuthula Sabela
Cloud Support Associate | AWS Solutions Architect Associate | AWS AI Practitioner | CCNA
