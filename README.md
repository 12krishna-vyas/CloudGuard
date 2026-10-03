# AWS CloudGuard — Cloud Cost & Security Auditor

CloudGuard is a Python-based AWS auditing tool that checks AWS resources for common **security risks** and **unnecessary cloud costs**.

It can run locally, inside Docker, or as a scheduled Kubernetes CronJob.

## What CloudGuard Checks

CloudGuard performs 8 read-only checks:

- Unattached EBS volumes
- Unused Elastic IPs
- Stopped EC2 instances
- Old EBS snapshots
- Security groups allowing SSH/RDP from the internet
- Public S3 buckets
- IAM users without MFA
- Access keys older than 90 days

The scanner does not automatically modify or delete AWS resources.

## Architecture

```text
                         AWS ACCOUNT
                              |
        +---------------------+----------------------+
        |                     |                      |
       EC2                   EBS                    S3
        |              Volumes / Snapshots           |
        |                     |                      |
        +---------------------+----------------------+
                              |
                       IAM / Security Groups
                              |
                              v
                  +-----------------------+
                  |  CloudWatchdog Scanner |
                  |   Python + boto3       |
                  +-----------+-----------+
                              |
                 +------------+------------+
                 |                         |
                 v                         v
        +------------------+       +------------------+
        |    DynamoDB      |       |       SNS        |
        | CloudWatchdog    |       | CloudGuardAlerts |
        |    Findings      |       +--------+---------+
        +------------------+                |
                                            v
                                         Email

                 Kubernetes / Minikube
                         |
                    CronJob
                  Every 5 minutes
                         |
                  Docker Container
                         |
                  CloudWatchdog Scanner

              Secret       ConfigMap
                |             |
          AWS credentials   AWS settings

              NGINX Dashboard
                     |
               Kubernetes Service
```

## AWS Services Used

### IAM

A dedicated `cloudguard-scanner` IAM user is used with a least-privilege policy for the required read operations and for writing findings to DynamoDB and publishing notifications through SNS.

### DynamoDB

Findings are stored in:

`CloudWatchdogFindings`

Each finding contains information such as severity, finding type, resource and estimated waste.

### SNS

The scanner publishes the report to:

`CloudGuardAlerts`

An email subscription is used to receive the scan results.

### EC2 / EBS

CloudGuard checks for:

- Unused Elastic IPs
- Stopped EC2 instances
- Unattached EBS volumes
- Old snapshots

### S3

CloudGuard checks whether S3 buckets have public access enabled.

### IAM

CloudGuard checks:

- Users without MFA
- Old access keys

### Security Groups

CloudGuard checks for SSH/RDP access that is open to the public internet.

## Docker

The scanner is packaged as a Docker image.

Build the image:

```bash
docker build -t cloudguard .
```

Run a dry scan:

```bash
docker run --rm \
-v ~/.aws:/root/.aws:ro \
-e AWS_REGION=ap-south-1 \
-e DRY_RUN=true \
cloudguard
```

For an actual scan:

```bash
docker run --rm \
-v ~/.aws:/root/.aws:ro \
-e AWS_REGION=ap-south-1 \
-e DRY_RUN=false \
-e SNS_TOPIC_ARN="YOUR_SNS_TOPIC_ARN" \
cloudguard
```

## Kubernetes

CloudGuard is scheduled using a Kubernetes CronJob.

The current schedule is:

```text
*/5 * * * *
```

This runs the scanner every 5 minutes.

Kubernetes components used:

- CronJob — schedules the scanner
- Job — represents each scanner execution
- Pod — runs the scanner container
- Secret — stores AWS credentials
- ConfigMap — stores application configuration
- Deployment — runs the dashboard
- Service — exposes the dashboard

Apply the scanner CronJob:

```bash
kubectl apply -f cronjob.yaml
```

Check the CronJob:

```bash
kubectl get cronjob
```

Check scanner Jobs:

```bash
kubectl get jobs
```

Check Pods:

```bash
kubectl get pods
```

View scanner logs:

```bash
kubectl logs <pod-name>
```

## Dashboard

A simple NGINX dashboard is deployed using Kubernetes.

Apply the Deployment:

```bash
kubectl apply -f dashboard-deployment.yaml
```

Apply the Service:

```bash
kubectl apply -f dashboard-service.yaml
```

Check the Service:

```bash
kubectl get service
```

For Minikube:

```bash
minikube service cloudguard-dashboard --url
```

## Security

CloudGuard follows a read-only auditing approach.

- AWS credentials are not stored inside the Docker image.
- Kubernetes credentials are provided through a Secret.
- Configuration is provided through a ConfigMap.
- The scanner does not automatically delete or modify AWS resources.
- AWS access is controlled using IAM permissions.

## Project Structure

```text
CloudGuard/
│
├── scanner.py
├── requirements.txt
├── Dockerfile
├── cronjob.yaml
├── dashboard-deployment.yaml
└── dashboard-service.yaml
```

## Example Scan Result

Example findings detected during testing:

```text
Findings: 3
Estimated waste: $4.05/month

[HIGH] user_without_mfa
[MEDIUM] unused_elastic_ip
[LOW] old_snapshot
```

## Technologies Used

- Python
- Boto3
- AWS
- DynamoDB
- SNS
- IAM
- EC2
- EBS
- S3
- Docker
- Kubernetes
- Minikube
- Git & GitHub

## Git Workflow

The project is managed using Git and GitHub.

Basic workflow:

```bash
git init
git add .
git commit -m "Initial CloudGuard project"
git remote add origin <repository-url>
git push -u origin master
```

## Purpose

The goal of CloudGuard is to demonstrate practical knowledge of:

- AWS resource auditing
- IAM and least-privilege access
- Cost-awareness
- Python automation with boto3
- Docker containerization
- Kubernetes scheduling
- Kubernetes Secrets and ConfigMaps
- AWS notifications using SNS
- Git and GitHub version control
- Basic cloud monitoring and troubleshooting
