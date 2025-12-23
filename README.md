

# Automated AWS Access Review System

**AI-Enhanced Alerts | Cloud Security Automation**

## Project Overview

The **Automated AWS Access Review System** is a cloud security automation project designed to audit AWS IAM users, roles, and permissions. It continuously evaluates access usage, identifies security risks, and generates actionable alerts and reports.

This project demonstrates **real-world cloud security practices**, including least privilege enforcement, automated compliance checks, and serverless architecture using AWS managed services.

---

## Key Features

*  Detects **unused IAM users and roles**
*  Identifies **overly permissive policies** (e.g., `AdministratorAccess`)
*  Generates **CSV and JSON access review reports**
*  Sends **email alerts via Amazon SNS**
*  Fully automated using **AWS Lambda and CloudWatch Events**
*  Stores audit reports securely in **Amazon S3**

---

## Architecture Overview

### System Flow

1. **AWS CloudTrail** logs IAM activity and stores logs in **Amazon S3**
2. **AWS Lambda** analyzes IAM users, roles, and attached policies
3. Risk findings and alerts are generated
4. **Amazon SNS** sends alert notifications via email
5. Audit reports are saved to **Amazon S3**
6. **CloudWatch Events** trigger Lambda on a scheduled basis

> This architecture is fully serverless, scalable, and optimized for AWS Free Tier usage.

---

## Technologies Used

### Cloud Services

* AWS IAM
* AWS Lambda
* AWS CloudTrail
* Amazon S3
* Amazon SNS
* Amazon CloudWatch Events

### Programming & Tools

* Python
* Boto3 (AWS SDK for Python)
* JSON / CSV reporting

---

## Skills Demonstrated

| Cloud      | Automation            | Security                    |
| ---------- | --------------------- | --------------------------- |
| AWS IAM    | Python & Boto3        | Least Privilege Enforcement |
| CloudTrail | Lambda Functions      | Policy Risk Analysis        |
| S3         | CloudWatch Events     | Access Reporting            |
| SNS        | Serverless Automation | Compliance Awareness        |

---

## Implementation Highlights

* **Lambda Functions**

  * Enumerate IAM users, roles, and policies
  * Detect unused identities based on activity logs
  * Identify high-risk and overly permissive permissions

* **Automated Reporting**

  * Generates structured **CSV and JSON reports**
  * Stores audit results in S3 for historical tracking

* **Alerting System**

  * Sends email notifications via SNS when risky access is detected

---

## How It Works

1. CloudWatch triggers the Lambda function on a schedule
2. Lambda analyzes IAM configurations and usage patterns
3. Risk scores and alerts are generated
4. Reports are stored in S3
5. Security alerts are emailed to administrators

---

### Risk Factors & Weights

| Risk Factor            | Condition                      | Score |
| ---------------------- | ------------------------------ | ----- |
| Unused Identity        | No activity in last 90 days    | +75   |


---

## Risk Levels

| Score  | Risk Level | Action           |
| ------ | ---------- | ---------------- |
| 0–29   | Low        | Monitor          |
| 30–59  | Medium     | Review           |
| 60–79  | High       | Investigate      |
| 80–100 | Critical   | Immediate action |

---


## Author

**Kurtes Allen**
GitHub: [https://github.com/kurtesallen](https://github.com/kurtesallen)
