from aws_cdk import (
    Stack,
    Duration,
    CfnOutput,
    aws_lambda as _lambda,
    aws_s3 as s3,
    aws_sns as sns,
    aws_sns_subscriptions as subscriptions,
    aws_events as events,
    aws_events_targets as targets,
    aws_iam as iam,
    RemovalPolicy,
    Tags,
)
from constructs import Construct


class AccessReviewStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # S3 bucket for CSV reports and alert state
        report_bucket = s3.Bucket(
            self,
            "AccessReportBucket",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        # SNS topic for summary email
        alert_topic = sns.Topic(
            self,
            "IAMAlertTopic",
            display_name="IAM Access Review Alerts",
        )

        # Subscribe an email address (replace with yours)
        alert_topic.add_subscription(
            subscriptions.EmailSubscription("name@mail.com")
        )

        # IAM Role for Lambda (least privilege)
        lambda_role = iam.Role(
            self,
            "AccessReviewLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Role for IAM access review Lambda",
        )

        # Basic Lambda execution permissions (logs)
        lambda_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole"
            )
        )

        # IAM: read-only to list users
        lambda_role.add_to_policy(
            iam.PolicyStatement(
                actions=["iam:ListUsers"],
                resources=["*"],
            )
        )

        # SNS: publish only to this topic
        lambda_role.add_to_policy(
            iam.PolicyStatement(
                actions=["sns:Publish"],
                resources=[alert_topic.topic_arn],
            )
        )
        # Allow listing the bucket (needed for GetObject existence checks)
        lambda_role.add_to_policy(
             iam.PolicyStatement(
            actions=["s3:ListBucket"],
            resources=[report_bucket.bucket_arn]
            )
        )

        

        # S3: write reports and read/write suppression state (scoped to bucket)
        lambda_role.add_to_policy(
            iam.PolicyStatement(
                actions=["s3:PutObject", "s3:GetObject"],
                resources=[f"{report_bucket.bucket_arn}/*"],
            )
        )

        # Lambda function
        fn = _lambda.Function(
            self,
            "AccessReviewLambda",
            runtime=_lambda.Runtime.PYTHON_3_11,
            handler="access_review.lambda_handler",
            code=_lambda.Code.from_asset("lambdas"),
            role=lambda_role,
            timeout=Duration.seconds(60),
            memory_size=256,
            environment={
                "REPORT_BUCKET": report_bucket.bucket_name,
                "SNS_TOPIC": alert_topic.topic_arn,
                "SUPPRESSION_DAYS": "7",
            },
        )

        # CloudWatch Events (EventBridge) schedule: daily at 00:00 UTC
        rule = events.Rule(
            self,
            "DailyIamAccessReviewRule",
            schedule=events.Schedule.cron(
                minute="0",
                hour="0",
            ),
        )
        rule.add_target(targets.LambdaFunction(fn))

        # Outputs
        CfnOutput(self, "ReportBucketName", value=report_bucket.bucket_name)
        CfnOutput(self, "AlertTopicArn", value=alert_topic.topic_arn)
        CfnOutput(self, "LambdaFunctionName", value=fn.function_name)

        # Optional tags for hygiene
        Tags.of(self).add("Project", "IamAccessReview")
        Tags.of(self).add("Owner", "YourName")
        Tags.of(self).add("Environment", "Demo")
