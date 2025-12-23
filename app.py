#!/usr/bin/env python3
import aws_cdk as cdk

from iam_access_review.access_review_stack import AccessReviewStack


app = cdk.App()

AccessReviewStack(
    app,
    "IamAccessReviewStack",
    # You can set env here if you want to pin to an account/region
    # env=cdk.Environment(account="123456789012", region="us-east-1"),
)

app.synth()
