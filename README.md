# AwsSecurityHubAutomateIntegration

An AWS Lambda function that sends data received from Chef Automate Data Tap to AWS Security Hub

Install it behind an API gateway and set the calling security appropriately for your environment.
It can be set to run with no authentication, but you SHOULD probably restrict it to just your A2 server.

## AWS IAM setup to allow Lambda to operate

The Lambda itself needs rights to write logs and send data to the security hub.

```
{
  "Version": "2012-10-17",
  "Statement": [
     {
       "Effect": "Allow",
       "Action": [
         "logs:CreateLogStream",
         "logs:CreateLogGroup",
         "logs:PutLogEvents",
         "securityhub:BatchImportFindings"
       ],
       "Resource": "*"
     }
   ]
}
```
