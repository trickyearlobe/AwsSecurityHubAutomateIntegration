# AwsSecurityHubAutomateIntegration

This project provides an AWS Lambda function that sends data received from the Chef Automate Data Tap to the AWS Security Hub. In the process, it converts the data from Automate data export format to [ASFF](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html) format.
## Basic flow
1. Create an AWS Lambda function with the code from [lambda_function.rb](lambda_function.rb)
2. Set up an IAM role to allow the Lambda to call SecurityHub functions.
3. Create an AWS API Gateway to expose the Lambda function over HTTPS
4. Set up ENV variables for HTTP basic auth and optionally, an proxy
5. Add the AWS API Gateway URL to a Chef Automate Data Tap
6. Adjust the settings of the `data-feed-service` to increase frequency and reduce request sizes
7. View the Chef Infrastructure and Compliance Data in the AWS Security Hub

## Creating the empty Lambda function

* Open the AWS Lambda console
* select create function - author from scratch
* Fill out the details as shown and click save

![Lambda Setup](images/lambda-setup.png "Lambda Setup")

## Adding the Lambda code

* Scroll down your lambda definition until you find the `function code` section
* Add the code from ([lambda_function.rb](lambda_function.rb)) in the code editor as shown

![Lambda Code](images/ruby-lambda-function.png "Lambda Function")

## Adding the IAM role/policy to the Lambda function
* Add a Policy to the Lambda's role to allow logging and reporting findings to the AWS Security Hub.
* Select the `Permissions` tab and click the existing link under `role name`.

![Role](images/role.png "Role")

* Click `Attach policies` Button, then `Create policy`

![Attach policies](images/attach_policies.png "Attach policies")

* Add this policy using the json editor

``` json
{
  "Version": "2012-10-17",
  "Statement": [
     {
       "Effect": "Allow",
       "Action": [
         "logs:CreateLogStream",
         "logs:CreateLogGroup",
         "logs:PutLogEvents",
         "securityhub:UpdateFindings",
         "securityhub:BatchUpdateFindings",
         "securityhub:BatchImportFindings"
       ],
       "Resource": "*"
     }
   ]
}
```

Click `Review policy`  
Click `Create policy`  
![Create policy](images/create_policy.png "Create policy")

Search for your newly created policy attach it to your role  
![Attach new policy](images/attach_new_policy.png "Attach new policy")

## Creating an AWS API Gateway Configuration

Create new API Gateway
![Create API](images/create_api.png "Create API")

Select a `Rest API` and `build`  
![Build API](images/build_rest.png "Build API")

Configure as shown below and click `Create API`
![Configure API](images/configure_api.png "Configure API")

Select `Actions`, then Create Resource as below, click `Create Resource`
![Create Resource](images/create_resource.png "Create Resource")

With the resource selected create a new method, select `ANY` and then tick the tick, as below:
![Create Method](images/create_method.png "Create Method")

Fill in the Lambda details and hit save:
![Connect Lambda](images/connect_to_lambda.png "Connect Lambda")  
Say Ok to allow the gateway to have the permission to call your Lambda function.  

Test your method if you want, you may see an error from the Lambda code, that is expected as there is no input data to work on, we will supply that later.  

Deploy your new API:  
![Deploy API](images/deploy_api.png "Deploy API")

Create a new Deploy stage:  
![New Deploy Stage](images/new_deploy_stage.png "New Deploy Stage")

Call it `dev` and hit `Deploy`
![Deploy Dev](images/deploy_dev.png "Deploy Stage Dev")

Select your stage and your resource and any of the methods (we choose to support ANY method to call our Lambda function in our setup). You can see the URL required to invoke the API, make a copy ot it.
![Resource URL](images/resource_url.png "Resoruce URL")

## Add environment variables for HTTP basic auth and (optionally) proxy

| Variable | Purpose
|--------- |-----------------------------------------------------------------------------------------------------------------------|
| A2USER   | The user ID you will use for the Automate data tap                                                                    |
| A2PASS   | The password you will use for the Automate data tap                                                                   |
| PROXY    | An optional URL if your Lambda function needs a proxy to access Security Hub (http://user:pass@fqdn:port)             |
|    |    |


## Create a Data Tap in Chef Automate

* Open your browser up and go to Chef Automate and select the `settings` tab -> `Data Feeds`. If the menu item is not there then you may need to upgrade Chef Automate to a recent version.
![Data Feed](images/data_feed.png "Data Feed")

* Click `Create Data Feed` and fill in as below. Use the credentials you put in A2USER and A2PASS environment variables.

* Click `Create Data Feed`
![Data Feed Details](images/data_feed_details.png "Data Feed Details")

* Test your data feed, you should get a postive reply if all is set up properly

## Adjust the settings of the data-feed-service

This step is necessary to make sure that compliance reports fit into the size limites for AWS Lambda and AWS Security Hub.

First, create a `data-feed.toml` configuration file (the name doesn't actually matter). It should set the batch size low (currently 1 recommended) and the interval relatively short (currently 2m recommended).

``` toml
[data_feed_service]
  [data_feed_service.v1]
    [data_feed_service.v1.sys]
      [data_feed_service.v1.sys.service]
        feed_interval = "2m"
        node_batch_size = 1
        updated_nodes_only = false
        disable_cidr_filter = true
        cidr_filter = "0.0.0.0/0"
        accepted_status_codes = [200, 201, 202, 203, 204]
      [data_feed_service.v1.sys.log]
        level = "info"
```

Apply the configuration to chef automate

``` bash
chef-automate config patch data-feed.toml
```

## View the Compliance data in the AWS Security hub.

Add a filter on `Generator ID` of `Inspec` as shown below:
![AWS Security Hub](images/security_hub.png "AWS Security Hub")
