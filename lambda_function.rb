require 'json'
require 'aws-sdk-securityhub'

def lambda_handler(event:, context:)

  # Initialise our ASFF object
  # asff = {}
  # asff['SchemaVersion'] = '2018-10-08'
  # asff['Id'] = "Chef-Automate/"

  body = event['body']
  body = JSON.parse(body) if body.class == String
  report = body['report']

  shclient = Aws::SecurityHub::Client.new
  aws_account_id = event['requestContext']['accountId']

  puts "Message from #{event['requestContext']['identity']['sourceIp']}"
  puts "AWS Account ID #{aws_account_id}"

  if report.nil?
    puts "Invalid message: #{body}"
  else
    report_timestamp = Time.at(report['end_time']['seconds']).iso8601
    report_timestamp = report_timestamp.to_s
    node_name = report['node_name']
    node_id = report['node_id']
    chef_server = report['chef_server']
    chef_org = report['chef_organization']
    
    puts "Report ID #{report['id']}"
    puts "Chef server #{chef_server} organisation #{chef_org}"
    puts "Node ID #{node_id}"
    puts "Node Name #{node_name}"
    puts "Report timestamp #{report_timestamp}"

    report['profiles'].each do |profile|
      puts "Processing profile #{profile['name']}"
      findings = []

      profile['controls'].each do |control|

        # An array of findings to be sent to AWS Security Hub
        control_failed=false
        control['results'].each do |result|
          if result['status'] == "failed"
            control_failed = true
          end
        end unless control['results'].nil?

        if control_failed  
          finding = {
            schema_version: "2018-10-08",
            id: "#{profile['name']} #{control['id']}",
            product_arn: "arn:aws:securityhub:eu-west-2:#{aws_account_id}:product/#{aws_account_id}/default",
            generator_id: "Inspec #{profile['name']}",
            aws_account_id: "#{aws_account_id}",
            types: ["Other"],
            last_observed_at: report_timestamp,
            created_at: report_timestamp,
            updated_at: report_timestamp,
            severity: {
              label: "HIGH", # accepts INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
            },
            title: "#{profile['name']} - #{control['id']}",
            description: "#{profile['name']} - #{control['id']}",
            resources: [
              type: "Other",
              id: "#{chef_server}/#{chef_org}/#{node_name}",
              partition: "aws",
              region: "eu-west-1",
            ],
            workflow: {
              status: "NEW"
            }
          }
          findings << finding
        end
      end unless profile['controls'].nil?
      if findings.length > 0
        puts "Sending #{findings.length} results"
        puts shclient.batch_import_findings(findings: findings)
      end
    end
  end
  
  { statusCode: 200, body: JSON.generate(result:'Success') }
end
