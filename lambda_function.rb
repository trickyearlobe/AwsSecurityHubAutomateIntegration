require 'json'
require 'aws-sdk-securityhub'
require 'base64'
require 'aws-sdk-secretsmanager'

def get_secret(secret_name)
  region_name = ENV['AWS_REGION']
  puts "Retrieving #{secret_name} creds from secrets manager in #{ENV['AWS_REGION']}"
  client = Aws::SecretsManager::Client.new(region: region_name)
  begin
    get_secret_value_response = client.get_secret_value(secret_id: secret_name)
  rescue Aws::SecretsManager::Errors::DecryptionFailure => e
    puts "Secrets Manager can't decrypt the protected secret text using the provided KMS key."
    raise
  rescue Aws::SecretsManager::Errors::InternalServiceError => e
    puts "An error occurred on the server side retrieving the secret"
    raise
  rescue Aws::SecretsManager::Errors::InvalidParameterException => e
    puts "You provided an invalid value for a parameter retrieving the secret"
    raise
  rescue Aws::SecretsManager::Errors::InvalidRequestException => e
    puts "You provided a parameter value that is not valid for the current state of the resource retrieving the secret"
    raise
  rescue Aws::SecretsManager::Errors::ResourceNotFoundException => e
    puts "We can't find the resource that you asked for retrieving the secret"
    raise
  else
    if get_secret_value_response.secret_string
      JSON.parse(get_secret_value_response.secret_string)
    else
      JSON.parse(Base64.decode64(get_secret_value_response.secret_binary))
    end
  end
end

class ComplianceReport
  def initialize(aws_account_id, report, node)
    @aws_account_id = aws_account_id
    @report = report
    @node = node
    @shclient = Aws::SecurityHub::Client.new(http_proxy:ENV['PROXY'])
  end

  def report
    @report
  end

  def node
    @node
  end

  def aws_account_id
    @aws_account_id
  end

  def node_name
    report['node_name']
  end

  def node_id
    report['node_id']
  end

  def report_timestamp
    Time.at(report['end_time']['seconds']).iso8601.to_s
  end

  def chef_server
    report['chef_server']
  end

  def chef_org
    report['chef_organization']
  end

  def report_id
    report['id']
  end

  def automate_server
    node['automate_fqdn']
  end

  def process_report
    puts "Compliance report for node #{node_name} from #{chef_server}/#{chef_org} reported via #{automate_server}"
    report['profiles'].each do |profile|
      process_profile(profile)
    end
  end

  def process_profile(profile)
    return unless profile['controls'] # Dont try process an empty control set
    puts "Processing profile #{profile['name']} with #{profile['controls'].length} controls"
    while profile['controls'].length > 0
      controls = profile['controls'].pop(100) # Respect AWS batch import limits
      findings = controls.map{ |control| finding_from_control(profile['name'], control)}
      success_updates = updates_from_findings(findings,"RESOLVED")
      failed_updates = updates_from_findings(findings,"NEW")
      
      puts "BatchImportFindings: #{@shclient.batch_import_findings(findings: findings)}"
      puts "RESOLVED BatchUpdateFindings: #{@shclient.batch_update_findings(success_updates)}" if success_updates[:finding_identifiers].length > 0
      puts "NEW      BatchUpdateFindings: #{@shclient.batch_update_findings(failed_updates)}" if failed_updates[:finding_identifiers].length > 0
    end
  end

  def finding_from_control(profile, control)
    # Handle long or missing control descriptions/impacts
    control['desc'] = control['id'] unless control['desc']
    control['desc'] = control['desc'][0...1000]+"...(truncated)" if control['desc'].length > 1024
    control['impact'] = 1 unless control['impact']
    # Construct an ASFF structure for AWS Security Hub
    finding = {
      schema_version: "2018-10-08",
      id: "#{profile} #{control['id']} #{node_id}",
      product_arn: "arn:aws:securityhub:#{ENV['AWS_REGION']}:#{aws_account_id}:product/#{aws_account_id}/default",
      generator_id: "Inspec #{profile}",
      aws_account_id: "#{aws_account_id}",
      types: ["Software and Configuration Checks/Industry and Regulatory Standards/CIS Host Hardening Benchmarks"],
      last_observed_at: report_timestamp,
      created_at: report_timestamp,
      updated_at: report_timestamp,
      severity: {
        normalized: control['impact'] * 100
      },
      title: "#{profile} #{control['id']}",
      description: control['desc'],
      source_url: "#{automate_server}/compliance/reports/nodes/#{node_id}",
      resources: [
        type: "Other",
        id: node_name,
        partition: "aws",
        region: ENV['AWS_REGION'],
      ],
      compliance: {
        status: control_status(control) # Control status is based on a result set
      },
      workflow: {
        status: control_status(control) == "PASSED" ? "RESOLVED" : "NEW"
      },
    }
  end

  def control_status(control)
    return "PASSED" unless control['results'] # Dont try process a control with no results
    if control['results'].map{ |result| result['status'] }.include? "failed"
      return "FAILED"
    else
      return "PASSED"
    end
  end

  def updates_from_findings(findings, status)
    {
      finding_identifiers: findings.select{
        |finding| finding[:workflow][:status]==status
      }.map{
        |finding| {id:finding[:id], product_arn:finding[:product_arn]}
      },
      workflow: { status: status }
    }
  end
end

# Check Basic Auth against ENV vars A2USER and A2PASS or AWS Secrets Manager
def authorized(authorization)
  if (ENV['SECRET_NAME'])
    creds = get_secret(ENV['SECRET_NAME'])
    calculated = "Basic " + Base64.encode64("#{creds['a2user'] || creds['A2USER']}:#{creds['a2pass'] || creds['A2PASS']}")
    return (authorization || "").strip == (calculated || "").strip
  end
  if (ENV['A2USER'] && ENV['A2PASS'])
    calculated = "Basic " + Base64.encode64("#{ENV['A2USER']}:#{ENV['A2PASS']}")
    return (authorization || "").strip == (calculated || "").strip
  end
  return false
end

#################################################################################
# This is the Lambda entry point that receives messages from A2 Data Tap
#################################################################################
def lambda_handler(event:, context:)
  statusCode = 200
  resultBody = JSON.pretty_generate(result:'Success')
  puts "Message packet arrived from #{event['requestContext']['identity']['sourceIp']}"

  # Check the Basic Auth credentials against A2USER and A2PASS in environment
  unless authorized(event['headers']['Authorization'])
    puts "Authorization failed"
    return { statusCode: 403, body: JSON.pretty_generate(result:"Dismal failure", reason: "Invalid credentials") }
  end

  body = event['body']
  aws_account_id = event['requestContext']['accountId']
  # The body may contain more than one report delimited by line breaks
  puts "Packet contains #{body.lines.length} messages"
  body.lines.each do |json_message|
    message = JSON.parse(json_message)
    if message['report']
      ComplianceReport.new(aws_account_id, message['report'], message['node']).process_report
    elsif (message['text'] && message['text']=="TEST: Successful validation completed by Automate")
      puts "Received a connecton test from Chef Automate"
    elsif (message['attributes'])
      puts "Received Chef run data for node #{message['node']['hostname']}... discarding"
    else
      puts "Skipping valid JSON message as its type is not recognised. It looks like this...\n#{message}"
    end
  rescue JSON::ParserError => e
    puts "One or more records did not contain valid JSON.\nWe received...\n#{body.lines.join("\n")}"
    statusCode = 400
    resultBody = JSON.pretty_generate(result:"Dismal failure", reason:"Bad JSON", original_request:body.lines.join("\n"))
  end
  { statusCode: statusCode, body: resultBody }
end