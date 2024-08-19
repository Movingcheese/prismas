
import boto3
import csv
import json
from botocore.exceptions import ClientError

def check_public_services():
    session = boto3.Session()
    sts = session.client('sts')
    try:
        sts.get_caller_identity()
        print("AWS credentials are valid.")
    except Exception as e:
        print(f"Error validating AWS credentials: {e}")
        exit(1)
    public_services = []

    # EC2
    ec2 = session.client('ec2')
    try:
        instances = ec2.describe_instances()
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                if any(group.get('GroupName') == 'default' for group in instance.get('SecurityGroups', [])):
                    public_services.append({
                        'Service': 'EC2',
                        'ResourceId': instance['InstanceId'],
                        'PublicIP': instance.get('PublicIpAddress', 'N/A')
                    })
    except ClientError as e:
        print(f"Error checking EC2: {e}")

    # S3
    s3 = session.client('s3')
    try:
        buckets = s3.list_buckets()
        for bucket in buckets['Buckets']:
            try:
                public_access = s3.get_public_access_block(Bucket=bucket['Name'])
                if not all(public_access['PublicAccessBlockConfiguration'].values()):
                    public_services.append({
                        'Service': 'S3',
                        'ResourceId': bucket['Name'],
                        'PublicAccess': 'Possible'
                    })
            except ClientError:
                public_services.append({
                    'Service': 'S3',
                    'ResourceId': bucket['Name'],
                    'PublicAccess': 'Possible (No block configuration)'
                })
    except ClientError as e:
        print(f"Error checking S3: {e}")

    # RDS
    rds = session.client('rds')
    try:
        db_instances = rds.describe_db_instances()
        for instance in db_instances['DBInstances']:
            if instance['PubliclyAccessible']:
                public_services.append({
                    'Service': 'RDS',
                    'ResourceId': instance['DBInstanceIdentifier'],
                    'Endpoint': instance['Endpoint']['Address']
                })
    except ClientError as e:
        print(f"Error checking RDS: {e}")

    # ELB
    elb = session.client('elbv2')
    try:
        load_balancers = elb.describe_load_balancers()
        for lb in load_balancers['LoadBalancers']:
            if lb['Scheme'] == 'internet-facing':
                public_services.append({
                    'Service': 'ELB',
                    'ResourceId': lb['LoadBalancerName'],
                    'DNSName': lb['DNSName']
                })
    except ClientError as e:
        print(f"Error checking ELB: {e}")

    # API Gateway
    apigw = session.client('apigateway')
    try:
        apis = apigw.get_rest_apis()
        for api in apis['items']:
            stages = apigw.get_stages(restApiId=api['id'])
            for stage in stages['item']:
                public_services.append({
                    'Service': 'API Gateway',
                    'ResourceId': f"{api['name']} - {stage['stageName']}",
                    'Endpoint': f"https://{api['id']}.execute-api.{session.region_name}.amazonaws.com/{stage['stageName']}"
                })
    except ClientError as e:
        print(f"Error checking API Gateway: {e}")

    # Lambda
    lambda_client = session.client('lambda')
    try:
        functions = lambda_client.list_functions()
        for function in functions['Functions']:
            try:
                policy = lambda_client.get_policy(FunctionName=function['FunctionName'])
                if 'Policy' in policy:
                    policy_json = json.loads(policy['Policy'])
                    for statement in policy_json['Statement']:
                        principal = statement.get('Principal', {})
                        if isinstance(principal, dict):
                            if '*' in principal.values():
                                public_services.append({
                                    'Service': 'Lambda',
                                    'ResourceId': function['FunctionName'],
                                    'PublicAccess': 'Yes'
                                })
                                break
                        elif principal == '*':
                            public_services.append({
                                'Service': 'Lambda',
                                'ResourceId': function['FunctionName'],
                                'PublicAccess': 'Yes'
                            })
                            break
            except ClientError as function_error:
                if function_error.response['Error']['Code'] != 'ResourceNotFoundException':
                    print(f"Error checking Lambda function {function['FunctionName']}: {function_error}")
    except ClientError as e:
        print(f"Error listing Lambda functions: {e}")

    # VPC and Subnets
    ec2 = session.client('ec2')
    try:
        # VPCs
        vpcs = ec2.describe_vpcs()
        for vpc_instance in vpcs['Vpcs']:
            if vpc_instance['IsDefault']:
                public_services.append({
                    'Service': 'VPC',
                    'ResourceId': vpc_instance['VpcId'],
                    'IsDefault': True
                })
            if vpc_instance.get('CidrBlockAssociationSet'):
                for association in vpc_instance['CidrBlockAssociationSet']:
                    if association.get('CidrBlockState', {}).get('State') == 'associated':
                        public_services.append({
                            'Service': 'VPC',
                            'ResourceId': vpc_instance['VpcId'],
                            'CidrBlock': association['CidrBlock']
                        })

        # Subnets
        subnets = ec2.describe_subnets()
        for subnet in subnets['Subnets']:
            if subnet['MapPublicIpOnLaunch']:
                public_services.append({
                    'Service': 'Subnet',
                    'ResourceId': subnet['SubnetId'],
                    'VpcId': subnet['VpcId'],
                    'CidrBlock': subnet['CidrBlock'],
                    'PublicIPOnLaunch': True
                })

        # Internet Gateways
        igws = ec2.describe_internet_gateways()
        for igw in igws['InternetGateways']:
            for attachment in igw.get('Attachments', []):
                if attachment['State'] == 'available':
                    public_services.append({
                        'Service': 'Internet Gateway',
                        'ResourceId': igw['InternetGatewayId'],
                        'VpcId': attachment['VpcId']
                    })

        # Route Tables
        route_tables = ec2.describe_route_tables()
        for route_table in route_tables['RouteTables']:
            for route in route_table['Routes']:
                if route.get('GatewayId') and 'igw-' in route['GatewayId']:
                    public_services.append({
                        'Service': 'Route Table',
                        'ResourceId': route_table['RouteTableId'],
                        'VpcId': route_table['VpcId'],
                        'DestinationCidrBlock': route['DestinationCidrBlock'],
                        'GatewayId': route['GatewayId']
                    })
    except ClientError as e:
        print(f"Error checking VPC components: {e}")

    # Route 53
    route53 = session.client('route53')
    try:
        hosted_zones = route53.list_hosted_zones()
        for zone in hosted_zones['HostedZones']:
            if not zone['Config'].get('PrivateZone', False):
                public_services.append({
                    'Service': 'Route 53',
                    'ResourceId': zone['Id'],
                    'PublicZone': True
                })
    except ClientError as e:
        print(f"Error checking Route 53: {e}")

    # CloudFront
    cloudfront = session.client('cloudfront')
    try:
        distributions = cloudfront.list_distributions()
        if 'DistributionList' in distributions:
            for distribution in distributions['DistributionList'].get('Items', []):
                if distribution['Enabled']:
                    public_services.append({
                        'Service': 'CloudFront',
                        'ResourceId': distribution['Id'],
                        'DomainName': distribution['DomainName']
                    })
import boto3
import csv
import json
from botocore.exceptions import ClientError

def check_public_services():
    session = boto3.Session()
    sts = session.client('sts')
    try:
        sts.get_caller_identity()
        print("AWS credentials are valid.")
    except Exception as e:
        print(f"Error validating AWS credentials: {e}")
        exit(1)
    public_services = []

    # EC2
    ec2 = session.client('ec2')
    try:
        instances = ec2.describe_instances()
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                if any(group.get('GroupName') == 'default' for group in instance.get('SecurityGroups', [])):
                    public_services.append({
                        'Service': 'EC2',
                        'ResourceId': instance['InstanceId'],
                        'PublicIP': instance.get('PublicIpAddress', 'N/A')
                    })
    except ClientError as e:
        print(f"Error checking EC2: {e}")

    # S3
    s3 = session.client('s3')
    try:
        buckets = s3.list_buckets()
        for bucket in buckets['Buckets']:
            try:
                public_access = s3.get_public_access_block(Bucket=bucket['Name'])
                if not all(public_access['PublicAccessBlockConfiguration'].values()):
                    public_services.append({
                        'Service': 'S3',
                        'ResourceId': bucket['Name'],
                        'PublicAccess': 'Possible'
                    })
            except ClientError:
                public_services.append({
                    'Service': 'S3',
                    'ResourceId': bucket['Name'],
                    'PublicAccess': 'Possible (No block configuration)'
                })
    except ClientError as e:
        print(f"Error checking S3: {e}")

    # RDS
    rds = session.client('rds')
    try:
        db_instances = rds.describe_db_instances()
        for instance in db_instances['DBInstances']:
            if instance['PubliclyAccessible']:
                public_services.append({
                    'Service': 'RDS',
                    'ResourceId': instance['DBInstanceIdentifier'],
                    'Endpoint': instance['Endpoint']['Address']
                })
    except ClientError as e:
        print(f"Error checking RDS: {e}")

    # ELB
    elb = session.client('elbv2')
    try:
        load_balancers = elb.describe_load_balancers()
        for lb in load_balancers['LoadBalancers']:
            if lb['Scheme'] == 'internet-facing':
                public_services.append({
                    'Service': 'ELB',
                    'ResourceId': lb['LoadBalancerName'],
                    'DNSName': lb['DNSName']
                })
    except ClientError as e:
        print(f"Error checking ELB: {e}")

    # API Gateway
    apigw = session.client('apigateway')
    try:
        apis = apigw.get_rest_apis()
        for api in apis['items']:
            stages = apigw.get_stages(restApiId=api['id'])
            for stage in stages['item']:
                public_services.append({
                    'Service': 'API Gateway',
                    'ResourceId': f"{api['name']} - {stage['stageName']}",
                    'Endpoint': f"https://{api['id']}.execute-api.{session.region_name}.amazonaws.com/{stage['stageName']}"
                })
    except ClientError as e:
        print(f"Error checking API Gateway: {e}")

    # Lambda
    lambda_client = session.client('lambda')
    try:
        functions = lambda_client.list_functions()
        for function in functions['Functions']:
            try:
                policy = lambda_client.get_policy(FunctionName=function['FunctionName'])
                if 'Policy' in policy:
                    policy_json = json.loads(policy['Policy'])
                    for statement in policy_json['Statement']:
                        principal = statement.get('Principal', {})
                        if isinstance(principal, dict):
                            if '*' in principal.values():
                                public_services.append({
                                    'Service': 'Lambda',
                                    'ResourceId': function['FunctionName'],
                                    'PublicAccess': 'Yes'
                                })
                                break
                        elif principal == '*':
                            public_services.append({
                                'Service': 'Lambda',
                                'ResourceId': function['FunctionName'],
                                'PublicAccess': 'Yes'
                            })
                            break
            except ClientError as function_error:
                if function_error.response['Error']['Code'] != 'ResourceNotFoundException':
                    print(f"Error checking Lambda function {function['FunctionName']}: {function_error}")
    except ClientError as e:
        print(f"Error listing Lambda functions: {e}")

    # VPC and Subnets
    ec2 = session.client('ec2')
    try:
        # VPCs
        vpcs = ec2.describe_vpcs()
        for vpc_instance in vpcs['Vpcs']:
            if vpc_instance['IsDefault']:
                public_services.append({
                    'Service': 'VPC',
                    'ResourceId': vpc_instance['VpcId'],
                    'IsDefault': True
                })
            if vpc_instance.get('CidrBlockAssociationSet'):
                for association in vpc_instance['CidrBlockAssociationSet']:
                    if association.get('CidrBlockState', {}).get('State') == 'associated':
                        public_services.append({
                            'Service': 'VPC',
                            'ResourceId': vpc_instance['VpcId'],
                            'CidrBlock': association['CidrBlock']
                        })

        # Subnets
        subnets = ec2.describe_subnets()
        for subnet in subnets['Subnets']:
            if subnet['MapPublicIpOnLaunch']:
                public_services.append({
                    'Service': 'Subnet',
                    'ResourceId': subnet['SubnetId'],
                    'VpcId': subnet['VpcId'],
                    'CidrBlock': subnet['CidrBlock'],
                    'PublicIPOnLaunch': True
                })

        # Internet Gateways
        igws = ec2.describe_internet_gateways()
        for igw in igws['InternetGateways']:
            for attachment in igw.get('Attachments', []):
                if attachment['State'] == 'available':
                    public_services.append({
                        'Service': 'Internet Gateway',
                        'ResourceId': igw['InternetGatewayId'],
                        'VpcId': attachment['VpcId']
                    })

        # Route Tables
        route_tables = ec2.describe_route_tables()
        for route_table in route_tables['RouteTables']:
            for route in route_table['Routes']:
                if route.get('GatewayId') and 'igw-' in route['GatewayId']:
                    public_services.append({
                        'Service': 'Route Table',
                        'ResourceId': route_table['RouteTableId'],
                        'VpcId': route_table['VpcId'],
                        'DestinationCidrBlock': route['DestinationCidrBlock'],
                        'GatewayId': route['GatewayId']
                    })
    except ClientError as e:
        print(f"Error checking VPC components: {e}")

    # Route 53
    route53 = session.client('route53')
    try:
        hosted_zones = route53.list_hosted_zones()
        for zone in hosted_zones['HostedZones']:
            if not zone['Config'].get('PrivateZone', False):
                public_services.append({
                    'Service': 'Route 53',
                    'ResourceId': zone['Id'],
                    'PublicZone': True
                })
    except ClientError as e:
        print(f"Error checking Route 53: {e}")

    # CloudFront
    cloudfront = session.client('cloudfront')
    try:
        distributions = cloudfront.list_distributions()
        if 'DistributionList' in distributions:
            for distribution in distributions['DistributionList'].get('Items', []):
                if distribution['Enabled']:
                    public_services.append({
                        'Service': 'CloudFront',
                        'ResourceId': distribution['Id'],
                        'DomainName': distribution['DomainName']
                    })
    except ClientError as e:
        print(f"Error checking CloudFront: {e}")

    return public_services

def save_to_csv(data, filename):
    fieldnames = set()
    for item in data:
        fieldnames.update(item.keys())
    
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for item in data:
            writer.writerow(item)

if __name__ == "__main__":
    # Verify AWS credentials
    session = boto3.Session()
    sts = session.client('sts')
    try:
        sts.get_caller_identity()
        print("AWS credentials are valid.")
    except Exception as e:
        print(f"Error validating AWS credentials: {e}")
        exit(1)

    public_services = check_public_services()
    save_to_csv(public_services, 'public_aws_services.csv')
    print(f"Results saved to public_aws_services.csv")

    except ClientError as e:
        print(f"Error checking CloudFront: {e}")

    return public_services

def save_to_csv(data, filename):
    fieldnames = set()
    for item in data:
        fieldnames.update(item.keys())
    
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for item in data:
            writer.writerow(item)

if __name__ == "__main__":
    # Verify AWS credentials
    session = boto3.Session()
    sts = session.client('sts')
    try:
        sts.get_caller_identity()
        print("AWS credentials are valid.")
    except Exception as e:
        print(f"Error validating AWS credentials: {e}")
        exit(1)

    public_services = check_public_services()
    save_to_csv(public_services, 'public_aws_services.csv')
    print(f"Results saved to public_aws_services.csv")
