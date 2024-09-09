import json
import boto3
from botocore.exceptions import ClientError

def lambda_handler(event, context):
	# Initialize EC2 client to interact with AWS EC2 service
	ec2 = boto3.client('ec2')
	# Extract instance ID and the IP address to block from the incoming event data
	instance_id = event['detail']['resource']['instanceDetails']['instanceId']
	# Covering IP address into CIDR format
	ip_to_block_cidr = f"{event['detail']['service']['action']['networkConnectionAction']['remoteIpDetails']['ipAddressV4']}/32"
	try:
		# Get details about the EC2 instance based on the instance ID
		instance = ec2.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
		# Extract the subnet ID of the instance
		subnet_id = instance['SubnetId']

		# Retrieve the Network Access Control Lists (NACLs) associated with the subnet
		nacls = ec2.describe_network_acls(Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}])['NetworkAcls']
	except ClientError as e:
		# Log error if there is an issue retrieving the instance or NACLs
		print(f"Error retrieving instance details or NACLs: {e}")
		return {'statusCode': 500, 'body': f"Error retrieving instance details or NACLs: {e}"}

	def block_ip_in_nacl(nacl, ip_cidr, egress):
		"""
		Add a rule to the NACL to block the specified IP.
		:param nacl: The Network ACL object
		:param ip_cidr: The IP address to block in CIDR format
		:param egress: True if blocking egress traffic, False for ingress
		:return: True if a rule was added, False if the IP is already blocked
		"""
		
		# Check if the IP is already blocked in the NACL for the specified direction (ingress/egress)
		if any(entry['CidrBlock'] == ip_cidr and entry['Egress'] == egress for entry in nacl['Entries']):
			return False  # IP is already blocked

		# Determine the next available rule number by sorting existing rules
		rules = sorted((entry['RuleNumber'] for entry in nacl['Entries'] if entry['Egress'] == egress), reverse=True)
		#print(rules)
		
		# Set the rule number. If there are fewer than 3 rules, use 101; otherwise, increment an existing rule number.
		rule_number = rules[2] + 1 if len(rules) > 2 else 101

		try:
			# Create a new NACL entry to block the IP address for all protocols
			ec2.create_network_acl_entry(
				NetworkAclId=nacl['NetworkAclId'],
				RuleNumber=rule_number,
				Protocol='-1',  # Apply to all protocols (-1 stands for all protocols)
				RuleAction='deny',  # Deny traffic from/to this IP
				Egress=egress,  # Whether it's an egress or ingress rule
				CidrBlock=ip_cidr  # The IP address to block, in CIDR notation
			)
		except ClientError as e:
			# Log any errors that occur when modifying the NACL
			print(f"Error modifying NACL {nacl['NetworkAclId']}: {e}")
			return {'statusCode': 500, 'body': f"Error modifying NACL {nacl['NetworkAclId']}: {e}"}
		return True  # Successfully added the blocking rule

	# Initialize flags to track whether the IP is blocked for ingress and egress
	ingress_blocked = egress_blocked = True

	# Iterate over all NACLs and attempt to block the IP for both ingress and egress traffic
	for nacl in nacls:
		ingress_blocked &= block_ip_in_nacl(nacl, ip_to_block_cidr, egress=False) is False  # Ingress rule
		egress_blocked &= block_ip_in_nacl(nacl, ip_to_block_cidr, egress=True) is False  # Egress rule

	# Check if the IP was already blocked for both ingress and egress
	if ingress_blocked and egress_blocked:
		return {'statusCode': 200, 'body': f"Malicious IP {ip_to_block_cidr} already exists in NACLs for instance {instance_id}"}
	else:
		return {'statusCode': 200, 'body': f"Successfully blocked IP {ip_to_block_cidr} in NACLs for instance {instance_id}"}
