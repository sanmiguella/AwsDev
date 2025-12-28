"""Create a security group in a subnet's VPC and add ingress rules for given ports."""

import argparse
import sys
from typing import Iterable

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Create a security group for a subnet's VPC and add ingress rules.",
	)
	parser.add_argument("--subnet-id", required=True, help="Subnet ID to target.")
	parser.add_argument(
		"--ports",
		required=True,
		nargs="+",
		type=int,
		help="One or more TCP ports to allow (e.g. 80 443 3306).",
	)
	parser.add_argument(
		"--cidr",
		default="0.0.0.0/0",
		help="CIDR to allow for ingress (default: 0.0.0.0/0).",
	)
	parser.add_argument(
		"--sg-name",
		default="custom-sg",
		help="Name tag and group name for the new security group.",
	)
	parser.add_argument(
		"--description",
		default="Custom ingress rules",
		help="Description for the security group.",
	)
	parser.add_argument("--region", help="AWS region (defaults to environment/config).")
	parser.add_argument(
		"--profile",
		help="AWS profile name from shared credentials/config files.",
	)
	return parser.parse_args()


def get_ec2_client(region: str | None, profile: str | None):
	session = boto3.Session(profile_name=profile) if profile else boto3.Session()
	return session.client("ec2", region_name=region)


def get_vpc_id_for_subnet(ec2, subnet_id: str) -> str:
	resp = ec2.describe_subnets(SubnetIds=[subnet_id])
	subnets: Iterable[dict] = resp.get("Subnets", [])
	if not subnets:
		raise RuntimeError(f"Subnet {subnet_id} not found")
	return subnets[0]["VpcId"]


def create_security_group(ec2, vpc_id: str, name: str, description: str) -> str:
	sg_id = ec2.create_security_group(
		GroupName=name,
		Description=description,
		VpcId=vpc_id,
	)["GroupId"]
	ec2.create_tags(Resources=[sg_id], Tags=[{"Key": "Name", "Value": name}])
	return sg_id


def add_ingress_rules(ec2, sg_id: str, ports: list[int], cidr: str) -> None:
	permissions = [
		{
			"IpProtocol": "tcp",
			"FromPort": port,
			"ToPort": port,
			"IpRanges": [{"CidrIp": cidr}],
		}
		for port in ports
	]
	ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=permissions)


def main() -> int:
	args = parse_args()
	ec2 = get_ec2_client(args.region, args.profile)

	try:
		vpc_id = get_vpc_id_for_subnet(ec2, args.subnet_id)
		sg_id = create_security_group(
			ec2=ec2,
			vpc_id=vpc_id,
			name=args.sg_name,
			description=args.description,
		)
		add_ingress_rules(ec2, sg_id=sg_id, ports=args.ports, cidr=args.cidr)
		print(
			f"Created security group {sg_id} in VPC {vpc_id} with inbound ports {args.ports} from {args.cidr}"
		)
	except (ClientError, BotoCoreError) as exc:  # pragma: no cover - runtime error path
		print(f"AWS error: {exc}", file=sys.stderr)
		return 1
	except Exception as exc:  # pragma: no cover - runtime error path
		print(exc, file=sys.stderr)
		return 1

	return 0


if __name__ == "__main__":
	sys.exit(main())
