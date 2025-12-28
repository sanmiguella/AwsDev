"""Create a VPC named labnetwork with cidr 10.10.0.0/16 using boto3."""

import argparse
import sys

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Create a VPC named labnetwork with the given CIDR block.",
	)
	parser.add_argument(
		"--region",
		help="AWS region to use (defaults to environment or config)",
	)
	parser.add_argument(
		"--profile",
		help="AWS profile name to use from credentials/config files",
	)
	parser.add_argument(
		"--cidr",
		default="10.10.0.0/16",
		help="CIDR block for the VPC (default: 10.10.0.0/16)",
	)
	return parser.parse_args()


def create_vpc(region: str | None, profile: str | None, cidr: str) -> str:
	session = boto3.Session(profile_name=profile) if profile else boto3.Session()
	ec2 = session.client("ec2", region_name=region)

	try:
		resp = ec2.create_vpc(
			CidrBlock=cidr,
			TagSpecifications=[
				{
					"ResourceType": "vpc",
					"Tags": [
						{"Key": "Name", "Value": "labnetwork"},
					],
				}
			],
		)

		vpc_id = resp["Vpc"]["VpcId"]

		# Enable DNS features so instances get hostnames and resolve names.
		ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
		ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

		ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id])
		return vpc_id
	except (ClientError, BotoCoreError) as exc:  # pragma: no cover - runtime error path
		raise RuntimeError(f"Failed to create VPC: {exc}") from exc


def main() -> int:
	args = parse_args()
	try:
		vpc_id = create_vpc(region=args.region, profile=args.profile, cidr=args.cidr)
	except Exception as exc:  # pragma: no cover - runtime error path
		print(exc, file=sys.stderr)
		return 1

	print(f"Created VPC {vpc_id} named labnetwork with CIDR {args.cidr}")
	return 0


if __name__ == "__main__":
	sys.exit(main())
