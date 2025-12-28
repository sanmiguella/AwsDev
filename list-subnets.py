"""List subnets for a VPC by ID using boto3."""

import argparse
import sys
from typing import Iterable

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="List subnets in a VPC.")
	parser.add_argument("--vpc-id", required=True, help="VPC ID to list subnets for.")
	parser.add_argument("--region", help="AWS region (defaults to environment/config).")
	parser.add_argument(
		"--profile",
		help="AWS profile name from shared credentials/config files.",
	)
	return parser.parse_args()


def get_ec2_client(region: str | None, profile: str | None):
	session = boto3.Session(profile_name=profile) if profile else boto3.Session()
	return session.client("ec2", region_name=region)


def list_subnets(ec2, vpc_id: str) -> None:
	resp = ec2.describe_subnets(
		Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
	)
	subnets: Iterable[dict] = resp.get("Subnets", [])
	if not subnets:
		print(f"No subnets found in VPC {vpc_id}.")
		return

	for subnet in subnets:
		subnet_id = subnet.get("SubnetId")
		cidr = subnet.get("CidrBlock")
		az = subnet.get("AvailabilityZone")
		name = next(
			(tag["Value"] for tag in subnet.get("Tags", []) if tag.get("Key") == "Name"),
			"",
		)
		printable_name = f" | Name={name}" if name else ""
		print(f"{subnet_id} | CIDR={cidr} | AZ={az}{printable_name}")


def main() -> int:
	args = parse_args()
	ec2 = get_ec2_client(args.region, args.profile)

	try:
		list_subnets(ec2, args.vpc_id)
	except (ClientError, BotoCoreError) as exc:  # pragma: no cover - runtime error path
		print(f"AWS error: {exc}", file=sys.stderr)
		return 1
	except Exception as exc:  # pragma: no cover - runtime error path
		print(exc, file=sys.stderr)
		return 1

	return 0


if __name__ == "__main__":
	sys.exit(main())
