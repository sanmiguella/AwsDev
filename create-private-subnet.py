"""Create a private subnet in a given VPC using boto3."""

import argparse
import sys
from typing import Iterable

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Create a private subnet in a VPC.")
	parser.add_argument("--vpc-id", required=True, help="Target VPC ID.")
	parser.add_argument(
		"--cidr",
		default="10.10.2.0/24",
		help="CIDR block for the subnet (default: 10.10.2.0/24).",
	)
	parser.add_argument("--az", help="Availability Zone for the subnet (optional).")
	parser.add_argument(
		"--name",
		default="private-subnet",
		help="Name tag for the subnet (default: private-subnet).",
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


def ensure_vpc_exists(ec2, vpc_id: str) -> None:
	resp = ec2.describe_vpcs(VpcIds=[vpc_id])
	vpcs: Iterable[dict] = resp.get("Vpcs", [])
	if not vpcs:
		raise RuntimeError(f"VPC {vpc_id} not found")


def create_private_subnet(ec2, vpc_id: str, cidr: str, az: str | None, name: str) -> str:
	subnet_kwargs = {"VpcId": vpc_id, "CidrBlock": cidr}
	if az:
		subnet_kwargs["AvailabilityZone"] = az

	subnet = ec2.create_subnet(**subnet_kwargs)["Subnet"]
	subnet_id = subnet["SubnetId"]

	# Tag and ensure it does NOT auto-assign public IPs on launch (private behavior).
	ec2.create_tags(Resources=[subnet_id], Tags=[{"Key": "Name", "Value": name}])
	ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": False})

	ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id])
	return subnet_id


def main() -> int:
	args = parse_args()
	ec2 = get_ec2_client(args.region, args.profile)

	try:
		ensure_vpc_exists(ec2, args.vpc_id)
		subnet_id = create_private_subnet(
			ec2=ec2,
			vpc_id=args.vpc_id,
			cidr=args.cidr,
			az=args.az,
			name=args.name,
		)
		print(
			f"Created private subnet {subnet_id} in VPC {args.vpc_id} with CIDR {args.cidr}"
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
