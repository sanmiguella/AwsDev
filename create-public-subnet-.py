"""List VPCs or create a public subnet within a given VPC using boto3."""

import argparse
import sys
from typing import Iterable

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="List VPCs or create a public subnet in a VPC.",
	)

	mode = parser.add_mutually_exclusive_group(required=True)
	mode.add_argument(
		"--list",
		action="store_true",
		help="List VPCs with their IDs, names, and CIDRs.",
	)
	mode.add_argument(
		"--create",
		action="store_true",
		help="Create a public subnet in the specified VPC.",
	)

	parser.add_argument(
		"--region",
		help="AWS region to target (defaults to environment/config).",
	)
	parser.add_argument(
		"--profile",
		help="AWS profile name to use from shared credentials/config files.",
	)

	parser.add_argument(
		"--vpc-id",
		help="Target VPC ID (required with --create).",
	)
	parser.add_argument(
		"--cidr",
		default="10.10.1.0/24",
		help="CIDR block for the subnet (default: 10.10.1.0/24).",
	)
	parser.add_argument(
		"--az",
		help="Availability Zone for the subnet (optional).",
	)
	parser.add_argument(
		"--name",
		default="public-subnet",
		help="Name tag to apply to the subnet (default: public-subnet).",
	)

	args = parser.parse_args()
	if args.create and not args.vpc_id:
		parser.error("--vpc-id is required when using --create")
	return args


def get_ec2_client(region: str | None, profile: str | None):
	session = boto3.Session(profile_name=profile) if profile else boto3.Session()
	return session.client("ec2", region_name=region)


def list_vpcs(ec2) -> None:
	resp = ec2.describe_vpcs()
	vpcs: Iterable[dict] = resp.get("Vpcs", [])
	if not vpcs:
		print("No VPCs found.")
		return

	for vpc in vpcs:
		vpc_id = vpc.get("VpcId")
		cidr = vpc.get("CidrBlock")
		state = vpc.get("State")
		name = next(
			(tag["Value"] for tag in vpc.get("Tags", []) if tag.get("Key") == "Name"),
			"",
		)
		printable_name = f" Name={name}" if name else ""
		print(f"{vpc_id} | CIDR={cidr} | State={state}{printable_name}")


def ensure_internet_gateway(ec2, vpc_id: str) -> str:
	existing = ec2.describe_internet_gateways(
		Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
	).get("InternetGateways", [])
	if existing:
		return existing[0]["InternetGatewayId"]

	igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
	ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
	return igw_id


def create_public_subnet(
	ec2,
	vpc_id: str,
	cidr: str,
	az: str | None,
	name: str,
) -> str:
	subnet_kwargs = {"VpcId": vpc_id, "CidrBlock": cidr}
	if az:
		subnet_kwargs["AvailabilityZone"] = az

	subnet = ec2.create_subnet(**subnet_kwargs)["Subnet"]
	subnet_id = subnet["SubnetId"]

	ec2.create_tags(Resources=[subnet_id], Tags=[{"Key": "Name", "Value": name}])
	ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

	igw_id = ensure_internet_gateway(ec2, vpc_id)

	route_table_id = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
	ec2.create_tags(
		Resources=[route_table_id], Tags=[{"Key": "Name", "Value": f"rtb-{name}"}]
	)
	ec2.create_route(
		RouteTableId=route_table_id,
		DestinationCidrBlock="0.0.0.0/0",
		GatewayId=igw_id,
	)
	ec2.associate_route_table(RouteTableId=route_table_id, SubnetId=subnet_id)

	ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id])
	return subnet_id


def main() -> int:
	args = parse_args()
	ec2 = get_ec2_client(args.region, args.profile)

	try:
		if args.list:
			list_vpcs(ec2)
		else:
			subnet_id = create_public_subnet(
				ec2=ec2,
				vpc_id=args.vpc_id,
				cidr=args.cidr,
				az=args.az,
				name=args.name,
			)
			print(
				f"Created subnet {subnet_id} in VPC {args.vpc_id} with CIDR {args.cidr}"
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
