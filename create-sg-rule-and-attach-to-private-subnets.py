"""Create a security group for private subnets and attach it to ENIs within them."""

import argparse
import sys
from typing import Iterable

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description=(
			"Create a security group in the VPC of the given subnets, add ingress rules, "
			"and attach the SG to all ENIs found in those subnets."
		)
	)
	parser.add_argument(
		"--subnet-ids",
		nargs="+",
		required=True,
		help="One or more subnet IDs (must all belong to the same VPC).",
	)
	parser.add_argument(
		"--ports",
		nargs="+",
		type=int,
		required=True,
		help="TCP ports to allow (e.g. 3306 5432).",
	)
	parser.add_argument(
		"--cidr",
		default="0.0.0.0/0",
		help="CIDR to allow for ingress (default: 0.0.0.0/0).",
	)
	parser.add_argument(
		"--name",
		default="private-subnets-sg",
		help="Name/Tag for the security group (default: private-subnets-sg).",
	)
	parser.add_argument(
		"--description",
		default="Ingress for private subnets",
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


def ensure_subnets_same_vpc(ec2, subnet_ids: list[str]) -> str:
	resp = ec2.describe_subnets(SubnetIds=subnet_ids)
	subnets: Iterable[dict] = resp.get("Subnets", [])
	if len(subnets) != len(subnet_ids):
		found = {s["SubnetId"] for s in subnets}
		missing = [sid for sid in subnet_ids if sid not in found]
		raise RuntimeError(f"Subnets not found: {', '.join(missing)}")

	vpcs = {s["VpcId"] for s in subnets}
	if len(vpcs) != 1:
		raise RuntimeError("All subnets must belong to the same VPC")
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


def attach_sg_to_enis(ec2, sg_id: str, subnet_ids: list[str]) -> None:
	# SGs attach to ENIs, not to subnets directly. Here we add the SG to all ENIs in the subnets.
	for subnet_id in subnet_ids:
		enis_resp = ec2.describe_network_interfaces(
			Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
		)
		enis: Iterable[dict] = enis_resp.get("NetworkInterfaces", [])
		if not enis:
			print(f"No ENIs found in subnet {subnet_id}; nothing to attach.")
			continue

		for eni in enis:
			eni_id = eni["NetworkInterfaceId"]
			current_groups = {g["GroupId"] for g in eni.get("Groups", [])}
			if sg_id in current_groups:
				print(f"ENI {eni_id} already has SG {sg_id}; skipping.")
				continue
			new_groups = list(current_groups | {sg_id})
			ec2.modify_network_interface_attribute(NetworkInterfaceId=eni_id, Groups=new_groups)
			print(f"Attached SG {sg_id} to ENI {eni_id} in subnet {subnet_id}")


def main() -> int:
	args = parse_args()
	ec2 = get_ec2_client(args.region, args.profile)

	try:
		vpc_id = ensure_subnets_same_vpc(ec2, args.subnet_ids)
		sg_id = create_security_group(
			ec2=ec2,
			vpc_id=vpc_id,
			name=args.name,
			description=args.description,
		)
		add_ingress_rules(ec2, sg_id=sg_id, ports=args.ports, cidr=args.cidr)
		attach_sg_to_enis(ec2, sg_id=sg_id, subnet_ids=args.subnet_ids)
		print(
			f"Created SG {sg_id} in VPC {vpc_id} allowing TCP {args.ports} from {args.cidr} and attached to ENIs in subnets {args.subnet_ids}"
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
