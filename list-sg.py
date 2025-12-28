"""List details for a security group, including VPC, rules, and attached subnets (via ENIs)."""

import argparse
import sys
from typing import Iterable

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Describe a security group.")
	parser.add_argument("--sg-id", required=True, help="Security Group ID to describe.")
	parser.add_argument("--region", help="AWS region (defaults to environment/config).")
	parser.add_argument(
		"--profile",
		help="AWS profile name from shared credentials/config files.",
	)
	return parser.parse_args()


def get_ec2_client(region: str | None, profile: str | None):
	session = boto3.Session(profile_name=profile) if profile else boto3.Session()
	return session.client("ec2", region_name=region)


def describe_security_group(ec2, sg_id: str) -> dict:
	resp = ec2.describe_security_groups(GroupIds=[sg_id])
	groups: Iterable[dict] = resp.get("SecurityGroups", [])
	if not groups:
		raise RuntimeError(f"Security Group {sg_id} not found")
	return groups[0]


def list_enis_for_sg(ec2, sg_id: str) -> list[dict]:
	resp = ec2.describe_network_interfaces(
		Filters=[{"Name": "group-id", "Values": [sg_id]}]
	)
	return resp.get("NetworkInterfaces", [])


def fmt_rules(rules: Iterable[dict]) -> str:
	parts: list[str] = []
	for rule in rules:
		proto = rule.get("IpProtocol")
		from_p = rule.get("FromPort")
		to_p = rule.get("ToPort")
		port_part = f"{from_p}-{to_p}" if from_p != to_p else f"{from_p}" if from_p is not None else "all"

		cidrs = [ip.get("CidrIp") for ip in rule.get("IpRanges", [])]
		cidr6 = [ip.get("CidrIpv6") for ip in rule.get("Ipv6Ranges", [])]
		plists = [pl.get("PrefixListId") for pl in rule.get("PrefixListIds", [])]
		sg_refs = [sg.get("GroupId") for sg in rule.get("UserIdGroupPairs", [])]

		items: list[str] = []
		if cidrs:
			items.append(f"cidr={','.join(cidrs)}")
		if cidr6:
			items.append(f"cidr6={','.join(cidr6)}")
		if plists:
			items.append(f"pl={','.join(plists)}")
		if sg_refs:
			items.append(f"sg={','.join(sg_refs)}")
		scope = "; ".join(items) if items else "(no ranges)"

		parts.append(f"proto={proto} ports={port_part} -> {scope}")
	return "\n  ".join(parts) if parts else "(none)"


def main() -> int:
	args = parse_args()
	ec2 = get_ec2_client(args.region, args.profile)

	try:
		sg = describe_security_group(ec2, args.sg_id)
		enis = list_enis_for_sg(ec2, args.sg_id)

		name = next(
			(t["Value"] for t in sg.get("Tags", []) if t.get("Key") == "Name"),
			"",
		)
		print(f"Security Group: {sg['GroupId']} ({name})")
		print(f"Description: {sg.get('Description')}")
		print(f"VPC: {sg.get('VpcId')}")
		print("Ingress:")
		print(f"  {fmt_rules(sg.get('IpPermissions', []))}")
		print("Egress:")
		print(f"  {fmt_rules(sg.get('IpPermissionsEgress', []))}")

		if not enis:
			print("Attached ENIs: none")
		else:
			print("Attached ENIs:")
			for eni in enis:
				eni_id = eni.get("NetworkInterfaceId")
				subnet_id = eni.get("SubnetId")
				az = eni.get("AvailabilityZone")
				desc = eni.get("Description", "")
				print(f"  {eni_id} | Subnet={subnet_id} | AZ={az} | {desc}")
	except (ClientError, BotoCoreError) as exc:  # pragma: no cover - runtime error path
		print(f"AWS error: {exc}", file=sys.stderr)
		return 1
	except Exception as exc:  # pragma: no cover - runtime error path
		print(exc, file=sys.stderr)
		return 1

	return 0


if __name__ == "__main__":
	sys.exit(main())
