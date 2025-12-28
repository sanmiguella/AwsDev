"""List EC2 instances or create a new Ubuntu t2.micro instance in a chosen subnet."""

import argparse
import sys
from typing import Iterable

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="List or create EC2 instances.")

	mode = parser.add_mutually_exclusive_group(required=True)
	mode.add_argument("--list", action="store_true", help="List EC2 instances.")
	mode.add_argument("--create", action="store_true", help="Create an EC2 instance.")

	parser.add_argument("--region", help="AWS region to target (defaults to env/config).")
	parser.add_argument("--profile", help="AWS profile from shared credentials/config.")

	parser.add_argument("--vpc-id", help="VPC ID (optional; validated if provided).")
	parser.add_argument("--subnet-id", help="Subnet ID for the instance (required with --create).")
	parser.add_argument(
		"--sg-ids",
		nargs="+",
		help="One or more security group IDs to attach (required with --create).",
	)
	parser.add_argument("--key-name", help="EC2 key pair name (optional).")
	parser.add_argument(
		"--name",
		default="lab-ec2",
		help="Name tag for the instance (default: lab-ec2).",
	)
	parser.add_argument(
		"--associate-public-ip",
		action="store_true",
		help="Force AssociatePublicIpAddress on the primary interface.",
	)

	args = parser.parse_args()
	if args.create:
		if not args.subnet_id:
			parser.error("--subnet-id is required with --create")
		if not args.sg_ids:
			parser.error("--sg-ids is required with --create")
	return args


def get_ec2_client(region: str | None, profile: str | None):
	session = boto3.Session(profile_name=profile) if profile else boto3.Session()
	return session.client("ec2", region_name=region)


def get_latest_ubuntu_ami(ec2) -> str:
	param_name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
	region = getattr(ec2, "meta", None).region_name if hasattr(ec2, "meta") else None
	ssm = boto3.client("ssm", region_name=region)
	return ssm.get_parameter(Name=param_name)["Parameter"]["Value"]


def ensure_subnet_matches_vpc(ec2, subnet_id: str, vpc_id: str | None) -> str:
	resp = ec2.describe_subnets(SubnetIds=[subnet_id])
	subnets: Iterable[dict] = resp.get("Subnets", [])
	if not subnets:
		raise RuntimeError(f"Subnet {subnet_id} not found")
	actual_vpc = subnets[0]["VpcId"]
	if vpc_id and vpc_id != actual_vpc:
		raise RuntimeError(f"Subnet {subnet_id} belongs to VPC {actual_vpc}, not {vpc_id}")
	return actual_vpc


def list_instances(ec2) -> None:
	resp = ec2.describe_instances()
	reservations: Iterable[dict] = resp.get("Reservations", [])
	instances = [inst for r in reservations for inst in r.get("Instances", [])]
	if not instances:
		print("No EC2 instances found.")
		return

	for inst in instances:
		iid = inst.get("InstanceId")
		state = inst.get("State", {}).get("Name")
		itype = inst.get("InstanceType")
		subnet = inst.get("SubnetId")
		vpc = inst.get("VpcId")
		az = inst.get("Placement", {}).get("AvailabilityZone")
		pub_ip = inst.get("PublicIpAddress")
		priv_ip = inst.get("PrivateIpAddress")
		name = next(
			(t["Value"] for t in inst.get("Tags", []) if t.get("Key") == "Name"),
			"",
		)
		printable_name = f" | Name={name}" if name else ""
		print(
			f"{iid} | {state} | {itype} | AZ={az} | Subnet={subnet} | VPC={vpc} | PrivateIP={priv_ip} | PublicIP={pub_ip}{printable_name}"
		)


def create_instance(
	ec2,
	subnet_id: str,
	sg_ids: list[str],
	name: str,
	key_name: str | None,
	associate_public_ip: bool,
) -> str:
	ami = get_latest_ubuntu_ami(ec2)
	ni = {
		"SubnetId": subnet_id,
		"DeviceIndex": 0,
		"Groups": sg_ids,
	}
	if associate_public_ip:
		ni["AssociatePublicIpAddress"] = True

	params = {
		"ImageId": ami,
		"InstanceType": "t2.micro",
		"MinCount": 1,
		"MaxCount": 1,
		"NetworkInterfaces": [ni],
		"TagSpecifications": [
			{
				"ResourceType": "instance",
				"Tags": [{"Key": "Name", "Value": name}],
			}
		],
	}
	if key_name:
		params["KeyName"] = key_name

	resp = ec2.run_instances(**params)
	instance_id = resp["Instances"][0]["InstanceId"]
	ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id])
	return instance_id


def main() -> int:
	args = parse_args()
	ec2 = get_ec2_client(args.region, args.profile)

	try:
		if args.list:
			list_instances(ec2)
		else:
			vpc_id = ensure_subnet_matches_vpc(ec2, args.subnet_id, args.vpc_id)
			instance_id = create_instance(
				ec2=ec2,
				subnet_id=args.subnet_id,
				sg_ids=args.sg_ids,
				name=args.name,
				key_name=args.key_name,
				associate_public_ip=args.associate_public_ip,
			)
			print(
				f"Created instance {instance_id} in VPC {vpc_id} subnet {args.subnet_id} with SGs {args.sg_ids}"
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
