"""Create a MariaDB RDS instance in private subnets with specified AZ, SG, and creds."""

import argparse
import sys
from typing import Iterable

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Create a MariaDB RDS instance.")

	parser.add_argument("--region", help="AWS region (defaults to env/config).")
	parser.add_argument("--profile", help="AWS profile name from shared credentials/config.")

	parser.add_argument(
		"--db-identifier",
		default="lab-rds",
		help="DB instance identifier (default: lab-rds).",
	)
	parser.add_argument(
		"--engine-version",
		default="10.6.18",
		help="MariaDB engine version (default: 10.6.18).",
	)
	parser.add_argument(
		"--instance-class",
		default="db.t3.micro",
		help="DB instance class (default: db.t3.micro).",
	)
	parser.add_argument(
		"--allocated-storage",
		type=int,
		default=20,
		help="Allocated storage in GB (default: 20).",
	)

	parser.add_argument("--availability-zone", required=True, help="Primary AZ, e.g. us-east-1a.")
	parser.add_argument(
		"--primary-subnet-id",
		required=True,
		help="Subnet ID in the primary AZ (private subnet).",
	)
	parser.add_argument(
		"--secondary-subnet-id",
		required=True,
		help="Subnet ID in a fallback AZ (private subnet).",
	)
	parser.add_argument(
		"--subnet-group-name",
		default="rds-private-subnets",
		help="DB subnet group name to create/use (default: rds-private-subnets).",
	)

	parser.add_argument(
		"--vpc-security-group-ids",
		nargs="+",
		required=True,
		help="One or more VPC security group IDs for the DB instance.",
	)

	parser.add_argument("--master-username", required=True, help="Master username.")
	parser.add_argument("--master-password", required=True, help="Master password.")

	return parser.parse_args()


def get_clients(region: str | None, profile: str | None):
	session = boto3.Session(profile_name=profile) if profile else boto3.Session()
	return session.client("rds", region_name=region), session.client("ec2", region_name=region)


def ensure_subnets_same_vpc(ec2, subnet_ids: list[str]) -> str:
	resp = ec2.describe_subnets(SubnetIds=subnet_ids)
	subnets: Iterable[dict] = resp.get("Subnets", [])
	if len(subnets) != len(subnet_ids):
		found = {s["SubnetId"] for s in subnets}
		missing = [sid for sid in subnet_ids if sid not in found]
		raise RuntimeError(f"Subnets not found: {', '.join(missing)}")
	vpcs = {s["VpcId"] for s in subnets}
	if len(vpcs) != 1:
		raise RuntimeError("Subnets must be in the same VPC for a DB subnet group")
	return subnets[0]["VpcId"]


def ensure_subnet_group(rds, name: str, subnet_ids: list[str]) -> None:
	try:
		rds.create_db_subnet_group(
			DBSubnetGroupName=name,
			DBSubnetGroupDescription="Private subnets for RDS",
			SubnetIds=subnet_ids,
		)
	except rds.exceptions.DBSubnetGroupAlreadyExistsFault:
		# Update existing group to ensure both subnets are present.
		rds.modify_db_subnet_group(
			DBSubnetGroupName=name,
			SubnetIds=subnet_ids,
			DBSubnetGroupDescription="Private subnets for RDS",
		)


def create_db_instance(
	rds,
	db_identifier: str,
	engine_version: str,
	instance_class: str,
	allocated_storage: int,
	availability_zone: str,
	subnet_group_name: str,
	sg_ids: list[str],
	master_username: str,
	master_password: str,
) -> None:
	rds.create_db_instance(
		DBInstanceIdentifier=db_identifier,
		Engine="mariadb",
		EngineVersion=engine_version,
		DBInstanceClass=instance_class,
		AllocatedStorage=allocated_storage,
		AvailabilityZone=availability_zone,
		DBSubnetGroupName=subnet_group_name,
		VpcSecurityGroupIds=sg_ids,
		PubliclyAccessible=False,
		MasterUsername=master_username,
		MasterUserPassword=master_password,
		BackupRetentionPeriod=0,
		MultiAZ=False,
		StorageType="gp2",
	)


def main() -> int:
	args = parse_args()
	rds, ec2 = get_clients(args.region, args.profile)

	try:
		ensure_subnets_same_vpc(ec2, [args.primary_subnet_id, args.secondary_subnet_id])
		ensure_subnet_group(
			rds,
			name=args.subnet_group_name,
			subnet_ids=[args.primary_subnet_id, args.secondary_subnet_id],
		)

		create_db_instance(
			rds=rds,
			db_identifier=args.db_identifier,
			engine_version=args.engine_version,
			instance_class=args.instance_class,
			allocated_storage=args.allocated_storage,
			availability_zone=args.availability_zone,
			subnet_group_name=args.subnet_group_name,
			sg_ids=args.vpc_security_group_ids,
			master_username=args.master_username,
			master_password=args.master_password,
		)
		print(
			f"Creating RDS instance {args.db_identifier} in AZ {args.availability_zone} with subnet group {args.subnet_group_name} and SGs {args.vpc_security_group_ids}; publicly accessible: False"
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
