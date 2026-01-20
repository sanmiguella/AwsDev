#!/usr/bin/env python3
"""Create an AWS Secrets Manager secret from CLI arguments."""

import argparse
import json
import sys

import boto3
from botocore.exceptions import ClientError


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Create an AWS Secrets Manager secret with database credentials.",
	)
	parser.add_argument("--name", required=True, help="Secret name.")
	parser.add_argument("--description", required=True, help="Secret description.")
	parser.add_argument("--username", required=True, help="Database user.")
	parser.add_argument("--password", required=True, help="Database password.")
	parser.add_argument("--host", required=True, help="Database host or endpoint.")
	parser.add_argument("--db", required=True, help="Database name.")
	parser.add_argument(
		"--region",
		default=None,
		help="AWS region (falls back to environment/config if omitted).",
	)
	return parser.parse_args()


def build_secret_string(args: argparse.Namespace) -> str:
	payload = {
		"user": args.username,
		"password": args.password,
		"host": args.host,
		"db": args.db,
	}
	return json.dumps(payload)


def main() -> int:
	args = parse_args()
	secret_string = build_secret_string(args)

	# Use an explicit region if provided; otherwise rely on default resolution.
	client = boto3.client("secretsmanager", region_name=args.region)

	try:
		response = client.create_secret(
			Name=args.name,
			Description=args.description,
			SecretString=secret_string,
		)
	except ClientError as exc:
		print(f"Failed to create secret: {exc}", file=sys.stderr)
		return 1

	arn = response.get("ARN", "<unknown>")
	name = response.get("Name", args.name)
	print(f"Secret created: {name}\nARN: {arn}")
	return 0


if __name__ == "__main__":
	sys.exit(main())
