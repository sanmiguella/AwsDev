#!/usr/bin/env python3
import argparse
from typing import Optional

import boto3
import botocore.exceptions


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create an AMI from an existing EC2 instance"
    )
    parser.add_argument(
        "--instance-id",
        required=True,
        help="EC2 instance ID to image",
    )
    parser.add_argument(
        "--name",
        default="WebServer",
        help="Name to assign to the new AMI (default: WebServer)",
    )
    parser.add_argument(
        "--region",
        default=None,
        help="AWS region (falls back to environment / config if omitted)",
    )
    parser.add_argument(
        "--no-reboot",
        action="store_true",
        help="Create the image without stopping the instance first",
    )
    parser.add_argument(
        "--wait",
        action="store_true",
        help="Wait for the AMI to become available before exiting",
    )
    parser.add_argument(
        "--iam-instance-profile",
        help="Optional IAM instance profile (name or ARN) to attach before imaging",
    )
    return parser.parse_args()


def create_image(
    instance_id: str,
    name: str,
    region: Optional[str],
    no_reboot: bool,
    wait: bool,
    iam_instance_profile: Optional[str],
) -> str:
    client = boto3.client("ec2", region_name=region)

    if iam_instance_profile:
        profile_ref = (
            {"Arn": iam_instance_profile}
            if iam_instance_profile.startswith("arn:")
            else {"Name": iam_instance_profile}
        )
        try:
            assoc = client.describe_iam_instance_profile_associations(
                Filters=[{"Name": "instance-id", "Values": [instance_id]}]
            )
            already_attached = any(
                a.get("IamInstanceProfile", {}).get("Arn") == profile_ref.get("Arn")
                or a.get("IamInstanceProfile", {}).get("Id") == profile_ref.get("Name")
                for a in assoc.get("IamInstanceProfileAssociations", [])
            )
            if not already_attached:
                client.associate_iam_instance_profile(
                    IamInstanceProfile=profile_ref,
                    InstanceId=instance_id,
                )
                print("IAM instance profile association requested.")
        except botocore.exceptions.ClientError as exc:
            raise SystemExit(f"Failed to associate IAM profile: {exc}") from exc

    try:
        response = client.create_image(
            InstanceId=instance_id,
            Name=name,
            NoReboot=no_reboot,
        )
    except botocore.exceptions.ClientError as exc:
        raise SystemExit(f"Failed to create AMI: {exc}") from exc

    image_id = response.get("ImageId")
    if not image_id:
        raise SystemExit("No ImageId returned by CreateImage")

    print(f"CreateImage request submitted. AMI ID: {image_id}")

    if wait:
        waiter = client.get_waiter("image_available")
        try:
            waiter.wait(ImageIds=[image_id])
            print(f"AMI {image_id} is now available.")
        except botocore.exceptions.WaiterError as exc:
            raise SystemExit(f"AMI creation timed out: {exc}") from exc

    return image_id


def main() -> None:
    args = parse_args()
    create_image(
        instance_id=args.instance_id,
        name=args.name,
        region=args.region,
        no_reboot=args.no_reboot,
        wait=args.wait,
        iam_instance_profile=args.iam_instance_profile,
    )


if __name__ == "__main__":
    main()
