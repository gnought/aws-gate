# -*- encoding: utf-8 -*-
import ipaddress
import logging

import botocore.exceptions

from aws_gate.exceptions import AWSConnectionError
from aws_gate.utils import get_aws_resource

logger = logging.getLogger(__name__)


def _parse_ip(ip):
    ret = None
    try:
        ret= ipaddress.ip_address(ip)
    except ValueError:
        pass
    return ret


def _query_aws_api(ec2, **kwargs):
    try:
        return filter(
            lambda i: i.instance_id is not None,
            ec2.instances.filter(Filters=kwargs.get("Filters", []), InstanceIds=kwargs.get("InstanceIds", [])))
    except botocore.exceptions.ClientError as e:
        raise AWSConnectionError(e) from None


def _get_running_ec2_instances(ec2, filters):
    # We are always interested only in running EC2 instances as we cannot
    # open a session to terminated EC2 instance.
    filters = filters + [{"Name": "instance-state-name", "Values": ["running"]}]
    i = next(_query_aws_api(ec2, Filters=filters), {})
    logger.debug("Matching instance: %s", i)
    return i


def get_instance_by_private_dnsname(ec2, name):
    filters = [{"Name": "private-dns-name", "Values": [name]}]
    return _get_running_ec2_instances(ec2, filters)


def get_instance_by_dnsname(ec2, name):
    filters = [{"Name": "dns-name", "Values": [name]}]
    return _get_running_ec2_instances(ec2, filters)


def get_instance_by_private_ipaddress(ec2, name):
    filters = [{"Name": "private-ip-address", "Values": [name]}]
    return _get_running_ec2_instances(ec2, filters)


def getinstanceidbyipaddress(ec2 ,name):
    filters = [{"Name": "ip-address", "Values": [name]}]
    return _get_running_ec2_instances(ec2, filters)


def get_instance_by_tag(ec2, name):
    # One of the allowed characters in tags is ":", which might break tag
    # parsing. For this reason,we have to differentiate 2 cases for
    # provided name:
    # - aws: special prefixed tags in the form of aws:<service>:<tag_name>:<tag_value>
    # - regular cases in the form <tag_name>:<tag_value>
    if name.startswith("aws:"):
        key, value = ":".join(name.split(":", 3)[:3]), name.split(":", 3)[-1]
    else:
        key, value = name.split(":", 1)

    filters = [{"Name": "tag:{}".format(key), "Values": [value]}]
    return _get_running_ec2_instances(ec2, filters)


def get_instance_by_instancename(ec2, name):
    return get_instance_by_tag(ec2, "Name:{}".format(name))


def get_instance_by_instanceid(ec2, name):
    filters = [{"Name": "instance-state-name", "Values": ["running"]}]
    return next(_query_aws_api(ec2, Filters=filters, InstanceIds=[name]), {})


def get_instance_by_autoscalinggroup(name, ec2=None):
    _, asg_name = name.split(":")
    return get_instance_by_tag(ec2, "aws:autoscaling:groupName:{}".format(asg_name))


def query_instance(name, region_name, profile_name, ec2=None):
    if ec2 is None:
        ec2 = get_aws_resource("ec2", region_name=region_name, profile_name=profile_name)

    logger.debug("Querying EC2 API for instance identifier: %s", name)

    identifier_type = None
    func_dispatcher = {
        "dns-name": get_instance_by_dnsname,
        "private-dns-name": get_instance_by_private_dnsname,
        "ip-address": getinstanceidbyipaddress,
        "private-ip-address": get_instance_by_private_ipaddress,
        "tag": get_instance_by_tag,
        "name": get_instance_by_instancename,
        "asg": get_instance_by_autoscalinggroup,
    }

    # If we are provided with instance ID directly, we don't need to contact EC2
    # API and can return the value directly.
    # Identifier prefixes:
    # id - human friendly, present in some systems
    # i - regular EC2 instance ID as present in AWS console/logs
    # mi - regular SSM-managed instance ID as present in AWS console/logs
    if name.startswith("id-") or name.startswith("i-") or name.startswith("mi-"):
        return get_instance_by_instanceid(ec2, name)

    ip_obj = _parse_ip(name)
    if ip_obj:
        if ip_obj.is_private:
            identifier_type = "private-ip-address"
        else:
            identifier_type = "ip-address"
    else:
        if name.endswith("compute.amazonaws.com"):
            identifier_type = "dns-name"
        elif name.endswith("compute.internal"):
            identifier_type = "private-dns-name"
        elif name.startswith("asg:"):
            identifier_type = "asg"
        elif ":" in name:
            identifier_type = "tag"
        else:
            identifier_type = "name"

    logger.debug("Identifier type chosen: %s", identifier_type)
    return func_dispatcher[identifier_type](ec2, name)


def get_instance_details(instance_id, ec2=None):
    return next(get_multiple_instance_details([instance_id], ec2))


def get_multiple_instance_details(instance_ids, ec2=None):
    for ec2_instance in _query_aws_api(ec2, InstanceIds=instance_ids):
        yield {
                "instance_id": ec2_instance.id,
                "instance_name": next(filter(lambda t: t["Key"] == "Name", ec2_instance.tags), {}).get("Value"),
                "availability_zone": ec2_instance.placement["AvailabilityZone"],
                "vpc_id": ec2_instance.vpc_id,
                "private_ip_address": ec2_instance.private_ip_address or None,
                "public_ip_address": ec2_instance.public_ip_address or None,
                "private_dns_name": ec2_instance.private_dns_name or None,
                "public_dns_name": ec2_instance.public_dns_name or None,
            }
