# -*- encoding: utf-8 -*-
import ipaddress
import logging

import botocore.exceptions

from aws_gate.exceptions import AWSConnectionError

logger = logging.getLogger(__name__)


def _is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return True


def _query_aws_api(ec2, **kwargs):
    try:
        return filter(lambda i: i.instance_id is not None, ec2.instances.filter(Filters=kwargs.get("Filters", []), InstanceIds=kwargs.get("InstanceIds", [])))
    except botocore.exceptions.ClientError as e:
        raise AWSConnectionError(e) from None


def _get_running_ec2_instances(ec2, filters):
    # We are always interested only in running EC2 instances as we cannot
    # open a session to terminated EC2 instance.
    filters = filters + [{"Name": "instance-state-name", "Values": ["running"]}]
    i = next(_query_aws_api(ec2, Filters=filters), {}).instance_id
    logger.debug("Matching instance: %s", i)
    return i


def getinstanceidbyprivatednsname(ec2, name):
    filters = [{"Name": "private-dns-name", "Values": [name]}]
    return _get_running_ec2_instances(ec2, filters)


def getinstanceidbydnsname(ec2, name):
    filters = [{"Name": "dns-name", "Values": [name]}]
    return _get_running_ec2_instances(ec2, filters)


def getinstanceidbyprivateipaddress(ec2, name):
    filters = [{"Name": "private-ip-address", "Values": [name]}]
    return _get_running_ec2_instances(ec2, filters)


def getinstanceidbyipaddress(ec2 ,name):
    filters = [{"Name": "ip-address", "Values": [name]}]
    return _get_running_ec2_instances(ec2, filters)


def getinstanceidbytag(ec2, name):
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


def getinstanceidbyinstancename(ec2, name):
    return getinstanceidbytag(ec2, "Name:{}".format(name))


def getinstanceidbyautoscalinggroup(name, ec2=None):
    _, asg_name = name.split(":")
    return getinstanceidbytag(ec2, "aws:autoscaling:groupName:{}".format(asg_name))


def query_instance(name, ec2=None):
    if ec2 is None:
        raise ValueError("EC2 client is not initialized")

    logger.debug("Querying EC2 API for instance identifier: %s", name)

    identifier_type = None
    func_dispatcher = {
        "dns-name": getinstanceidbydnsname,
        "private-dns-name": getinstanceidbyprivatednsname,
        "ip-address": getinstanceidbyipaddress,
        "private-ip-address": getinstanceidbyprivateipaddress,
        "tag": getinstanceidbytag,
        "name": getinstanceidbyinstancename,
        "asg": getinstanceidbyautoscalinggroup,
    }

    # If we are provided with instance ID directly, we don't need to contact EC2
    # API and can return the value directly.
    # Identifier prefixes:
    # id - human friendly, present in some systems
    # i - regular EC2 instance ID as present in AWS console/logs
    # mi - regular SSM-managed instance ID as present in AWS console/logs
    if name.startswith("id-") or name.startswith("i-") or name.startswith("mi-"):
        return name

    if _is_valid_ip(name):
        if not ipaddress.ip_address(name).is_private:
            identifier_type = "ip-address"
        else:
            identifier_type = "private-ip-address"
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
