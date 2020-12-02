import logging

from aws_gate.constants import AWS_DEFAULT_PROFILE, AWS_DEFAULT_REGION
from aws_gate.decorators import (
    plugin_required,
    plugin_version,
    valid_aws_profile,
    valid_aws_region,
)
from aws_gate.query import query_instance
from aws_gate.session_common import BaseSession
from aws_gate.utils import (
    get_aws_client,
    fetch_instance_details_from_config,
    get_aws_resource,
)

logger = logging.getLogger(__name__)


class ExecSession(BaseSession):
    def __init__(
        self,
        ssm,
        instance_id,
        command,
        region_name=AWS_DEFAULT_REGION,
        profile_name=AWS_DEFAULT_PROFILE,
    ):
        self._command = " ".join(command)
        super().__init__(ssm, instance_id, region_name, profile_name,
            session_parameters = {
                "Target": instance_id,
                "DocumentName": "AWS-StartInteractiveCommand",
                "Parameters": {"command": [self._command]},
            })


@plugin_required
@plugin_version("1.1.23.0")
@valid_aws_profile
@valid_aws_region
def execute(
    config,
    instance_name,
    command,
    profile_name=AWS_DEFAULT_PROFILE,
    region_name=AWS_DEFAULT_REGION,
):
    instance, profile, region = fetch_instance_details_from_config(
        config, instance_name, profile_name, region_name
    )

    ssm = get_aws_client("ssm", region_name=region, profile_name=profile)
    ec2 = get_aws_resource("ec2", region_name=region, profile_name=profile)

    instance_id = query_instance(name=instance, ec2=ec2)
    if instance_id is None:
        raise ValueError("No instance could be found for name: {}".format(instance))

    logger.info(
        'Executing command "%s"  on instance %s (%s) via profile %s',
        " ".join(command),
        instance_id,
        region,
        profile,
    )
    with ExecSession(ssm, instance_id, command, region_name=region) as sess:
        sess.open()
