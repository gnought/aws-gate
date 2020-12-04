# -*- encoding: utf-8 -*-
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
from aws_gate.utils import get_aws_resource

logger = logging.getLogger(__name__)


class SSMSession(BaseSession):
    def __init__(
        self,
        instance_id,
        region_name=AWS_DEFAULT_REGION,
        profile_name=AWS_DEFAULT_PROFILE,
    ):
        super().__init__(
            instance_id,
            region_name,
            profile_name,
            session_parameters={"Target": instance_id},
        )


@plugin_required
@plugin_version("1.2.30.0")
@valid_aws_profile
@valid_aws_region
def session(
    config,
    instance_name,
    profile_name=AWS_DEFAULT_PROFILE,
    region_name=AWS_DEFAULT_REGION,
):
    instance, profile, region = fetch_instance_details_from_config(
        config, instance_name, profile_name, region_name
    )

    ec2 = get_aws_resource("ec2", region_name=region, profile_name=profile)

    instance_id = query_instance(name=instance, ec2=ec2).instance_id
    if instance_id is None:
        raise ValueError(f"No instance could be found for name: {instance}")

    logger.info(
        "Opening session on instance %s (%s) via profile %s",
        instance_id,
        region,
        profile,
    )
    with SSMSession(instance_id, region_name=region, profile_name=profile) as sess:
        sess.open()
