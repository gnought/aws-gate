# -*- encoding: utf-8 -*-
import logging

from aws_gate.constants import AWS_DEFAULT_PROFILE, AWS_DEFAULT_REGION
from aws_gate.decorators import (
    plugin_version,
    plugin_required,
    valid_aws_profile,
    valid_aws_region,
)
from aws_gate.query import query_instance
from aws_gate.session_common import BaseSession
from aws_gate.utils import (
    fetch_instance_details_from_config,
)

logger = logging.getLogger(__name__)


class SSMSession(BaseSession):
    def __init__(
        self,
        instance_id,
        region_name=AWS_DEFAULT_REGION,
        profile_name=AWS_DEFAULT_REGION,
    ):
        super().__init__(instance_id, region_name, profile_name,
            session_parameters = {"Target": instance_id})


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

    instance_obj = query_instance(name=instance, region_name=region_name, profile_name=profile_name)
    if instance_obj is None:
        raise ValueError("No instance could be found for name: {}".format(instance_obj))

    instance_id = instance_obj.instance_id

    logger.info(
        "Opening session on instance %s (%s) via profile %s",
        instance_id,
        region,
        profile,
    )
    with SSMSession(instance_id, region_name=region_name, profile_name=profile_name) as sess:
        sess.open()
