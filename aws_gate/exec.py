# -*- encoding: utf-8 -*-
import logging

from aws_gate.constants import AWS_DEFAULT_PROFILE, AWS_DEFAULT_REGION
from aws_gate.decorators import (
    plugin_required,
)
from aws_gate.query import query_instance
from aws_gate.session_common import BaseSession
from aws_gate.utils import (
    fetch_instance_details_from_config,
)

logger = logging.getLogger(__name__)


class ExecSession(BaseSession):
    def __init__(
        self,
        instance_id,
        command,
        region_name=AWS_DEFAULT_REGION,
        profile_name=AWS_DEFAULT_PROFILE,
    ):
        self._command = " ".join(command)
        super().__init__(instance_id, region_name, profile_name,
            session_parameters = {
                "Target": instance_id,
                "DocumentName": "AWS-StartInteractiveCommand",
                "Parameters": {"command": [self._command]},
            })


@plugin_required
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

    instance_obj = query_instance(name=instance, region_name=region_name, profile_name=profile_name)
    if instance_obj is None:
        raise ValueError("No instance could be found for name: {}".format(instance_obj))

    instance_id = instance_obj.instance_id

    logger.info(
        "Executing command %s on instance %s (%s) via profile %s",
        " ".join(command),
        instance_id,
        region,
        profile,
    )
    with ExecSession(instance_id, command, region_name=region) as sess:
        sess.open()
