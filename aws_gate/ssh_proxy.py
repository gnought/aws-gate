# -*- encoding: utf-8 -*-
import logging

from aws_gate.constants import (
    AWS_DEFAULT_PROFILE,
    AWS_DEFAULT_REGION,
    DEFAULT_OS_USER,
    DEFAULT_SSH_PORT,
    DEFAULT_KEY_ALGORITHM,
    DEFAULT_KEY_SIZE,
    DEFAULT_GATE_KEY_PATH,
)
from aws_gate.decorators import (
    plugin_version,
    plugin_required,
)
from aws_gate.query import query_instance
from aws_gate.session_common import BaseSession
from aws_gate.ssh_common import SshKey, SshKeyUploader
from aws_gate.utils import (
    fetch_instance_details_from_config,
)

logger = logging.getLogger(__name__)


class SshProxySession(BaseSession):
    def __init__(
        self,
        instance_id,
        region_name=AWS_DEFAULT_REGION,
        profile_name=AWS_DEFAULT_PROFILE,
        port=DEFAULT_SSH_PORT,
        user=DEFAULT_OS_USER,
    ):
        super().__init__(instance_id, region_name, profile_name,
            session_parameters = {
                "Target": instance_id,
                "DocumentName": "AWS-StartSSHSession",
                "Parameters": {"portNumber": [str(port)]},
            })
        self._port = port
        self._user = user


@plugin_required
@plugin_version("1.2.30.0")
def ssh_proxy(
    config,
    instance_name,
    user=DEFAULT_OS_USER,
    port=DEFAULT_SSH_PORT,
    key_type=DEFAULT_KEY_ALGORITHM,
    key_size=DEFAULT_KEY_SIZE,
    key_path=DEFAULT_GATE_KEY_PATH,
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
    az = instance_obj.placement["AvailabilityZone"]

    logger.info(
        "Opening SSH proxy session on instance %s (%s) via profile %s",
        instance_id,
        region,
        profile,
    )
    with SshKey(key_path=key_path, key_type=key_type, key_size=key_size) as ssh_key:
        with SshKeyUploader(
            instance_id=instance_id, az=az, region_name=region, profile_name=profile, user=user, ssh_key=ssh_key
        ):
            with SshProxySession(
                instance_id,
                region_name=region,
                profile_name=profile,
                port=port,
                user=user,
            ) as ssh_proxy_session:
                ssh_proxy_session.open(deferred_signal_list=[])
