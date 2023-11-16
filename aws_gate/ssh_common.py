# -*- encoding: utf-8 -*-
import logging
import os
import sys
import weakref
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

if TYPE_CHECKING:
    from mypy_boto3_ec2_instance_connect import EC2InstanceConnectClient

from aws_gate.constants import (
    DEFAULT_GATE_KEY_PATH,
    DEFAULT_OS_USER,
    KEY_MIN_SIZE,
    SUPPORTED_KEY_TYPES,
)
from aws_gate.utils import get_aws_client

logger = logging.getLogger(__name__)


class SshKey:
    def __init__(
        self,
        key_path=DEFAULT_GATE_KEY_PATH,
        key_type: str = "rsa",
        key_size: int = KEY_MIN_SIZE,
    ):
        self.key_path = key_path
        self.key_type = key_type
        self.key_size = key_size
        self._private_key: rsa.RSAPrivateKey | ed25519.Ed25519PrivateKey
        self._public_key: rsa.RSAPublicKey | ed25519.Ed25519PublicKey

        self._finalizer = weakref.finalize(self, os.remove, self.key_path.name)

    def __enter__(self):
        self.generate()
        self.write_to_file()
        return self

    def __exit__(self, *args):
        self.delete()

    def _generate_key(self):
        logger.debug("Generating One-time SSH %s Key", self.key_type)

        if self.key_type == "rsa":
            self._private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size,
                backend=default_backend(),
            )
        elif self.key_type == "ed25519":
            self._private_key = ed25519.Ed25519PrivateKey.generate()

        self._public_key = self._private_key.public_key()

    def generate(self):
        self._generate_key()

    def write_to_file(self):
        logger.debug("Writing One-time SSH Key in %s", self.key_path)
        self.key_path.write_bytes(self.private_key)
        # 'ssh' refuses to use the key with broad access permissions
        os.chmod(self.key_path, 0o600)

    def delete(self):
        try:
            self._finalizer()
        except FileNotFoundError:
            pass

    @property
    def public_key(self):
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )

    @property
    def private_key(self):
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @property
    def key_type(self):
        return self._key_type

    @key_type.setter
    def key_type(self, value: str):
        if not value or value not in SUPPORTED_KEY_TYPES:
            raise ValueError(f"Unsupported or invalid key type: {value}")
        self._key_type = value

    @property
    def key_path(self):
        return self._key_path

    @key_path.setter
    def key_path(self, value: str | Path):
        self._key_path = Path(value or "")
        if not self.key_path.is_file():
            raise ValueError(f"Invalid key path: {value}")

    @property
    def key_size(self):
        return self._key_size

    @key_size.setter
    def key_size(self, value: int):
        if value < KEY_MIN_SIZE:
            raise ValueError(f"Invalid key size: {value}")
        self._key_size = value


class SshKeyUploader:
    def __init__(
        self,
        ssh_key: SshKey,
        instance_id,
        az,
        region_name,
        profile_name,
        user=DEFAULT_OS_USER,
    ):
        self._instance_id = instance_id
        self._az = az
        self._ssh_key = ssh_key
        self._user = user
        self._region_name = region_name
        self._profile_name = profile_name

    def __enter__(self):
        self.upload()
        return self

    def __exit__(self, *args):
        pass

    def upload(self):
        ec2_ic = get_aws_client(
            "ec2-instance-connect", self._region_name, self._profile_name
        )  # type: EC2InstanceConnectClient
        logger.debug("Uploading SSH public key: %s", self._ssh_key.public_key.decode())
        response = weakref.proxy(ec2_ic).send_ssh_public_key(
            InstanceId=self._instance_id,
            InstanceOSUser=self._user,
            SSHPublicKey=str(self._ssh_key.public_key.decode()),
            AvailabilityZone=self._az,
        )

        # tweak memory
        for mod in [
            m
            for m in sys.modules
            if m.startswith("cryptography.hazmat") or sys.modules[m] is None
        ]:
            # del sys.modules[mod]
            sys.modules[mod] = None

        logger.debug("Received response: %s", response)
        if not response["Success"]:
            raise ValueError(
                f"Failed to upload SSH key to instance {self._instance_id}"
            )
