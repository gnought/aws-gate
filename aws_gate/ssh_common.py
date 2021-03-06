# -*- encoding: utf-8 -*-
import logging
import os
import sys
import weakref

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519

from aws_gate.utils import (
    get_aws_client,
)

from aws_gate.constants import (
    DEFAULT_GATE_KEY_PATH,
    DEFAULT_KEY_SIZE,
    SUPPORTED_KEY_TYPES,
    DEFAULT_OS_USER,
)

logger = logging.getLogger(__name__)

KEY_MIN_SIZE = DEFAULT_KEY_SIZE


class SshKey:
    def __init__(
        self, key_path=DEFAULT_GATE_KEY_PATH, key_type="rsa", key_size=KEY_MIN_SIZE
    ):
        self._key_path = None
        self._key_type = None
        self._key_size = None
        self._private_key = None
        self._public_key = None

        self.key_path = key_path
        self.key_type = key_type
        self.key_size = key_size

        self._finalizer = weakref.finalize(self, os.remove, self._key_path.name)

    def __enter__(self):
        self.generate()
        self.write_to_file()
        return self

    def __exit__(self, *args):
        self.delete()

    def _generate_key(self):
        logger.debug("Generating One-time SSH %s Key", self._key_type)

        self._private_key = None

        if self._key_type == "rsa":
            self._private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self._key_size,
                backend=default_backend(),
            )
        elif self._key_type == "ed25519":
            self._private_key = ed25519.Ed25519PrivateKey.generate()

        self._public_key = self._private_key.public_key()

    def generate(self):
        self._generate_key()

    def write_to_file(self):
        logger.debug("Writing One-time SSH Key in %s", self._key_path.name)
        with self._key_path as f:
            f.write(self.private_key)
        # 'ssh' refuses to use the key with broad access permissions
        os.chmod(self._key_path.name, 0o600)

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
    def key_type(self, value):
        if not value or value not in SUPPORTED_KEY_TYPES:
            raise ValueError("Unsupported or invalid key type: {}".format(value))

        self._key_type = value

    @property
    def key_path(self):
        return self._key_path

    @key_path.setter
    def key_path(self, value):
        if not value:
            raise ValueError("Invalid key path: {}".format(value))
        self._key_path = value

    @property
    def key_size(self):
        return self._key_size

    @key_size.setter
    def key_size(self, value):
        if value < KEY_MIN_SIZE:
            raise ValueError("Invalid key size: {}".format(value))

        self._key_size = value


class SshKeyUploader:
    def __init__(
        self, instance_id, az, region_name, profile_name, user=DEFAULT_OS_USER, ssh_key=None
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
        )
        logger.debug("Uploading SSH public key: %s", self._ssh_key.public_key.decode())
        response = weakref.proxy(ec2_ic).send_ssh_public_key(
            InstanceId=self._instance_id,
            InstanceOSUser=self._user,
            SSHPublicKey=str(self._ssh_key.public_key.decode()),
            AvailabilityZone=self._az,
        )
        # tweak memory
        for mod in [ m for m in sys.modules if m.startswith('cryptography.hazmat') or sys.modules[m] is None ]:
            # del sys.modules[mod]
            sys.modules[mod] = None

        logger.debug("Received response: %s", response)
        if not response["Success"]:
            raise ValueError(
                "Failed to upload SSH key to instance {}".format(self._instance_id)
            )
