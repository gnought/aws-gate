# -*- encoding: utf-8 -*-
import logging
import os

from aws_gate.constants import DEFAULT_GATE_CONFIG_PATH, DEFAULT_GATE_CONFIGD_PATH

logger = logging.getLogger(__name__)


class GateConfig:
    def __init__(self, defaults=None, hosts=None):
        self._defaults = defaults or {}
        self._hosts = hosts or []

    @property
    def hosts(self):
        return self._hosts

    @property
    def defaults(self):
        return self._defaults

    @property
    def default_region(self):
        return self._defaults.get("region", None)

    @property
    def default_profile(self):
        return self._defaults.get("profile", None)

    def get_host(self, name):
        host = [host for host in self._hosts if host["alias"] == name]
        if host:
            return host[0]
        return {}


def _locate_config_files():
    config_files = []

    if os.path.isdir(DEFAULT_GATE_CONFIGD_PATH):
        configd_files = sorted(os.listdir(DEFAULT_GATE_CONFIGD_PATH))
        for f in configd_files:
            file_path = os.path.join(DEFAULT_GATE_CONFIGD_PATH, f)
            if os.path.isfile(file_path):
                logger.debug("Located config file: %s", file_path)
                config_files.append(file_path)

    if os.path.isfile(DEFAULT_GATE_CONFIG_PATH):
        logger.debug("Located config file: %s", DEFAULT_GATE_CONFIG_PATH)
        config_files.append(DEFAULT_GATE_CONFIG_PATH)

    return config_files


def load_config_from_files(config_files=None):
    if config_files is None:
        config_files = _locate_config_files()

    if not config_files:
        return GateConfig()

    from aws_gate.config_helper import load_config
    return load_config(config_files)
