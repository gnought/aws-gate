# -*- encoding: utf-8 -*-
import logging
from typing import Any

from aws_gate.constants import DEFAULT_GATE_CONFIG, DEFAULT_GATE_CONFIGD_PATH

logger = logging.getLogger(__name__)


class GateConfig:
    def __init__(self, defaults: dict[str, Any] = {}, hosts: list[dict[str, Any]] = []):
        self._defaults = defaults
        self._hosts = hosts

    @property
    def hosts(self):
        return self._hosts

    @property
    def defaults(self):
        return self._defaults

    @property
    def default_region(self) -> str | None:
        return self._defaults.get("region")

    @property
    def default_profile(self) -> str | None:
        return self._defaults.get("profile")

    def get_host(self, name: str) -> dict[str, Any]:
        host = [host for host in self._hosts if host["alias"] == name]
        if host:
            return host[0]
        return {}


def _locate_config_files():
    config_files = (
        sorted(
            [f.absolute() for f in DEFAULT_GATE_CONFIGD_PATH.iterdir() if f.is_file()]
        )
        if DEFAULT_GATE_CONFIGD_PATH.is_dir()
        else []
    )

    if DEFAULT_GATE_CONFIG.is_file():
        config_files.append(DEFAULT_GATE_CONFIG)

    return config_files


def load_config_from_files():
    if not (config_files := _locate_config_files()):
        return GateConfig()

    from aws_gate.config_helper import load_config

    return load_config(config_files)
