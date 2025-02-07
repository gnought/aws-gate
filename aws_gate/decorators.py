import logging
import os
import platform
from pathlib import Path
from subprocess import PIPE

from packaging.version import parse as parse_version
from wrapt import decorator

from aws_gate.constants import (
    PLUGIN_INSTALL_PATH,
    PLUGIN_MINIMUM_VERSION_REQUIRED,
    PLUGIN_NAME,
)
from aws_gate.utils import execute_plugin

logger = logging.getLogger(__name__)


def _plugin_exists(plugin_path: Path):
    return plugin_path.is_file() and plugin_path.exists()


def _plugin_exists_in_path():
    return any(
        _plugin_exists(Path(p) / PLUGIN_NAME)
        for p in str(os.getenv("PATH", "")).split(os.path.pathsep)
    )


@decorator
def plugin_required(
    wrapped_function, instance, args, kwargs
):  # pylint: disable=unused-argument
    if (
        not _plugin_exists(PLUGIN_INSTALL_PATH)
        and not _plugin_exists_in_path()
        and not platform.system().lower() == "windows"
    ):
        raise OSError(f"{PLUGIN_NAME} not found")

    required_version = kwargs.pop("required_version", PLUGIN_MINIMUM_VERSION_REQUIRED)
    version = execute_plugin(["--version"], stdout=PIPE, stderr=PIPE)
    logger.debug(
        "session-manager-plugin version: %s (required version: %s)",
        version,
        required_version,
    )

    if version and parse_version(version) < parse_version(required_version):
        raise ValueError(f"Require plugin minimum version: {required_version}")

    return wrapped_function(*args, **kwargs)
