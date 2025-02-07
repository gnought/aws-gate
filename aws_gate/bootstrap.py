import logging
import os
import shutil
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from subprocess import PIPE
from urllib.parse import urlparse

import requests

from aws_gate.constants import PLUGIN_INSTALL_PATH, PLUGIN_NAME, SSM_PLUGIN_PATH
from aws_gate.exceptions import UnsupportedPlatormError
from aws_gate.safetarfile import SafeTarFile
from aws_gate.utils import execute

logger = logging.getLogger(__name__)


def _check_plugin_version(path=PLUGIN_INSTALL_PATH):
    return execute(path, ["--version"], stdout=PIPE, stderr=PIPE)


class Plugin(ABC):
    def __init__(self, url: str) -> None:
        self.url = url

    @property
    def is_installed(self):
        logger.debug("Checking if %s exists and is executable", PLUGIN_INSTALL_PATH)
        return shutil.which(PLUGIN_INSTALL_PATH) is not None

    def download(self):
        tmp_dir = Path(tempfile.mkdtemp())
        download_path = tmp_dir / Path(urlparse(self.url).path).parts[-1]
        try:
            logger.debug("Downloading session-manager-plugin archive from %s", self.url)
            with requests.get(self.url, stream=True, timeout=10) as req:
                req.raise_for_status()
                with open(download_path, "wb") as f:
                    shutil.copyfileobj(req.raw, f)
                    logger.debug("Download stored at %s", download_path)
        except requests.exceptions.HTTPError as e:
            logger.error("HTTP error while downloading %s: %s", self.url, e)
        return download_path

    @abstractmethod
    def extract(self, dst: Path, abs_filename: Path):
        pass

    def install(self):
        dst_path = PLUGIN_INSTALL_PATH.parent
        logger.debug("Creating %s", dst_path)
        dst_path.mkdir(mode=0o755, parents=True, exist_ok=True)
        logger.debug("Extracting session-manager-plugin archive at %s", dst_path)
        self.extract(dst_path, self.download())
        os.chmod(PLUGIN_INSTALL_PATH, 0o755)
        version = _check_plugin_version(PLUGIN_INSTALL_PATH)
        print(f"{PLUGIN_NAME} (version {version}) installed successfully!")


class MacPlugin(Plugin):
    def extract(self, dst, abs_filename):
        try:
            from zipfile import ZipFile

            with ZipFile(abs_filename) as zObject:
                zObject.extract(PLUGIN_NAME, path=dst)
        except Exception:
            raise ValueError(
                f"Invalid macOS session-manager-plugin ZIP file found {abs_filename}"
            )


class LinuxPlugin(Plugin):
    def extract(self, dst, abs_filename):
        import unix_ar

        ar_file = unix_ar.open(abs_filename)
        tarball = ar_file.open("data.tar.gz/")
        tar_file = SafeTarFile.open(fileobj=tarball)
        tar_file.extract(PLUGIN_NAME, path=dst)


def bootstrap(force=False):
    import platform

    system = platform.system().lower()
    if system == "darwin":
        plugin = MacPlugin(SSM_PLUGIN_PATH["Darwin"]["download"])
    elif system == "linux":
        plugin = LinuxPlugin(SSM_PLUGIN_PATH["Linux"]["download"])
    else:
        raise UnsupportedPlatormError(
            f"Unable to bootstrap session-manager-plugin on {system}"
        )

    if not plugin.is_installed or force:
        plugin.install()
