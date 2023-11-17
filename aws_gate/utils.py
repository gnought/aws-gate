# -*- encoding: utf-8 -*-
import errno
import logging
import os
import signal
import subprocess
import sys
from contextlib import contextmanager
from contextvars import ContextVar
from importlib import import_module
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING
from weakref import proxy

from aws_gate import __version__

if TYPE_CHECKING:
    from botocore.awsrequest import AWSPreparedRequest
    from aws_gate.config import GateConfig
    from botocore.hooks import HierarchicalEmitter
    from botocore import session
    from botocore.utils import JSONFileCache
    from boto3.session import Session
    from botocore.credentials import CredentialResolver

from aws_gate.constants import (
    AWS_DEFAULT_PROFILE,
    AWS_DEFAULT_REGION,
    DEFAULT_GATE_BIN_PATH,
    PLUGIN_NAME,
)

logger = logging.getLogger(__name__)


class LazyLoader(ModuleType):
    def __init__(self, module_name: str):
        super().__init__(module_name)
        self._module_name = module_name
        self._moddep_loaded = []
        self._mod = None

    def load(self):
        if self._mod is None:
            before_import = sys.modules.copy()
            self._mod = proxy(import_module(self._module_name))
            self._moddep_loaded = [
                mod for mod in sys.modules if mod not in before_import
            ]
        return self._mod

    def unload(self):
        for mod in [
            m for m in sys.modules if m in self._moddep_loaded or sys.modules[m] is None
        ]:
            # del sys.modules[mod]
            sys.modules[mod] = None  # type: ignore

    def __getattr__(self, attrb):
        return getattr(self.load(), attrb)

    def __dir__(self):
        return dir(self._load())


boto3_session = LazyLoader("boto3.session")
botocore_utils = LazyLoader("botocore.utils")
botocore_hooks = LazyLoader("botocore.hooks")
botocore_session = LazyLoader("botocore.session")


def _create_aws_session(profile_name: str | None = None):
    # type: (str | None) -> Session

    logger.debug("Obtaining boto3 session object: %s", profile_name)
    kwargs = {}
    if profile_name is not None:
        kwargs["profile_name"] = str(profile_name)

    # https://github.com/boto/boto3/issues/598
    if "AWS_ACCESS_KEY_ID" in os.environ:
        kwargs["aws_access_key_id"] = str(os.environ["AWS_ACCESS_KEY_ID"])
    if "AWS_SECRET_ACCESS_KEY" in os.environ:
        kwargs["aws_secret_access_key"] = str(os.environ["AWS_SECRET_ACCESS_KEY"])
    if "AWS_SESSION_TOKEN" in os.environ:
        kwargs["aws_session_token"] = str(os.environ["AWS_SESSION_TOKEN"])

    # workaround, close connection per AWS API query
    # ref: https://gist.github.com/RyanGWU82/741a652eb816c0a6dacf
    def before_send_handler(
        **kwargs,  # type: AWSPreparedRequest | None
    ):
        req = kwargs.get("request")
        if req is not None:
            req.headers["Connection"] = "close"

    # ref: https://gist.github.com/salrashid123/fec7339e245e118654948da3abb8b685
    # ref: https://gist.github.com/RyanGWU82/741a652eb816c0a6dacf
    # ref: https://pages.awscloud.com/rs/112-TZM-766/images/B-4.pdf
    hooks = botocore_hooks.HierarchicalEmitter()  # type: HierarchicalEmitter
    hooks.register(event_name="before-send.*", handler=before_send_handler)

    # Skip to automatically register builtin handlers botocore/handlers.py
    _sess = botocore_session.Session(
        profile=str(profile_name), event_hooks=hooks, include_builtin_handlers=False
    )  # type: session.Session
    # Add aws-gate version to the client user-agent
    _sess.user_agent_extra = f"aws-gate/{__version__}"

    # By default the cache path is ~/.aws/boto/cache
    cli_cache = str(Path.home() / ".aws/cli/cache")
    cache = botocore_utils.JSONFileCache(cli_cache)  # type: JSONFileCache
    credentials = _sess.get_component("credential_provider")  # type: CredentialResolver
    credentials.get_provider("assume-role").cache = cache

    return boto3_session.Session(botocore_session=_sess, **kwargs)


# inspired by https://github.com/boto/boto3/issues/1670
class AWSSession:
    def __init__(self, profile_name: str | None = None) -> None:
        self.__key = str(profile_name or "default")
        self.context = ContextVar("aws_sessions", default={})

    def get_session(self):
        sess = self.context.get().get(self.__key)  # type: Session | None
        if sess is None:
            sess = _create_aws_session(self.__key)
            self.context.set({self.__key: sess})
        return sess

    def gc(self):
        self.context.set({})


def get_aws_client(
    service_name: str, region_name: str, profile_name: str | None = None
):
    session = AWSSession(profile_name).get_session()
    logger.debug("Obtaining %s client", service_name)
    try:
        return session.client(service_name=service_name, region_name=region_name)  # type: ignore
    except Exception:
        raise


def get_aws_resource(
    service_name: str, region_name: str, profile_name: str | None = None
):
    session = AWSSession(profile_name).get_session()
    logger.debug("Obtaining %s boto3 resource", service_name)
    try:
        return session.resource(service_name=service_name, region_name=region_name)  # type: ignore
    except Exception:
        raise


def get_profile_region(args, config):
    profile = str(
        getattr(args, "profile", None)
        or config.default_profile
        or os.getenv("AWS_VAULT")
        or os.getenv("AWS_PROFILE")
        or AWS_DEFAULT_PROFILE
    )

    session = AWSSession(profile).get_session()

    ap: list[str] = session.available_profiles
    logger.debug("Obtained configured AWS profiles: %s", " ".join(ap))
    if not profile in ap:
        raise ValueError(f"Invalid profile provided: {profile}")

    # boto3 will search `region` in order: env AWS_DEFAULT_REGION, ~/.aws/config
    # ref: https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html?highlight=region
    region = str(
        getattr(args, "region", None)
        or config.default_region
        or session.region_name
        or AWS_DEFAULT_REGION
    )

    # TODO! slow?
    ar: list[str] = session.get_available_regions("ec2")
    logger.debug("Obtained configured AWS regions: %s", " ".join(ar))
    if not region in ar:
        raise ValueError(f"Invalid region provided: {region}")

    return profile, region


@contextmanager
def deferred_signals(signal_list=None):
    if signal_list is None:
        if hasattr(signal, "SIGHUP"):
            signal_list = [signal.SIGHUP, signal.SIGINT, signal.SIGTERM]
        else:  # pragma: no cover
            signal_list = [signal.SIGINT, signal.SIGTERM]

    for deferred_signal in signal_list:
        signal_name = signal.Signals(deferred_signal).name
        logger.debug("Deferring signal: %s", signal_name)
        signal.signal(deferred_signal, signal.SIG_IGN)

    try:
        yield
    finally:
        for deferred_signal in signal_list:
            signal_name = signal.Signals(deferred_signal).name
            logger.debug("Restoring signal: %s", signal_name)
            signal.signal(deferred_signal, signal.SIG_DFL)


def execute(cmd, args, **kwargs):
    ret, result = None, None

    env = os.environ.copy() | {
        "PATH": str(DEFAULT_GATE_BIN_PATH) + os.pathsep + os.environ["PATH"]
    }
    try:
        logger.debug("PATH in environment: %s", env["PATH"])
        logger.debug("Executing %s", " ".join([cmd] + args))
        c = kwargs.pop("clear_modules", False)
        if c:
            logger.debug("Releasing lazy modules")
            AWSSession().gc()
            boto3_session.unload()
            botocore_session.unload()
            botocore_utils.unload()
            botocore_hooks.unload()

        result = subprocess.run([cmd] + args, env=env, check=True, **kwargs)
    except subprocess.CalledProcessError as e:
        logger.error("Command %s exited with %s", " ".join([cmd] + args), e.returncode)
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise ValueError(f"{cmd} cannot be found") from e

    if result and result.stdout:
        ret = result.stdout.decode("utf-8").rstrip()

    return ret


def execute_plugin(args, **kwargs):
    with deferred_signals(kwargs.pop("deferred_signal_list", None)):
        return execute(PLUGIN_NAME, args, **kwargs)


def fetch_instance_details_from_config(
    config, instance_name, profile_name, region_name
):
    # type: (GateConfig, str, str, str) -> tuple[str, str, str]

    region = region_name
    profile = profile_name
    instance = instance_name

    if (
        (config_data := config.get_host(instance_name))
        and (instance := config_data["name"])
        and (profile := config_data["profile"])
        and (region := config_data["region"])
    ):
        logger.debug(
            "Entry found in configuration file for host alias: %s", instance_name
        )
        logger.debug(
            "Host alias data: host %s with AWS profile %s in region %s",
            instance,
            profile,
            region,
        )
    else:
        logger.debug("No entry found in configuration file for host: %s", instance_name)

    return instance, profile, region
