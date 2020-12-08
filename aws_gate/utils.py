# -*- encoding: utf-8 -*-
from contextlib import contextmanager
import errno
from importlib import import_module
import logging
import os
import signal
import subprocess
import sys
from threading import currentThread
from types import ModuleType
from weakref import proxy

from aws_gate import __version__
from aws_gate.constants import (AWS_DEFAULT_PROFILE, AWS_DEFAULT_REGION,
                                DEFAULT_GATE_BIN_PATH, PLUGIN_NAME)

# import boto3
# import botocore.session
# from botocore import credentials


logger = logging.getLogger(__name__)

# This list is maintained by hand as new regions are not added that often. This should be
# removed once, we find a better way how to obtain region list without the need to
# contact AWS EC2 API
AWS_REGIONS = [
    "af-south-1",
    "ap-east-1",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-south-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ca-central-1",
    "cn-north-1",
    "cn-northwest-1",
    "eu-central-1",
    "eu-north-1",
    "eu-south-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "me-south-1",
    "sa-east-1",
    "us-east-1",
    "us-east-2",
    "us-gov-east-1",
    "us-gov-west-1",
    "us-west-1",
    "us-west-2",
]


class LazyLoader(ModuleType):

    def __init__(self, module_name):
        super().__init__(module_name)
        self._module_name = module_name
        self._moddep_loaded = []
        self._mod = None

    def load(self):
        if self._mod is None:
            before_import = sys.modules.copy()
            self._mod = proxy(import_module(
                self._module_name
            ))
            self._moddep_loaded = [mod for mod in sys.modules if mod not in before_import]
        return self._mod

    def unload(self):
        for mod in [m for m in sys.modules if m in self._moddep_loaded or sys.modules[m] is None]:
            # del sys.modules[mod]
            sys.modules[mod] = None

    def __getattr__(self, attrb):
        return getattr(self.load(), attrb)

    def __dir__(self):
        return dir(self._load())


boto3_session = LazyLoader('boto3.session')
credentials = LazyLoader('botocore.credentials')
botocore_hooks = LazyLoader('botocore.hooks')
botocore_session = LazyLoader('botocore.session')


def _create_aws_session(profile_name=None):
    logger.debug("Obtaining boto3 session object: %s", profile_name)
    kwargs = {}
    if profile_name is not None:
        kwargs["profile_name"] = profile_name

    # https://github.com/boto/boto3/issues/598
    if "AWS_ACCESS_KEY_ID" in os.environ:
        kwargs["aws_access_key_id"] = os.environ["AWS_ACCESS_KEY_ID"]
    if "AWS_SECRET_ACCESS_KEY" in os.environ:
        kwargs["aws_secret_access_key"] = os.environ["AWS_SECRET_ACCESS_KEY"]
    if "AWS_SESSION_TOKEN" in os.environ:
        kwargs["aws_session_token"] = os.environ["AWS_SESSION_TOKEN"]

    # By default the cache path is ~/.aws/boto/cache
    cli_cache = os.path.join(os.path.expanduser("~"), ".aws/cli/cache")

    # workaround, close connection per AWS API query
    # ref: https://gist.github.com/RyanGWU82/741a652eb816c0a6dacf
    def before_send_handler(**kwargs):
        req = kwargs.get('request')
        req.headers['Connection'] = 'close'

    # ref: https://gist.github.com/salrashid123/fec7339e245e118654948da3abb8b685
    # ref: https://gist.github.com/RyanGWU82/741a652eb816c0a6dacf
    # ref: https://pages.awscloud.com/rs/112-TZM-766/images/B-4.pdf
    hooks = botocore_hooks.HierarchicalEmitter()
    hooks.register(event_name="before-send.*", handler=before_send_handler)

    # Skip to automatically register builtin handlers botocore/handlers.py
    _sess = botocore_session.Session(profile=profile_name, event_hooks=hooks, include_builtin_handlers=False)
    # Add aws-gate version to the client user-agent
    _sess.user_agent_extra = "aws-gate/{}".format(__version__)
    _sess.get_component("credential_provider").get_provider(
        "assume-role"
    ).cache = credentials.JSONFileCache(cli_cache)

    return boto3_session.Session(botocore_session=_sess, **kwargs)


# inspired by https://github.com/boto/boto3/issues/1670
class AWSSession:
    def __init__(self, profile_name=None) -> None:
        self.profile_name = profile_name
        self.__key = profile_name or "default"

    def get_session(self):
        thread = currentThread()
        if not hasattr(thread, "__aws_metadata__"):
            thread.__aws_metadata__ = {
                "sessions": {}
            }
        sessions = thread.__aws_metadata__["sessions"]
        if not self.__key in sessions or sessions[self.__key] is None:
            sessions[self.__key] = _create_aws_session(profile_name=self.profile_name)

        return sessions[self.__key]

    def gc(self):
        thread = currentThread()
        for k in thread.__aws_metadata__["sessions"]:
            thread.__aws_metadata__["sessions"][k] = None


def get_aws_client(service_name, region_name, profile_name=None):
    session = AWSSession(profile_name).get_session()

    logger.debug("Obtaining %s client", service_name)
    return session.client(service_name=service_name, region_name=region_name)


def get_aws_resource(service_name, region_name, profile_name=None):
    session = AWSSession(profile_name).get_session()

    logger.debug("Obtaining %s boto3 resource", service_name)
    return session.resource(service_name=service_name, region_name=region_name)


def get_profile_region(args, config):
    profile = getattr(args, "profile", None) or \
        config.default_profile or \
        os.environ.get("AWS_VAULT") or \
        os.environ.get("AWS_PROFILE") or \
        AWS_DEFAULT_PROFILE

    session = AWSSession(profile).get_session()

    ap = session.available_profiles
    logger.debug(
        "Obtained configured AWS profiles: %s", " ".join(ap)
    )
    if not profile in ap :
        raise ValueError("Invalid profile provided: {}".format(profile))

    # boto3 will search `region` in order: env AWS_DEFAULT_REGION, ~/.aws/config
    # ref: https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html?highlight=region
    region = getattr(args, "region", None) or \
        config.default_region or \
        session.region_name or \
        AWS_DEFAULT_REGION

    if not region in AWS_REGIONS:
        raise ValueError("Invalid region provided: {}".format(region))

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

    env_path = DEFAULT_GATE_BIN_PATH + os.pathsep + os.environ["PATH"]
    env = os.environ.copy()
    env.update({"PATH": env_path})
    try:
        logger.debug("PATH in environment: %s", os.environ["PATH"])
        logger.debug("Executing %s", " ".join([cmd] + args))
        c = kwargs.pop('clear_modules', False)
        if c:
            AWSSession().gc()
            credentials.unload()
            boto3_session.unload()
            botocore_session.unload()

        result = subprocess.run([cmd] + args, env=env, check=True, **kwargs)
    except subprocess.CalledProcessError as e:
        logger.error(
            "Command %s exited with %s", " ".join([cmd] + args), e.returncode
        )
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise ValueError("{} cannot be found".format(cmd)) from e

    if result and result.stdout:
        ret = result.stdout.decode('utf-8').rstrip()

    return ret


def execute_plugin(args, **kwargs):
    with deferred_signals(kwargs.pop('deferred_signal_list', None)):
        return execute(PLUGIN_NAME, args, **kwargs)


def fetch_instance_details_from_config(
    config, instance_name, profile_name, region_name
):
    config_data = config.get_host(instance_name)
    if (
        config_data
        and config_data["name"]
        and config_data["profile"]
        and config_data["region"]
    ):
        logger.debug(
            "Entry found in configuration file for host alias: %s", instance_name
        )
        logger.debug(
            "Host alias data: host %s with AWS profile %s in region %s",
            config_data["name"],
            config_data["profile"],
            config_data["region"],
        )

        region = config_data["region"]
        profile = config_data["profile"]
        instance = config_data["name"]
    else:
        logger.debug("No entry found in configuration file for host: %s", instance_name)

        region = region_name
        profile = profile_name
        instance = instance_name

    return instance, profile, region
