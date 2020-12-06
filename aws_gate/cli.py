# -*- encoding: utf-8 -*-
import argparse
import logging
import os
import sys

from marshmallow import ValidationError
from yaml.scanner import ScannerError

from aws_gate import __version__, __description__
from aws_gate.bootstrap import bootstrap
from aws_gate.config import load_config_from_files
from aws_gate.constants import (
    SUPPORTED_KEY_TYPES,
    DEBUG,
    AWS_DEFAULT_REGION,
    AWS_DEFAULT_PROFILE,
    DEFAULT_OS_USER,
    DEFAULT_SSH_PORT,
    DEFAULT_KEY_ALGORITHM,
    DEFAULT_KEY_SIZE,
    DEFAULT_LIST_HUMAN_FIELDS,
    DEFAULT_LIST_OUTPUT_FORMATS,
    DEFAULT_LIST_OUTPUT,
    DEFAULT_GATE_KEY_PATH,
)
from aws_gate.exec import execute
from aws_gate.list import list_instances
from aws_gate.session import session
from aws_gate.ssh import ssh
from aws_gate.ssh_config import ssh_config
from aws_gate.ssh_proxy import ssh_proxy
from aws_gate.utils import get_region

logger = logging.getLogger(__name__)


def _get_profile_region(args, config):
    profile = getattr(args, "profile", None) or \
        config.default_profile or \
        os.environ.get("AWS_VAULT") or \
        os.environ.get("AWS_PROFILE") or \
        AWS_DEFAULT_PROFILE

    region = getattr(args, "region", None) or \
        config.default_region or \
        get_region(profile) or \
        AWS_DEFAULT_REGION

    return profile, region


def get_argument_parser(*args, **kwargs):
    parser = argparse.ArgumentParser(*args, **kwargs)
    parser.add_argument(
        "-v", "--verbose", help="increase output verbosity", action="store_true"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s {version}".format(version=__version__),
    )
    subparsers = parser.add_subparsers(title="subcommands", dest="subcommand")

    # 'bootstrap' subcommand
    bootstrap_parser = subparsers.add_parser(
        "bootstrap", help="Download and install session-manager-plugin"
    )
    bootstrap_parser.add_argument(
        "-f", "--force", action="store_true", help="Forces bootstrap operation"
    )

    # 'exec' subcommand
    exec_parser = subparsers.add_parser(
        "exec", help="Execute interactive command on instance"
    )
    exec_parser.add_argument("-p", "--profile", help="AWS profile to use")
    exec_parser.add_argument("-r", "--region", help="AWS region to use")
    exec_parser.add_argument(
        "instance_name", help="Instance we wish to execute command on"
    )
    exec_parser.add_argument(
        "command", help="command to execute on the instance", nargs=argparse.REMAINDER
    )

    # 'session' subcommand
    session_parser = subparsers.add_parser(
        "session", help="Open new session on instance and connect to it"
    )
    session_parser.add_argument("-p", "--profile", help="AWS profile to use")
    session_parser.add_argument("-r", "--region", help="AWS region to use")
    session_parser.add_argument(
        "instance_name", help="Instance we wish to open session to"
    )

    # 'ssh' subcommand
    ssh_parser = subparsers.add_parser(
        "ssh", help="Open SSH session on instance and connect to it"
    )
    ssh_parser.add_argument("-p", "--profile", help="AWS profile to use")
    ssh_parser.add_argument("-r", "--region", help="AWS region to use")
    ssh_parser.add_argument(
        "-l", "--os-user", help="SSH user to use", type=str, default=DEFAULT_OS_USER
    )
    ssh_parser.add_argument(
        "-P", "--port", help="SSH port to use", type=int, default=DEFAULT_SSH_PORT
    )
    ssh_parser.add_argument(
        "-L",
        "--local_forwarding",
        "--forwarding",
        help="Specifies a port on the local host that is to be forwarded to the given host and port",  # noqa: B950
        default=None,
        dest="local_forward",
    )
    ssh_parser.add_argument(
        "-R",
        "--remote-forwarding",
        help="Specifies a port on the remote host that is to be forwarded to the local side",  # noqa: B950
        default=None,
        dest="remote_forward",
    )
    ssh_parser.add_argument(
        "-D",
        "--dynamic-forwarding",
        help="Specifies a dynamic application-level port forwarding",
        default=None,
        dest="dynamic_forward",
    )
    ssh_parser.add_argument(
        "--key-type",
        type=str,
        default=DEFAULT_KEY_ALGORITHM,
        choices=SUPPORTED_KEY_TYPES,
        help=argparse.SUPPRESS,
    )
    ssh_parser.add_argument(
        "--key-size", type=int, default=DEFAULT_KEY_SIZE, help=argparse.SUPPRESS
    )
    ssh_parser.add_argument("instance_name", help="Instance we wish to open session to")
    ssh_parser.add_argument(
        "command", help="command to execute on the instance", nargs=argparse.REMAINDER
    )

    # 'ssh_config' subcommand
    ssh_config_parser = subparsers.add_parser(
        "ssh-config", help="Generate SSH configuration file"
    )
    ssh_config_parser.add_argument("-p", "--profile", help="AWS profile to use")
    ssh_config_parser.add_argument("-r", "--region", help="AWS region to use")
    ssh_config_parser.add_argument(
        "-l", "--os-user", help="SSH user to use", type=str, default=DEFAULT_OS_USER
    )
    ssh_config_parser.add_argument(
        "-P", "--port", help="SSH port to use", type=int, default=DEFAULT_SSH_PORT
    )

    # 'ssh-proxy' subcommand
    ssh_proxy_parser = subparsers.add_parser(
        "ssh-proxy", help="Open new SSH proxy session to instance"
    )
    ssh_proxy_parser.add_argument("-p", "--profile", help="AWS profile to use")
    ssh_proxy_parser.add_argument("-r", "--region", help="AWS region to use")
    ssh_proxy_parser.add_argument(
        "-l", "--os-user", help="SSH user to use", type=str, default=DEFAULT_OS_USER
    )
    ssh_proxy_parser.add_argument(
        "-P", "--port", help="SSH port to use", type=int, default=DEFAULT_SSH_PORT
    )
    ssh_proxy_parser.add_argument(
        "--key-type",
        type=str,
        default=DEFAULT_KEY_ALGORITHM,
        choices=SUPPORTED_KEY_TYPES,
        help=argparse.SUPPRESS,
    )
    ssh_proxy_parser.add_argument(
        "--key-size", type=int, default=DEFAULT_KEY_SIZE, help=argparse.SUPPRESS
    )
    ssh_proxy_parser.add_argument(
        "--key-path",
        type=str,
        default=DEFAULT_GATE_KEY_PATH,
    )
    ssh_proxy_parser.add_argument(
        "instance_name", help="Instance we wish to open session to"
    )

    # 'list' subcommand
    ls_parser = subparsers.add_parser(
        "list", aliases=["ls"], help="List available instances"
    )
    ls_parser.add_argument("-p", "--profile", help="AWS profile to use")
    ls_parser.add_argument("-r", "--region", help="AWS region to use")
    ls_parser.add_argument(
        "-f",
        "--format",
        help="Output format",
        default=DEFAULT_LIST_OUTPUT,
        choices=DEFAULT_LIST_OUTPUT_FORMATS,
    )
    ls_parser.add_argument(
        "-o",
        "--output",
        help=argparse.SUPPRESS,
        default=",".join(DEFAULT_LIST_HUMAN_FIELDS),
    )

    return parser, subparsers


def parse_arguments(parser=None):
    if not parser:
        parser, *_ = get_argument_parser(description=__description__)

    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        sys.exit(1)

    return args


def main(args=None, argument_parser=None):
    if not args:
        args = parse_arguments(argument_parser)

    if not DEBUG:
        sys.excepthook = lambda exc_type, exc_value, traceback: logger.error(exc_value)

    log_level = logging.ERROR
    log_format = "%(message)s"

    # We want to silence dependencies
    logging.getLogger("botocore").setLevel(logging.CRITICAL)
    logging.getLogger("boto3").setLevel(logging.CRITICAL)
    logging.getLogger("urllib3").setLevel(logging.CRITICAL)

    if args.verbose:
        log_level = logging.INFO

    if DEBUG:
        log_level = logging.DEBUG
        log_format = "%(asctime)s - %(name)-28s - %(levelname)-5s - %(message)s"

    logging.basicConfig(level=log_level, stream=sys.stderr, format=log_format)

    if args.subcommand == "bootstrap":
        bootstrap(force=args.force)
        sys.exit(0)

    try:
        config = load_config_from_files()
    except (ValidationError, ScannerError) as e:
        raise ValueError("Invalid configuration provided: {}".format(e)) from None

    # We try to obtain default profile from the environment or use 'default' to
    # save a call to boto3. In the environment, we check if we are being called
    # from aws-vault first or not. Then we return 'default' as boto3 will
    # https://github.com/boto/boto3/blob/develop/boto3/session.py#L93
    if "AWS_VAULT" in os.environ:
        logger.debug(
            "aws-vault usage detected, defaulting to the AWS profile from $AWS_VAULT"
        )

    profile, region = _get_profile_region(args, config)

    logger.debug("Using AWS profile %s in region %s", profile, region)

    if args.subcommand == "exec":
        execute(
            config=config,
            instance_name=args.instance_name,
            command=args.command,
            region_name=region,
            profile_name=profile,
        )
    elif args.subcommand == "session":
        session(
            config=config,
            instance_name=args.instance_name,
            region_name=region,
            profile_name=profile,
        )
    elif args.subcommand == "ssh":
        ssh(
            config=config,
            instance_name=args.instance_name,
            region_name=region,
            profile_name=profile,
            user=args.os_user,
            port=args.port,
            key_type=args.key_type,
            key_size=args.key_size,
            command=args.command,
            local_forward=args.local_forward,
            remote_forward=args.remote_forward,
            dynamic_forward=args.dynamic_forward,
        )
    elif args.subcommand == "ssh-config":
        ssh_config(
            region_name=region, profile_name=profile, user=args.os_user, port=args.port
        )
    elif args.subcommand == "ssh-proxy":
        ssh_proxy(
            config=config,
            instance_name=args.instance_name,
            region_name=region,
            profile_name=profile,
            user=args.os_user,
            port=args.port,
            key_type=args.key_type,
            key_size=args.key_size,
            key_path=args.key_path,
        )
    elif args.subcommand in ["ls", "list"]:
        fields = args.output.split(",")
        list_instances(
            region_name=region,
            profile_name=profile,
            output_format=args.format,
            fields=fields,
        )


if __name__ == "__main__":  # pragma: no cover
    main()
