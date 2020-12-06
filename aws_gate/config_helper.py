# -*- encoding: utf-8 -*-
import logging

import yaml
from marshmallow import Schema, fields, post_load, ValidationError
from yaml.constructor import ConstructorError
from yaml.parser import ParserError
from yaml.scanner import ScannerError

from aws_gate.config import GateConfig
from aws_gate.utils import is_existing_profile, is_existing_region

logger = logging.getLogger(__name__)


class EmptyConfigurationError(Exception):
    pass


def validate_profile(profile):
    if not is_existing_profile(profile):
        raise ValidationError("Invalid profile provided: {}".format(profile))


def validate_region(region):
    if not is_existing_region(region):
        raise ValidationError("Invalid region name provided: {}".format(region))


def validate_defaults(data):
    schema = DefaultsSchema()
    schema.load(data)


class DefaultsSchema(Schema):
    profile = fields.String(required=False, validate=validate_profile)
    region = fields.String(required=False, validate=validate_region)


class HostSchema(Schema):
    alias = fields.String(required=True)
    name = fields.String(required=True)
    profile = fields.String(required=True, validate=validate_profile)
    region = fields.String(required=True, validate=validate_region)


class GateConfigSchema(Schema):
    defaults = fields.Nested(
        DefaultsSchema, required=False, missing=dict(), validate=validate_defaults
    )
    hosts = fields.List(fields.Nested(HostSchema), required=False, missing=list())

    # pylint: disable=no-self-use,unused-argument
    @post_load
    def create_config(self, data, **kwargs):
        return GateConfig(**data)


def _merge_data(src, dst):
    if isinstance(dst, dict):
        if isinstance(src, dict):
            for key in src:
                if key in dst:
                    dst[key] = _merge_data(src[key], dst[key])
                else:
                    dst[key] = src[key]
        else:
            raise TypeError(
                "Cannot merge {} with dict, src={} dst={}".format(
                    type(src).__name__, src, dst
                )
            )

    elif isinstance(dst, list):
        if isinstance(src, list):
            dst.extend(src)
        else:
            dst.append(src)
    else:
        dst = src

    return dst


def _merge_defaults(config_data):
    for host in config_data.get("hosts", []):
        for key, value in config_data.get("defaults", {}).items():
            if key not in host:
                host[key] = value


def load_config(config_files=None):
    config_data, data = {}, {}

    for path in config_files:
        try:
            with open(path, "r") as config_file:
                data = yaml.safe_load(config_file) or {}
        except (ConstructorError, ParserError):
            data = {}
        _merge_data(data, config_data)

    if not config_data:
        raise EmptyConfigurationError("Empty configuration data")

    _merge_defaults(config_data)

    try:
        config = GateConfigSchema().load(config_data)
    except (ValidationError, ScannerError) as e:
        raise ValueError("Invalid configuration provided: {}".format(e)) from None

    return config
