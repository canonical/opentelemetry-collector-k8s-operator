# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

# TODO: Update once we have moved to a lib
"""OpenTelemetry protocol (OTLP) Library.

## Overview

This document explains how to integrate with the Opentelemetry-collector charm
for the purpose of providing OTLP telemetry to Opentelemetry-collector. This document is the
authoritative reference on the structure of relation data that is
shared between Opentelemetry-collector charms and any other charm that intends to
provide OTLP telemetry for Opentelemetry-collector.
"""

import json
import logging
import socket
from enum import Enum, unique
from typing import Any, Callable, ClassVar, Dict, List, Optional, Sequence

from cosl.juju_topology import JujuTopology
from ops import CharmBase
from ops.framework import Object
from pydantic import BaseModel, ConfigDict, ValidationError

DEFAULT_CONSUMER_RELATION_NAME = "send-otlp"
DEFAULT_PROVIDER_RELATION_NAME = "receive-otlp"
RELATION_INTERFACE_NAME = "otlp"

logger = logging.getLogger(__name__)


@unique
class ProtocolType(str, Enum):
    """OTLP protocols used by the OpenTelemetry Collector."""

    grpc = "grpc"
    """gRPC protocol for sending/receiving OTLP data."""
    http = "http"
    """HTTP protocol for sending/receiving OTLP data."""


@unique
class TelemetryType(str, Enum):
    """OTLP telemetries used by the OpenTelemetry Collector."""

    log = "logs"
    """OTLP logs data."""
    metric = "metrics"
    """OTLP metrics data."""
    trace = "traces"
    """OTLP traces data."""


class ProtocolPort(BaseModel):
    """A pydantic model for OTLP protocols and their associated port."""

    model_config = ConfigDict(extra="forbid")

    grpc: Optional[int] = None
    http: Optional[int] = None


class OtlpEndpoint(BaseModel):
    """A pydantic model for a single OTLP endpoint."""

    model_config = ConfigDict(extra="forbid")

    protocol: ProtocolType
    endpoint: str
    telemetries: List[TelemetryType]


class OtlpProviderUnitData(BaseModel):
    """A pydantic model for the OTLP provider's data bag.

    {
        'egress-subnets': '192.0.2.0'
        snip ...
        'otlp': {
            'secure': 'false',
            'endpoints': '[{"protocol": "grpc", "endpoint": "foo"}]',
        }
    }
    """

    KEY: ClassVar[str] = "otlp"

    model_config = ConfigDict(extra="forbid")

    secure: bool = True
    endpoints: List[OtlpEndpoint]


class OtlpConsumer(Object):
    """A class for consuming OTLP endpoints."""

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str = DEFAULT_CONSUMER_RELATION_NAME,
        protocols: Optional[Sequence[ProtocolType]] = None,
    ):
        super().__init__(charm, relation_name)
        self._charm = charm
        self._relation_name = relation_name
        self._protocols = list(protocols) if protocols is not None else []

        self.topology = JujuTopology.from_charm(charm)

    def _get_unit_databag(self, endpoints: List[Dict[str, Any]]) -> Optional[OtlpProviderUnitData]:
        # TODO: This can be a method of the OtlpProviderUnitData class
        otlp_endpoints = []
        for endpoint in endpoints:
            # Filter out any unsupported telemetry types before validation
            endpoint["telemetries"] = [
                t for t in endpoint.get("telemetries", []) if t in set(TelemetryType)
            ]
            try:
                otlp_endpoints.append(OtlpEndpoint.model_validate(endpoint))
            except ValidationError as e:
                logger.error(f"OTLP endpoint failed validation: {e}")

        try:
            databag = OtlpProviderUnitData(secure=False, endpoints=otlp_endpoints)
        except ValidationError as e:
            logger.error(f"OTLP endpoint failed validation: {e}")
            return None

        return databag

    def get_remote_otlp_endpoints(self) -> Dict[int, Dict[str, OtlpEndpoint]]:
        """Return a mapping of relation ID to a mapping of unit name to OtlpProviderUnitData.

        For each remote unit's list of OtlpEndpoints:
            - If a telemetry type is not supported, then the endpoint is accepted, but the
              telemetry is ignored.
            - If the endpoint contains an unsupported protocol it is ignored.
            - The first available (and supported) endpoint is returned.

        The returned structure is as follows:
        {
            rel-n: {
                unit-n: OtlpProviderUnitData([OtlpEndpoint, ...])
            },
        }
        """
        aggregate = {}
        for rel in self.model.relations[self._relation_name]:
            unit_databags = {}
            for remote_unit in list(rel.units):
                otlp = json.loads(rel.data[remote_unit].get(OtlpProviderUnitData.KEY, "{}"))
                if unit_databag := self._get_unit_databag(otlp.get("endpoints", [])):
                    if endpoint_choice := next(
                        (e for e in unit_databag.endpoints if e.protocol in self._protocols), None
                    ):
                        unit_databags[remote_unit.name] = endpoint_choice

            aggregate[rel.id] = unit_databags

        return aggregate


class OtlpProvider(Object):
    """A class for publishing all supported OTLP endpoints."""

    def __init__(
        self,
        charm: CharmBase,
        # TODO: Should we accept a ProtocolType instead?
        protocol_ports: Dict[str, int],
        relation_name: str = DEFAULT_PROVIDER_RELATION_NAME,
        path: str = "",
        supported_telemetries: List[TelemetryType] = list(TelemetryType),
        server_host_func: Callable[[], str] = lambda: f"http://{socket.getfqdn()}",
    ):
        super().__init__(charm, relation_name)
        self._charm = charm
        self._relation_name = relation_name
        self._protocol_ports = ProtocolPort(**protocol_ports)
        self._path = path
        self._supported_telemetries = supported_telemetries
        self._get_server_host = server_host_func

        self._reconcile()

    def _reconcile(self) -> None:
        for relation in self.model.relations[self._relation_name]:
            otlp = {
                OtlpProviderUnitData.KEY: OtlpProviderUnitData(
                    secure=False, endpoints=self.otlp_endpoints
                ).model_dump(exclude_none=True)
            }
            relation.data[self._charm.unit].update({k: json.dumps(v) for k, v in otlp.items()})

    @property
    def otlp_endpoints(self) -> List[OtlpEndpoint]:
        """List all available OTLP endpoints for this server."""
        endpoints = []
        for protocol, port in self._protocol_ports.model_dump(exclude_none=True).items():
            endpoint = f"{self._get_server_host().rstrip('/')}:{port}"
            if self._path:
                endpoint += f"/{self._path.rstrip('/')}"
            endpoints.append(
                OtlpEndpoint(
                    protocol=ProtocolType(protocol),
                    endpoint=endpoint,
                    telemetries=self._supported_telemetries,
                )
            )
        return endpoints
