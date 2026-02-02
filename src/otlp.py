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
from typing import Callable, Dict, List, Optional, Sequence

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
    """A pydantic model for the OTLP provider's databag."""

    model_config = ConfigDict(extra="forbid")

    data: List[OtlpEndpoint]


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

    def get_remote_otlp_endpoints(self) -> Dict[int, OtlpEndpoint]:
        """Return a single OtlpEndpoint per relation.

        Attempt to find the endpoint for the consumer's desired protocol in the provider databag.
        If it is not found, return the next available endpoint.
        """
        databags = self._get_remote_databags()

        aggregate = {}
        for rel_id, databag in databags.items():
            # An OTLP server can support multiple endpoints. Choose the first endpoint available.
            if preferred_endpoint := next(
                (e for e in databag.data if e.protocol in self._protocols), None
            ):
                aggregate[rel_id] = preferred_endpoint

        return aggregate

    def _get_remote_databags(self) -> Dict[int, OtlpProviderUnitData]:
        """Return a mapping of relation ID to OtlpProviderUnitData.

        Attempt to load the remote databag as a list of OtlpEndpoints. If a telemetry type is not
        supported, then it is ignored.
        """
        aggregate = {}
        otlp_endpoints = []
        for rel in self.model.relations[self._relation_name]:
            for unit in list(rel.units):
                if not (data := rel.data[unit].get("data")):
                    # TODO: Set status message?
                    continue
                for endpoint in json.loads(data):
                    try:
                        # TODO: Set status message?
                        endpoint["telemetries"] = [
                            e for e in endpoint["telemetries"] if e in set((TelemetryType))
                        ]
                        otlp_endpoints.append(OtlpEndpoint(**endpoint))
                    except ValidationError as e:
                        # TODO: Set status message?
                        logger.error(f"OTLP endpoint failed validation for {rel}: {e}")

                databag = OtlpProviderUnitData(data=otlp_endpoints)
                aggregate[rel.id] = databag

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
            relation.data[self._charm.unit]["data"] = OtlpProviderUnitData(
                data=self.otlp_endpoints
            ).model_dump_json(exclude_none=True)

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
