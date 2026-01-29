# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Prometheus Scrape Library.

## Overview

This document explains how to integrate with the Opentelemetry-collector charm
for the purpose of providing OTLP telemetry to Opentelemetry-collector. This document is the
authoritative reference on the structure of relation data that is
shared between Opentelemetry-collector charms and any other charm that intends to
provide OTLP telemetry for Opentelemetry-collector.
"""

# TODO: Move to a lib
import json
import logging
import socket
from enum import Enum, unique
from typing import Callable, Dict, Final, List, Optional

from cosl.juju_topology import JujuTopology
from ops import CharmBase
from ops.framework import EventBase, EventSource, Object, ObjectEvents
from pydantic import BaseModel, ConfigDict

DEFAULT_CONSUMER_RELATION_NAME = "send-otlp"
DEFAULT_PROVIDER_RELATION_NAME = "receive-otlp"
RELATION_INTERFACE_NAME = "otlp"
SUPPORTED_TELEMETRIES: Final = ["logs", "metrics", "traces"]

logger = logging.getLogger(__name__)


@unique
class OtlpProtocols(str, Enum):
    """OTLP protocols used by the OpenTelemetry Collector."""

    grpc = "grpc"
    """gRPC protocol for sending/receiving OTLP data."""
    http = "http"
    """HTTP protocol for sending/receiving OTLP data."""


# TODO: This fails if a Provider does not provide all protocols!
class ProtocolPorts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grpc: Optional[int] = None
    http: Optional[int] = None


class OtlpEndpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: str  # TODO: Should be from an Enum type
    endpoint: str
    telemetries: List[str]  # TODO: Should be from an Enum type


class OtlpProviderAppData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: List[OtlpEndpoint]
    # TODO: Add field_validator for:
    #       1. protocols are all supported
    #       2. telemetries are all supported


class OtlpEndpointsChangedEvent(EventBase):
    """Event emitted when OTLP endpoints change."""

    def __init__(self, handle, relation_id):
        super().__init__(handle)
        self.relation_id = relation_id


class OtlpConsumerEvents(ObjectEvents):
    """Event descriptor for events raised by `OTLPConsumer`."""

    endpoints_changed = EventSource(OtlpEndpointsChangedEvent)


class OtlpConsumer(Object):
    # TODO: update
    """docstring."""

    on = OtlpConsumerEvents()  # pyright: ignore

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str = DEFAULT_CONSUMER_RELATION_NAME,
        protocol: str = OtlpProtocols.grpc.value,
    ):
        super().__init__(charm, relation_name)
        self._charm = charm
        self._relation_name = relation_name
        self._protocol = protocol

        self.topology = JujuTopology.from_charm(charm)

        # TODO: Use Pietro's new lib to listen to all events and execute the reconcile
        self._reconcile()

    def _reconcile(self):
        # NOTE: The provider serves OTLP endpoints which are always listening, so we do nothing
        pass

    def get_remote_otlp_endpoint(self) -> Dict[int, OtlpEndpoint]:
        """Return a mapping of relation ID to OtlpEndpoint.

        Attempt to find the endpoint for the consumer's desired protocol in the provider databag.
        If it is not found, return the next available endpoint.
        """
        aggregate = {}
        for rel in self.model.relations[self._relation_name]:
            if not (app_databag := rel.data[rel.app]):
                continue

            data = json.loads(app_databag["data"])
            otlp_endpoints = [OtlpEndpoint(**endpoint) for endpoint in data]

            if preferred_endpoint := next(
                (e for e in otlp_endpoints if self._protocol == e.protocol), None
            ):
                aggregate[rel.id] = preferred_endpoint
            else:
                if endpoint := next((e for e in otlp_endpoints), None):
                    aggregate[rel.id] = endpoint

        return aggregate


class OtlpProviderConsumersChangedEvent(EventBase):
    """Event emitted when Prometheus remote_write alerts change."""


class OtlpProviderEvents(ObjectEvents):
    """Event descriptor for events raised by `PrometheusRemoteWriteProvider`."""

    consumers_changed = EventSource(OtlpProviderConsumersChangedEvent)


# TODO: Consider renaming to SendOTLP
class OtlpProvider(Object):
    # TODO: update
    """docstring."""

    on = OtlpProviderEvents()  # pyright: ignore

    def __init__(
        self,
        charm: CharmBase,
        protocol_ports: Dict[str, int],
        relation_name: str = DEFAULT_PROVIDER_RELATION_NAME,
        path: str = "",
        supported_telemetries: List[str] = SUPPORTED_TELEMETRIES,
        server_host_func: Callable[[], str] = lambda: f"http://{socket.getfqdn()}",
    ):
        super().__init__(charm, relation_name)
        self._charm = charm
        self._relation_name = relation_name
        self._protocol_ports = ProtocolPorts(**protocol_ports)
        self._path = path
        self._supported_telemetries = supported_telemetries
        self._get_server_host = server_host_func

        self._reconcile()

    def _reconcile(self) -> None:
        if not self._charm.unit.is_leader():
            return

        for relation in self.model.relations[self._relation_name]:
            # TODO: pass the supported telemetries to requirer here
            relation.data[self._charm.app]["data"] = json.dumps(
                [e.model_dump_json(exclude_none=True) for e in self.otlp_endpoints]
            )

    @property
    def otlp_endpoints(self) -> List[OtlpEndpoint]:
        endpoints = []
        for protocol, port in self._protocol_ports.model_dump(exclude_none=True).items():
            endpoint = f"{self._get_server_host().rstrip('/')}:{port}"
            if self._path:
                endpoint += f"/{self._path.rstrip('/')}"
            endpoints.append(
                OtlpEndpoint(
                    protocol=protocol, endpoint=endpoint, telemetries=self._supported_telemetries
                )
            )
        return endpoints
