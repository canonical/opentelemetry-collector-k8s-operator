
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.
# TODO: Move to a lib
import logging
import socket
from typing import Dict

from cosl import JujuTopology
from ops import CharmBase
from ops.charm import RelationEvent
from ops.framework import EventBase, EventSource, Object, ObjectEvents

from config_builder import Port

DEFAULT_CONSUMER_RELATION_NAME = "send-otlp"
DEFAULT_PROVIDER_RELATION_NAME = "receive-otlp"
RELATION_INTERFACE_NAME = "otlp"
logger = logging.getLogger(__name__)

SUPPORTED_PROTOCOLS = {"grpc", "http"}

class OTLPEndpointsChangedEvent(EventBase):
    """Event emitted when OTLP endpoints change."""

    def __init__(self, handle, relation_id):
        super().__init__(handle)
        self.relation_id = relation_id

    # TODO: Is this needed
    def snapshot(self):
        """Save OTLP information."""
        return {"relation_id": self.relation_id}

    # TODO: Is this needed
    def restore(self, snapshot):
        """Restore OTLP information."""
        self.relation_id = snapshot["relation_id"]


class OTLPConsumerEvents(ObjectEvents):
    """Event descriptor for events raised by `OTLPConsumer`."""

    endpoints_changed = EventSource(OTLPEndpointsChangedEvent)


class OTLPConsumer(Object):
    on = OTLPConsumerEvents()  # pyright: ignore

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str = DEFAULT_CONSUMER_RELATION_NAME,
        protocol: str = "grpc"  # TODO: If we don't do this then the lib becomes too specific to otelcol
    ):
        super().__init__(charm, relation_name)
        self._charm = charm
        self._relation_name = relation_name
        if protocol in SUPPORTED_PROTOCOLS:
            self._protocol = protocol
        else:
            raise NotImplementedError(f"The {protocol} protocol is not in {SUPPORTED_PROTOCOLS}")

        self.topology = JujuTopology.from_charm(charm)

        on_relation = self._charm.on[self._relation_name]

        # TODO: Use Pietro's new lib to listen to all events and execute the reconcile
        self.framework.observe(self._charm.on.update_status, self._reconcile)
        self.framework.observe(self._charm.on.upgrade_charm, self._reconcile)
        self.framework.observe(on_relation.relation_joined, self._reconcile)
        self.framework.observe(on_relation.relation_changed, self._reconcile)
        self.framework.observe(on_relation.relation_departed, self._reconcile)
        self.framework.observe(on_relation.relation_broken, self._reconcile)

    def _reconcile(self, event: RelationEvent) -> None:
        logger.warning("+++CONSUMER RECONCILING")


class OTLPProviderConsumersChangedEvent(EventBase):
    """Event emitted when Prometheus remote_write alerts change."""


class OTLPProviderEvents(ObjectEvents):
    """Event descriptor for events raised by `PrometheusRemoteWriteProvider`."""

    consumers_changed = EventSource(OTLPProviderConsumersChangedEvent)


# TODO: Consider renaming to SendOTLP
class OTLPProvider(Object):
    on = OTLPProviderEvents()  # pyright: ignore

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str = DEFAULT_PROVIDER_RELATION_NAME,
        protocols: Dict[str, int] = {"grpc": Port.otlp_grpc.value, "http": Port.otlp_http.value}  # TODO: default_factory here?
    ):
        super().__init__(charm, relation_name)
        self._charm = charm
        self._relation_name = relation_name
        if any(k not in SUPPORTED_PROTOCOLS for k in protocols.keys()):
            raise NotImplementedError(f"Only {SUPPORTED_PROTOCOLS} protocols are supported.")

        on_relation = self._charm.on[self._relation_name]
        self.framework.observe(self._charm.on.update_status, self._reconcile)
        self.framework.observe(self._charm.on.upgrade_charm, self._reconcile)
        self.framework.observe(on_relation.relation_joined, self._reconcile)
        self.framework.observe(on_relation.relation_changed, self._reconcile)
        self.framework.observe(on_relation.relation_departed, self._reconcile)
        self.framework.observe(on_relation.relation_broken, self._reconcile)

    def _reconcile(self, event: RelationEvent) -> None:
        logger.warning("+++PROVIDER RECONCILING")
        if not self._charm.unit.is_leader():
            return

        databag = {
            "grpc": f"http://{socket.getfqdn()}:{4317}",
            "http": f"http://{socket.getfqdn()}:{4318}",
        }

        for relation in self.model.relations[self._relation_name]:
            for protocol, endpoint in databag.items():
                relation.data[self._charm.app][protocol] = endpoint
        logger.warning("+++FINISHED")
