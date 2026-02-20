# Copyright 2026 Canonical Ltd.
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

import copy
import json
import logging
from typing import Dict, List, Literal, Optional, Sequence, Union

from cosl.juju_topology import JujuTopology
from cosl.rules import AlertRules, RecordingRules, RulesModel, generic_alert_groups
from cosl.utils import LZMABase64
from ops import CharmBase
from ops.framework import Object
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

DEFAULT_CONSUMER_RELATION_NAME = "send-otlp"
DEFAULT_PROVIDER_RELATION_NAME = "receive-otlp"
DEFAULT_LOKI_ALERT_RULES_RELATIVE_PATH = "./src/loki_alert_rules"
DEFAULT_LOKI_RECORD_RULES_RELATIVE_PATH = "./src/loki_record_rules"
DEFAULT_PROM_ALERT_RULES_RELATIVE_PATH = "./src/prometheus_alert_rules"
DEFAULT_PROM_RECORD_RULES_RELATIVE_PATH = "./src/prometheus_record_rules"


logger = logging.getLogger(__name__)


class OtlpEndpoint(BaseModel):
    """A pydantic model for a single OTLP endpoint."""

    model_config = ConfigDict(extra="forbid")

    protocol: Literal["http", "grpc"]
    endpoint: str
    telemetries: Sequence[Literal["logs", "metrics", "traces"]]


class OtlpProviderAppData(BaseModel):
    """A pydantic model for the OTLP provider's unit databag."""

    model_config = ConfigDict(extra="forbid")

    endpoints: List[OtlpEndpoint]

    @field_validator("endpoints", mode="before")
    @classmethod
    def _endpoints_from_json(cls, value):
        if isinstance(value, str):
            return json.loads(value)
        return value

    def to_databag(self) -> Dict[str, str]:
        """Serialize model fields for relation app databag storage."""
        payload = self.model_dump(exclude_none=True)
        return {key: json.dumps(value, sort_keys=True) for key, value in payload.items()}


class OtlpConsumerAppData(BaseModel):
    """A pydantic model for the OTLP provider's unit databag."""

    model_config = ConfigDict(extra="forbid")

    rules: RulesModel

    @field_validator("rules", mode="before")
    @classmethod
    def _rules_from_json(cls, value):
        if isinstance(value, str):
            decompressed = LZMABase64.decompress(json.dumps(value, sort_keys=True))
            return json.loads(decompressed)
        return value

    def to_databag(self) -> Dict[str, str]:
        # TODO: Update deccriptions about compress and decompress
        """Serialize model fields for relation app databag storage."""
        payload = self.model_dump(exclude_none=True)
        return {
            key: json.dumps(value, sort_keys=True)
            if key != "rules"
            else LZMABase64.compress(json.dumps(value, sort_keys=True))
            for key, value in payload.items()
        }


class OtlpConsumer(Object):
    """A class for consuming OTLP endpoints."""

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str = DEFAULT_CONSUMER_RELATION_NAME,
        protocols: Optional[Sequence[Literal["http", "grpc"]]] = None,
        telemetries: Optional[Sequence[Literal["logs", "metrics", "traces"]]] = None,
        *,
        forward_rules: bool = True,
        loki_alert_rules_path: str = DEFAULT_LOKI_ALERT_RULES_RELATIVE_PATH,
        loki_record_rules_path: str = DEFAULT_LOKI_RECORD_RULES_RELATIVE_PATH,
        prometheus_alert_rules_path: str = DEFAULT_PROM_ALERT_RULES_RELATIVE_PATH,
        prometheus_record_rules_path: str = DEFAULT_PROM_RECORD_RULES_RELATIVE_PATH,
    ):
        super().__init__(charm, relation_name)
        self._charm = charm
        self._relation_name = relation_name
        self._protocols = protocols if protocols is not None else []
        self._telemetries = telemetries if telemetries is not None else []
        self._topology = JujuTopology.from_charm(charm)
        self._forward_rules = forward_rules
        charm_dir = self._charm.charm_dir
        self._loki_alert_rules_path = AlertRules.validate_rules_path(
            loki_alert_rules_path, charm_dir
        )
        self._loki_record_rules_path = AlertRules.validate_rules_path(
            loki_record_rules_path, charm_dir
        )
        self._prom_alert_rules_path = AlertRules.validate_rules_path(
            prometheus_alert_rules_path, charm_dir
        )
        self._prom_record_rules_path = AlertRules.validate_rules_path(
            prometheus_record_rules_path, charm_dir
        )

    def _filter_endpoints(
        self, endpoints: List[Dict[str, Union[str, List[str]]]]
    ) -> Optional[OtlpProviderAppData]:
        """Load the OtlpProviderAppData from the given databag string.

        For each endpoint in the databag, if it contains unsupported telemetry types, those
        telemetries are filtered out before validation. If an endpoint contains an unsupported
        protocol, or has no supported telemetries, it is skipped entirely.
        """
        valid_endpoints = []
        supported_telemetries = set(self._telemetries)
        for endpoint in endpoints:
            if filtered_telemetries := [
                t for t in endpoint.get("telemetries", []) if t in supported_telemetries
            ]:
                endpoint["telemetries"] = filtered_telemetries
            else:
                # If there are no supported telemetries for this endpoint, skip it entirely
                continue
            try:
                endpoint = OtlpEndpoint.model_validate(endpoint)
            except ValidationError:
                continue
            valid_endpoints.append(endpoint)
        try:
            return OtlpProviderAppData(endpoints=valid_endpoints)
        except ValidationError as e:
            logger.error(f"OTLP databag failed validation: {e}")
            return None

    def publish(self):
        """Triggers programmatically the update of the relation data.

        There are 2 rules file paths which are loaded from disk and published to the databag. The
        rules files exist in 2 separate directories, distinguished by logql and promql expression
        formats.
        """
        if not self._charm.unit.is_leader():
            # Only the leader unit can write to app data.
            return

        loki_alert_rules = AlertRules(query_type="logql", topology=self._topology)
        prom_alert_rules = AlertRules(query_type="promql", topology=self._topology)
        loki_recording_rules = RecordingRules(query_type="logql", topology=self._topology)
        prom_recording_rules = RecordingRules(query_type="promql", topology=self._topology)
        prom_alert_rules.add(
            copy.deepcopy(generic_alert_groups.aggregator_rules),
            group_name_prefix=self._topology.identifier,
        )
        if self._forward_rules:
            loki_alert_rules.add_path(self._loki_alert_rules_path, recursive=True)
            prom_alert_rules.add_path(self._prom_alert_rules_path, recursive=True)
            loki_recording_rules.add_path(self._loki_record_rules_path, recursive=True)
            prom_recording_rules.add_path(self._prom_record_rules_path, recursive=True)

        consumer_appdata = OtlpConsumerAppData.model_validate(
            {
                "rules": {
                    "logql": {
                        "alerting": loki_alert_rules.as_dict(),
                        "recording": loki_recording_rules.as_dict(),
                    },
                    "promql": {
                        "alerting": prom_alert_rules.as_dict(),
                        "recording": prom_recording_rules.as_dict(),
                    },
                }
            }
        )

        for relation in self.model.relations[self._relation_name]:
            relation.data[self._charm.app].update(consumer_appdata.to_databag())

    def endpoints(self) -> Dict[int, OtlpEndpoint]:
        """Return a mapping of relation ID to OTLP endpoint.

        For each remote unit's list of OtlpEndpoints:
            - If a telemetry type is not supported, then the endpoint is accepted, but the
              telemetry is ignored.
            - If the endpoint contains an unsupported protocol it is ignored.
            - The first available (and supported) endpoint is returned.
        """
        endpoint_map = {}
        for rel in self.model.relations[self._relation_name]:
            if not (raw_databag := rel.data[rel.app]):
                continue
            endpoints = json.loads(raw_databag.get("endpoints") or "[]")
            if not (app_databag := self._filter_endpoints(endpoints)):
                continue

            # Choose the first valid endpoint in list
            if endpoint_choice := next(
                (e for e in app_databag.endpoints if e.protocol in self._protocols), None
            ):
                endpoint_map[rel.id] = endpoint_choice

        return endpoint_map


class OtlpProvider(Object):
    """A class for publishing all supported OTLP endpoints.

    Args:
        charm: The charm instance.
        relation_name: The name of the relation to use.
    """

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str = DEFAULT_PROVIDER_RELATION_NAME,
    ):
        super().__init__(charm, relation_name)
        self._charm = charm
        self._relation_name = relation_name
        self._endpoints = []
        self._topology = JujuTopology.from_charm(charm)

    def add_endpoint(
        self,
        protocol: Literal["http", "grpc"],
        endpoint: str,
        telemetries: Sequence[Literal["logs", "metrics", "traces"]],
    ):
        """Add an OtlpEndpoint to the list.

        Call this method after endpoint-changing events e.g. TLS and ingress.
        """
        self._endpoints.append(
            OtlpEndpoint(protocol=protocol, endpoint=endpoint, telemetries=telemetries)
        )

    def publish(self) -> None:
        """Triggers programmatically the update of the relation data."""
        if not self._charm.unit.is_leader():
            # Only the leader unit can write to app data.
            return

        for relation in self.model.relations[self._relation_name]:
            provider_appdata = OtlpProviderAppData(endpoints=self._endpoints)
            relation.data[self._charm.app].update(provider_appdata.to_databag())

    def rules(self, query_type: Literal["logql", "promql"], rule_type: Literal["alerting", "recording"]):
        """Fetch alerts for all relations.

        A Loki alert rules file consists of a list of "groups". Each
        group consists of a list of alerts (`rules`) that are sequentially
        executed. This method returns all the alert rules provided by each
        related metrics provider charm. These rules may be used to generate a
        separate alert rules file for each relation since the returned list
        of alert groups are indexed by relation ID. Also for each relation ID
        associated scrape metadata such as Juju model, UUID and application
        name are provided so a unique name may be generated for the rules
        file. For each relation the structure of data returned is a dictionary
        with four keys

        - groups
        - model
        - model_uuid
        - application

        The value of the `groups` key is such that it may be used to generate
        a Loki alert rules file directly using `yaml.dump` but the
        `groups` key itself must be included as this is required by Loki,
        for example as in `yaml.dump({"groups": alerts["groups"]})`.

        Currently only accepts a list of rules and these
        rules are all placed into a single group, even though Loki itself
        allows for multiple groups within a single alert rules file.

        Returns:
            a dictionary of alert rule groups and associated scrape
            metadata indexed by relation ID.
        """
        alert_rules = AlertRules(query_type, self._topology)
        rules_map = {}
        for relation in self.model.relations[self._relation_name]:
            if not (raw_data := relation.data[relation.app]):
                continue
            consumer_appdata = OtlpConsumerAppData.model_validate(raw_data)

            # get rules for the desired query type
            if not (rules_types := getattr(consumer_appdata.rules, alert_rules.query_type, None)):
                continue

            # get rules for the desired type
            if not (rules := getattr(rules_types, rule_type)):
                continue

            alert_rules_data = alert_rules.inject_alert_expr_labels(rules)

            identifier, topology = alert_rules.get_identifier_by_alert_rules(alert_rules_data)
            if not topology:
                try:
                    # TODO: What is this metadata?
                    metadata = json.loads(relation.data[relation.app]["metadata"])
                    identifier = JujuTopology.from_dict(metadata).identifier
                    rules_map[identifier] = alert_rules.tool.apply_label_matchers(alert_rules_data)  # type: ignore

                except KeyError as e:
                    logger.debug(
                        "Relation %s has no 'metadata': %s",
                        relation.id,
                        e,
                    )

            if not identifier:
                logger.error(
                    "Alert rules were found but no usable group or identifier was present."
                )
                continue

            _, errmsg = alert_rules.tool.validate_alert_rules(alert_rules_data)  # type: ignore[reportCallIssue]
            if errmsg:
                relation.data[self._charm.app]["event"] = json.dumps({"errors": errmsg})
                continue

            rules_map[identifier] = alert_rules_data

        return rules_map
