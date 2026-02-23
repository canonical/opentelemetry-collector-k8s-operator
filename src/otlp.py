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
from typing import Dict, List, Literal, Optional, OrderedDict, Sequence, Union

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
    """A pydantic model for the OTLP consumer's unit databag.

    The rules are compressed when published to databag and decompressed when
    read to avoid hitting databag size limits for large deployments. An admin
    can decode the rules using the following command:
    ```bash
    <rules-from-show-unit> | base64 -d | xz -d | jq
    ```

    TODO: Add metadata description
    """

    model_config = ConfigDict(extra="forbid")

    rules: RulesModel
    metadata: Optional[OrderedDict[str, str]] = None

    @field_validator("rules", mode="before")
    @classmethod
    def _rules_from_json(cls, value):
        if isinstance(value, str):
            decompressed = LZMABase64.decompress(json.dumps(value, sort_keys=True))
            return json.loads(decompressed)
        return value

    @field_validator("metadata", mode="before")
    @classmethod
    def _metadata_from_json(cls, value):
        if isinstance(value, str):
            return json.loads(value)
        return value

    def to_databag(self) -> Dict[str, str]:
        """Serialize model fields for relation app databag storage."""
        payload = self.model_dump(exclude_none=True)
        return {
            key: json.dumps(value, sort_keys=True)
            if key != "rules"
            else LZMABase64.compress(json.dumps(value, sort_keys=True))
            for key, value in payload.items()
        }


class OtlpConsumer(Object):
    """A class for consuming OTLP endpoints.

    Args:
        charm: The charm instance.
        relation_name: The name of the relation to use.
        protocols: The protocols to filter for in the provider's OTLP
            endpoints.
        telemetries: The telemetries to filter for in the provider's OTLP
            endpoints.
        loki_alert_rules_path: The path to Loki alerting rules provided by this
            charm.
        loki_record_rules_path: The path to Loki recording rules provided by
            this charm.
        prometheus_alert_rules_path: The path to Prometheus alerting rules
            provided by this charm.
        prometheus_record_rules_path: The path to Prometheus recording rules
            provided by this charm.
    """

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str = DEFAULT_CONSUMER_RELATION_NAME,
        protocols: Optional[Sequence[Literal["http", "grpc"]]] = None,
        telemetries: Optional[Sequence[Literal["logs", "metrics", "traces"]]] = None,
        *,
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
        charm_dir = self._charm.charm_dir
        self._loki_alert_rules_path = AlertRules.validate_rules_path(
            loki_alert_rules_path, charm_dir
        )
        self._prom_alert_rules_path = AlertRules.validate_rules_path(
            prometheus_alert_rules_path, charm_dir
        )
        self._loki_record_rules_path = RecordingRules.validate_rules_path(
            loki_record_rules_path, charm_dir
        )
        self._prom_record_rules_path = RecordingRules.validate_rules_path(
            prometheus_record_rules_path, charm_dir
        )

    def _filter_endpoints(
        self, endpoints: List[Dict[str, Union[str, List[str]]]]
    ) -> List[OtlpEndpoint]:
        """Filter out unsupported OtlpEndpoints.

        For each endpoint:
            - If a telemetry type is not supported, then the endpoint is
              accepted, but the telemetry is ignored.
            - If there are no supported telemetries for this endpoint, the
              endpoint is ignored.
            - If the endpoint contains an unsupported protocol it is ignored.
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

        return valid_endpoints

    def publish(self):
        """Triggers programmatically the update of the relation data.

        The rule files exist in separate directories, distinguished by format
        (logql|promql) and type (alerting|recording). The charm uses these
        paths as aggregation points for rules, acting as their source of truth.
        For each type of rule, the charm may aggregate rules from:
            - rules bundled in the charm's source code
            - any rules provided by related charms

        Generic, injected rules (not specific to any charm) are always
        published. Besides these generic rules, the inclusion of bundled rules
        and rules from related charms is the responsibility of the charm using
        the library. Including bundled rules and rules from related charms is
        achieved by copying these rules to the respective paths within the
        charm's filesystem and providing those paths to the OtlpConsumer constructor.
        """
        if not self._charm.unit.is_leader():
            # Only the leader unit can write to app data.
            return

        # Define the 4 rule types
        loki_alert_rules = AlertRules(query_type="logql", topology=self._topology)
        prom_alert_rules = AlertRules(query_type="promql", topology=self._topology)
        loki_recording_rules = RecordingRules(query_type="logql", topology=self._topology)
        prom_recording_rules = RecordingRules(query_type="promql", topology=self._topology)

        # Add rules
        prom_alert_rules.add(
            copy.deepcopy(generic_alert_groups.aggregator_rules),
            group_name_prefix=self._topology.identifier,
        )
        loki_alert_rules.add_path(self._loki_alert_rules_path, recursive=True)
        prom_alert_rules.add_path(self._prom_alert_rules_path, recursive=True)
        loki_recording_rules.add_path(self._loki_record_rules_path, recursive=True)
        prom_recording_rules.add_path(self._prom_record_rules_path, recursive=True)

        # Publish to databag
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
                },
                # TODO: Add tests for this set vs. not set
                "metadata": self._topology.as_dict()
            }
        )
        for relation in self.model.relations[self._relation_name]:
            relation.data[self._charm.app].update(consumer_appdata.to_databag())

    def endpoints(self) -> Dict[int, OtlpEndpoint]:
        """Return a mapping of relation ID to OTLP endpoint.

        For each remote's list of OtlpEndpoints, the consumer filters out
        unsupported endpoints and telemetries. If there are multiple supported
        endpoints, the consumer chooses the first available endpoint in the
        list. This allows providers to specify multiple endpoints with
        different protocols and/or telemetry types and the consumer can choose
        one based on its own capabilities. For example, a provider may specify
        both an HTTP and gRPC endpoint, and a consumer that only supports HTTP
        will choose the HTTP endpoint.
        """
        endpoint_map = {}
        for rel in self.model.relations[self._relation_name]:
            if not (raw_databag := rel.data[rel.app]):
                continue

            provided_endpoints = json.loads(raw_databag.get("endpoints") or "[]")
            if not (endpoints := self._filter_endpoints(provided_endpoints)):
                continue

            # Ensure that the filtered endpoints are valid
            try:
                app_databag = OtlpProviderAppData(endpoints=endpoints)
            except ValidationError as e:
                logger.error(f"OTLP databag failed validation: {e}")
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
        """Add an OtlpEndpoint to the list of endpoints to publish.

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

    def rules(
        self, query_type: Literal["logql", "promql"], rule_type: Literal["alerting", "recording"]
    ):
        """Fetch rules for all relations of the desired query and rule types.

        This method returns all rules of the desired query and rule types
        provided by related OTLP consumer charms. These rules may be used to
        generate a rules file for each relation since the returned list of
        groups are indexed by relation ID. This method ensures rules:
            - have Juju topology from the rule's labels injected into the expr.
            - are valid using CosTool.

        Returns:
            a mapping of relation ID to a dictionary of alert rule groups
            following the OfficialRuleFileFormat from cos-lib.
        """
        rule_cls = AlertRules if rule_type == "alerting" else RecordingRules
        rules_obj = rule_cls(query_type, self._topology)

        rules_map = {}
        for relation in self.model.relations[self._relation_name]:
            if not (raw_data := relation.data[relation.app]):
                continue
            consumer_appdata = OtlpConsumerAppData.model_validate(raw_data)

            # get rules for the desired query type
            if not (rule_types := getattr(consumer_appdata.rules, rules_obj.query_type, None)):
                continue

            # get rules for the desired type
            if not (rules := getattr(rule_types, rule_type, None)):
                continue

            rules_data = rules_obj.inject_alert_expr_labels(rules)

            # TODO: If rules don't have labels for topology, then they can provide it via metadata.
            identifier, topology = rules_obj.get_identifier_by_alert_rules(rules_data)
            if not topology:
                try:
                    # TODO: What is this metadata, would fail if it DNE, .get(metadata, default)?
                    metadata = json.loads(relation.data[relation.app]["metadata"])
                    # TODO: Why do we get the identifier twice? Check with loki_push_api
                    identifier = JujuTopology.from_dict(metadata).identifier
                    # TODO: Shouldn't we apply label matchers before injecting expr labels? Check with loki_push_api
                    rules_map[identifier] = rules_obj.tool.apply_label_matchers(rules_data)  # type: ignore

                except KeyError as e:
                    logger.debug(
                        "Relation %s has no 'metadata': %s",
                        relation.id,
                        e,
                    )

            if not identifier:
                logger.error(
                    f"{query_type}, {rule_type} rules were found but no usable group or identifier was present."
                )
                continue

            _, errmsg = rules_obj.tool.validate_alert_rules(rules_data)  # type: ignore[reportCallIssue]
            if errmsg:
                relation.data[self._charm.app]["event"] = json.dumps({"errors": errmsg})
                continue
            # TODO: Does this not override the code in the try/except above?
            rules_map[identifier] = rules_data

        return rules_map
