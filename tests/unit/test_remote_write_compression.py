# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: compression of the alert rules published over send-remote-write.

The charm may only compress its alert rules if the remote-write provider advertises that
it is able to read them compressed, so that this charm stays compatible with providers
running an older version of the `prometheus_remote_write` library.
"""

import json

import pytest
from charms.prometheus_k8s.v1.prometheus_remote_write import (
    ALERT_RULES_ENCODINGS_KEY,
    ALERT_RULES_KEY,
    JSON_ENCODING,
    LZMA_ENCODING,
)
from cosl.utils import LZMABase64
from ops.testing import Model, Relation, State

MODEL = Model("my_model", uuid="74a5690b-89c9-44dd-984b-f69f26a6b751")

LZMA_ADVERTISED = {ALERT_RULES_ENCODINGS_KEY: json.dumps([LZMA_ENCODING, JSON_ENCODING])}


def _published_rules(state: State, relation: Relation) -> str:
    return state.get_relation(relation.id).local_app_data[ALERT_RULES_KEY]


@pytest.mark.parametrize(
    "remote_app_data, compressed",
    [
        pytest.param(LZMA_ADVERTISED, True, id="lzma_advertised"),
        pytest.param({}, False, id="legacy_provider"),
        pytest.param(
            {ALERT_RULES_ENCODINGS_KEY: json.dumps([JSON_ENCODING])}, False, id="json_only"
        ),
    ],
)
def test_alert_rules_are_compressed_only_for_a_capable_provider(
    ctx, otelcol_container, remote_app_data, compressed
):
    # GIVEN a send-remote-write relation to a provider with a given set of supported encodings
    remote_write_relation = Relation(
        "send-remote-write", remote_app_name="prometheus", remote_app_data=remote_app_data
    )
    state = State(
        leader=True,
        model=MODEL,
        relations=[remote_write_relation],
        containers=otelcol_container,
    )

    # WHEN the charm reconciles
    state_out = ctx.run(ctx.on.relation_changed(relation=remote_write_relation), state)

    # THEN the alert rules are compressed only if the provider said it can read them
    published = _published_rules(state_out, remote_write_relation)
    if compressed:
        with pytest.raises(json.JSONDecodeError):
            json.loads(published)
        rules = json.loads(LZMABase64.decompress(published))
    else:
        rules = json.loads(published)

    # AND the rules themselves are unaffected by the encoding
    assert rules["groups"]
