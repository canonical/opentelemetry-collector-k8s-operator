"""Feature: Otelcol can form TLS connections with HTTPS servers."""

import textwrap
from typing import Dict
import tempfile
import pathlib
import logging
import jubilant

logger = logging.getLogger(__name__)


# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


def test_unknown_authority(juju: jubilant.Juju, charm: str, charm_resources: Dict[str, str]):
    """Scenario: Otelcol fails to scrape metrics from a server signed by unknown authority."""
    assert juju.model
    juju.cli("switch", juju.model, include_model=False)

    # GIVEN a scrape target signed by a self-signed certificate
    # WHEN related to otelcol
    bundle = textwrap.dedent(f"""
        bundle: kubernetes
        applications:
          am:
            charm: alertmanager-k8s
            channel: latest/stable
            revision: 158
            resources:
              alertmanager-image: 99
            scale: 1
            trust: true
          otelcol:
            charm: {charm}
            scale: 1
            resources:
                opentelemetry-collector-image: {charm_resources["opentelemetry-collector-image"]}
          prom:
            charm: prometheus-k8s
            channel: latest/stable
            revision: 234
            resources:
              prometheus-image: 151
            scale: 1
            trust: true
          ssc:
            charm: self-signed-certificates
            channel: 1/stable
            revision: 263
            scale: 1
        relations:
        - - ssc:certificates
          - am:certificates
        - - ssc:certificates
          - otelcol:certificates
        - - ssc:certificates
          - prom:certificates
        - - am:self-metrics-endpoint
          - otelcol:metrics-endpoint
        - - prom:receive-remote-write
          - otelcol:send-remote-write
    """)
    with tempfile.NamedTemporaryFile(dir=TEMP_DIR, suffix=".yaml") as f:
        f.write(bundle.encode())
        f.flush()
        juju.deploy(f.name, trust=True)
    juju.wait(jubilant.all_active, delay=10, timeout=600)

# cat /etc/alertmanager/alertmanager-web-config.yml
# tls_server_config:
#   cert_file: /etc/alertmanager/alertmanager.cert.pem
#   key_file: /etc/alertmanager/alertmanager.key.pem

# cat /etc/prometheus/prometheus-web-config.yml
# tls_server_config:
#   cert_file: /etc/prometheus/server.cert
#   key_file: /etc/prometheus/server.key

# TODO Try to decode these PEM or cert/keys to check the contents to see the CA
# openssl x509 -text -in certs-testing/alertmanager.key.pem -noout > certs-testing/am-key-pem-decoded.txt
# juju scp --container alertmanager am/0:/etc/alertmanager/ ./certs-testing
