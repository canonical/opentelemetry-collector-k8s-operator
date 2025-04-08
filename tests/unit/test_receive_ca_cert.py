from ops.testing import Container, State, Exec, Relation
from constants import RECV_CA_CERT_FOLDER_PATH
from unittest.mock import patch
import json


def test_no_recv_ca_cert_relations_present(ctx):
    # GIVEN the charm is deployed in isolation
    state = State(
        leader=True,
        containers={Container("otelcol", can_connect=True, execs={Exec(["update-ca-certificates", "--fresh"], return_code=0, stdout="")})},
    )

    # WHEN any event is emitted
    with patch("charm._aggregate_alerts"):
        out = ctx.run(ctx.on.update_status(), state)

    # THEN no recv_ca_cert-associated certs are present
    container = out.get_container("otelcol")
    fs = container.get_filesystem(ctx)
    assert not fs.joinpath(RECV_CA_CERT_FOLDER_PATH.lstrip("/")).exists()


def test_ca_forwarded_over_rel_data(ctx):
    # Relation 1
    cert1a = "-----BEGIN CERTIFICATE-----\n ... cert1a ... \n-----END CERTIFICATE-----"
    cert1b = "-----BEGIN CERTIFICATE-----\n ... cert1b ... \n-----END CERTIFICATE-----"

    # Relation 2
    cert2a = "-----BEGIN CERTIFICATE-----\n ... cert2a ... \n-----END CERTIFICATE-----"
    cert2b = "-----BEGIN CERTIFICATE-----\n ... cert2b ... \n-----END CERTIFICATE-----"

    # GIVEN the charm is related to a CA
    state = State(
        leader=True,
        containers={Container("otelcol", can_connect=True, execs={Exec(["update-ca-certificates", "--fresh"], return_code=0, stdout="")})},
        relations=[
            Relation("receive-ca-cert", remote_app_data={"certificates": json.dumps([cert1a, cert1b])}),
            Relation("receive-ca-cert", remote_app_data={"certificates": json.dumps([cert2a, cert2b])}),
        ]
    )

    # WHEN any event is emitted
    with patch("charm._aggregate_alerts"):
        out = ctx.run(ctx.on.update_status(), state)

    # THEN recv_ca_cert-associated certs are present
    container = out.get_container("otelcol")
    fs = container.get_filesystem(ctx)
    certs_dir = fs.joinpath(RECV_CA_CERT_FOLDER_PATH.lstrip("/"))
    assert certs_dir.exists()
    certs = {file.read_text() for file in certs_dir.glob("*.crt")}
    assert certs == {cert1a, cert1b, cert2a, cert2b}
