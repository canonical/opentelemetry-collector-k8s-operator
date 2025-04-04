from ops.testing import Container, State, Exec
from constants import RECV_CA_CERT_FOLDER_PATH
from unittest.mock import patch


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
    assert not fs.joinpath(RECV_CA_CERT_FOLDER_PATH).exists()
