from ops.testing import Container, Relation, State, Exec
from ops import PathError
import pytest
from constants import RECV_CA_CERT_FOLDER_PATH


def test_no_recv_ca_cert_relations_present(ctx):
    # GIVEN the charm is deployed in isolation
    state = State(
        leader=True,
        containers={Container("otelcol", can_connect=True)},
        execs={Exec(["update-ca-certificates", "--fresh"], return_code=0, stdout="")},
    )

    # WHEN any event is emitted
    out = ctx.run(ctx.on.update_status(), state)

    # THEN no recv_ca_cert-associated certs are present
    container = out.get_container("otelcol")
    with pytest.raises(PathError):
        container.list_files(RECV_CA_CERT_FOLDER_PATH)
