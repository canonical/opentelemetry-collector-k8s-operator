# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.


from contextlib import contextmanager
from datetime import timedelta
from unittest.mock import patch

import yaml
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    PrivateKey,
    TLSCertificatesRequiresV4,
    generate_ca,
    generate_certificate,
    generate_csr,
)
from ops.testing import Context, State

from constants import CA_TRUST_STAMP_PATH


class IssuedCertificate:
    """A real, parsable server certificate plus its CA, for tests that inspect SANs.

    `MockCertificate` carries opaque strings, which is enough for most tests but not for the
    ones that assert on which names otelcol's certificate is valid for.
    """

    def __init__(self, common_name: str, sans_dns: frozenset[str]):
        ca_key = PrivateKey.generate()
        ca = generate_ca(private_key=ca_key, validity=timedelta(days=1), common_name="test-ca")
        key = PrivateKey.generate()
        csr = generate_csr(private_key=key, common_name=common_name, sans_dns=sans_dns)
        self.private_key = key
        self.certificate = generate_certificate(
            csr=csr, ca=ca, ca_private_key=ca_key, validity=timedelta(days=1)
        )
        self.ca = ca


@contextmanager
def issued_certificate(issued: IssuedCertificate):
    """Run the reconciler as if the CA had assigned `issued` over `receive-server-cert`.

    Yields inside a patch of `TLSCertificatesRequiresV4`, so the charm writes a real,
    parsable certificate to disk and the code that reads its SANs back is exercised for
    real rather than falling back to the "unparsable cert" branch.
    """
    with (
        patch.object(TLSCertificatesRequiresV4, "_find_available_certificates", return_value=None),
        patch.object(
            TLSCertificatesRequiresV4,
            "get_assigned_certificate",
            return_value=(issued, issued.private_key),
        ),
    ):
        yield issued


def get_otelcol_file(state_out: State, ctx: Context, file_path: str) -> dict:
    otelcol = state_out.get_container("otelcol")
    assert otelcol.services["otelcol"].is_running()
    fs = otelcol.get_filesystem(ctx)
    otelcol_file = fs.joinpath(*file_path.strip("/").split("/"))
    assert otelcol_file.exists(), "file does not exist"
    cfg = yaml.safe_load(otelcol_file.read_text())
    return cfg


def trust_stamp_after_reconcile(ctx: Context, state_in: State, cert_obj, private_key: str) -> str:
    """Run a reconcile with a stubbed assigned server cert and return the trust-store stamp.

    `_reconcile` fetches the server cert, key and CA from the `receive-server-cert` relation
    via `TLSCertificatesRequiresV4`; here `get_assigned_certificate` is stubbed to return
    `cert_obj` (which must expose `.certificate.raw` and `.ca.raw`) together with
    `private_key`. The returned stamp (`CA_TRUST_STAMP_PATH`) reflects what `refresh_certs`
    wrote for that cert, so comparing two runs isolates the trust-store inputs that changed.
    """
    with (
        patch.object(TLSCertificatesRequiresV4, "_find_available_certificates", return_value=None),
        patch.object(
            TLSCertificatesRequiresV4,
            "get_assigned_certificate",
            return_value=(cert_obj, private_key),
        ),
        patch.object(Certificate, "from_string", return_value=cert_obj),
    ):
        state_out = ctx.run(ctx.on.update_status(), state=state_in)
    otelcol = state_out.get_container("otelcol")
    fs = otelcol.get_filesystem(ctx)

    stamp = fs.joinpath(*CA_TRUST_STAMP_PATH.strip("/").split("/"))
    assert stamp.exists(), "trust store stamp was not written"
    return stamp.read_text()
