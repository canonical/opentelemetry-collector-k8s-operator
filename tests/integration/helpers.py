# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
"""Shared helpers for integration tests."""

import jubilant


def deploy_seaweedfs(juju: jubilant.Juju, app: str, s3_requirer_app: str) -> None:
    """Deploy seaweedfs-k8s and integrate it with the given S3-requiring app.

    Args:
        juju: The jubilant Juju instance.
        app: The name to give the deployed seaweedfs-k8s application.
        s3_requirer_app: The name of the app that requires the S3 relation.
    """
    juju.deploy("seaweedfs-k8s", app, channel="edge")
    juju.wait(lambda status: jubilant.all_active(status, app), delay=5, timeout=600)
    juju.integrate(f"{s3_requirer_app}:s3", f"{app}:s3-credentials")
