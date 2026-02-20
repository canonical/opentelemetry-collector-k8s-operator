# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.


from typing import Any, Dict, Optional

import yaml
from ops.testing import Context, State


def get_otelcol_file(state_out: State, ctx: Context, file_path: str) -> dict:
    otelcol = state_out.get_container("otelcol")
    assert otelcol.services["otelcol"].is_running()
    fs = otelcol.get_filesystem(ctx)
    otelcol_file = fs.joinpath(*file_path.strip("/").split("/"))
    assert otelcol_file.exists(), "file does not exist"
    cfg = yaml.safe_load(otelcol_file.read_text())
    return cfg


def get_group_by_name(rules: Optional[Dict[str, Any]], name: str) -> Optional[Dict[str, Any]]:
    if rules is None:
        return None
    for group in rules.get("groups", []):
        if group.get("name") == name:
            return group
    return None
