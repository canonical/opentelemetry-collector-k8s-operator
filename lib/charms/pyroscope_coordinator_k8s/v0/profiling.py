"""Profiling integration endpoint wrapper.
"""
from typing import List

import ops
import pydantic

# The unique Charmhub library identifier, never change it
LIBID = "a04f470b17b64e9abcdb102f5458df55"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

DEFAULT_ENDPOINT_NAME = "profiling"


class ProfilingAppDatabagModel(pydantic.BaseModel):
    otlp_grpc_endpoint_url: str


class ProfilingProvider:
    """Wraps a profiling provider endpoint."""
    def __init__(self, relations:List[ops.Relation], app:ops.Application):
        self._relations = relations
        self._app = app

    def publish_endpoint(self, grpc_endpoint:str):
        """Publish the profiling grpc endpoint to all relations."""
        for relation in self._relations:
            relation.save(
                ProfilingAppDatabagModel(otlp_grpc_endpoint_url=grpc_endpoint),
                self._app
            )


class ProfilingRequirer:
    """Wraps a profiling requirer endpoint."""
    def __init__(self, relations:List[ops.Relation]):
        self._relations = relations

    def get_endpoints(self):
        """Obtain the profiling grpc endpoints from all relations."""
        for relation in self._relations:
            relation.load(
                ProfilingAppDatabagModel,
                relation.app
            )

