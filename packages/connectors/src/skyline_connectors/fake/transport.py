"""In-process transport that answers fake API calls from :class:`FakeCloud`.

This plays the role a boto3/HTTP adapter plays for real providers: it holds the credential
and turns an :class:`ApiCall` into a response. It makes no network calls.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from typing import Any, Final

from skyline_connectors.base import ApiCall, AuthenticationError, ConnectorError, ScopeError
from skyline_connectors.fake.dataset import ACCOUNT_ID, REGIONS, FakeCloud
from skyline_connectors.fake.models import FakeConfig, FakeCredentials
from skyline_core.types import JSON

SERVICE: Final = "fake"
_PAGE_SIZE: Final = 1  # tiny pages so pagination is exercised


class FakeTransport:
    """Implements :class:`skyline_connectors.gateway.Transport` for the fake cloud."""

    def __init__(self, config: FakeConfig, credentials: FakeCredentials) -> None:
        self._cloud = FakeCloud(config.simulate_fixes)
        self._failing: set[str] = set(config.fail_scopes)
        self._api_key = credentials.api_key
        # Explicit dispatch table: one handler per allowlisted operation.
        self._handlers: dict[str, Callable[[Mapping[str, JSON]], dict[str, Any]]] = {
            "GetCallerIdentity": self._caller_identity,
            "ListRegions": self._list_regions,
            "DescribeInstances": self._describe_instances,
            "DescribeSecurityGroups": self._describe_security_groups,
            "ListBuckets": self._list_buckets,
            "GetBucketEncryption": self._get_bucket_encryption,
            "ListUsers": self._list_users,
            "ListRoles": self._list_roles,
        }

    async def send(self, api: ApiCall, params: Mapping[str, JSON]) -> Mapping[str, JSON]:
        if api.service != SERVICE:
            msg = "unknown service"
            raise ConnectorError(msg)
        if len(self._api_key.get_secret_value()) < 32:  # noqa: PLR2004 - credential shape
            raise AuthenticationError
        handler = self._handlers.get(api.operation)
        if handler is None:
            msg = "unknown operation"
            raise ConnectorError(msg)
        result: dict[str, Any] = handler(params)
        return copy.deepcopy(result)

    def _region(self, params: Mapping[str, JSON]) -> str:
        region = params.get("Region")
        if region not in REGIONS:
            msg = "unknown region"
            raise ConnectorError(msg)
        assert isinstance(region, str)  # noqa: S101 - narrowed by the membership test
        if region in self._failing:
            msg = f"region {region} is unavailable (simulated)"
            raise ScopeError(msg)
        return region

    def _page(
        self, items: list[dict[str, Any]], params: Mapping[str, JSON], key: str
    ) -> dict[str, Any]:
        token = params.get("NextToken")
        start = int(token) if isinstance(token, str) and token.isdigit() else 0
        page: dict[str, Any] = {key: items[start : start + _PAGE_SIZE]}
        if start + _PAGE_SIZE < len(items):
            page["NextToken"] = str(start + _PAGE_SIZE)
        return page

    # Operation handlers -------------------------------------------------------------------

    def _caller_identity(self, _params: Mapping[str, JSON]) -> dict[str, Any]:
        return {"Account": ACCOUNT_ID, "Principal": "fake:role/skyline-readonly"}

    def _list_regions(self, _params: Mapping[str, JSON]) -> dict[str, Any]:
        return {"Regions": list(REGIONS)}

    def _describe_instances(self, params: Mapping[str, JSON]) -> dict[str, Any]:
        region = self._region(params)
        return self._page(self._cloud.in_region(self._cloud.instances, region), params, "Instances")

    def _describe_security_groups(self, params: Mapping[str, JSON]) -> dict[str, Any]:
        region = self._region(params)
        return {"SecurityGroups": self._cloud.in_region(self._cloud.security_groups, region)}

    def _list_buckets(self, params: Mapping[str, JSON]) -> dict[str, Any]:
        region = self._region(params)
        buckets = self._cloud.in_region(self._cloud.buckets, region)
        return {"Buckets": [{k: v for k, v in b.items() if k != "encryption"} for b in buckets]}

    def _get_bucket_encryption(self, params: Mapping[str, JSON]) -> dict[str, Any]:
        bucket = next((b for b in self._cloud.buckets if b["id"] == params.get("Bucket")), None)
        if bucket is None:
            msg = "unknown bucket"
            raise ConnectorError(msg)
        return {"Encryption": bucket["encryption"]}

    def _list_users(self, _params: Mapping[str, JSON]) -> dict[str, Any]:
        if ACCOUNT_ID in self._failing:
            msg = "identity service is unavailable (simulated)"
            raise ScopeError(msg)
        return {"Users": self._cloud.users}

    def _list_roles(self, _params: Mapping[str, JSON]) -> dict[str, Any]:
        return {"Roles": self._cloud.roles}
