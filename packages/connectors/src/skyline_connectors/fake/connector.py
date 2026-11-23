"""The fake connector: collects the fake cloud through the guarded gateway only."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from typing import ClassVar, Final, cast

from skyline_connectors.base import (
    ApiCall,
    ApiGateway,
    AssetRecord,
    RelationshipRecord,
    Scope,
    ValidationResult,
)
from skyline_connectors.fake.dataset import ACCOUNT_ID
from skyline_core.types import JSON

_S: Final = "fake"
GET_CALLER_IDENTITY: Final = ApiCall(_S, "GetCallerIdentity")
LIST_REGIONS: Final = ApiCall(_S, "ListRegions")
DESCRIBE_INSTANCES: Final = ApiCall(_S, "DescribeInstances")
DESCRIBE_SECURITY_GROUPS: Final = ApiCall(_S, "DescribeSecurityGroups")
LIST_BUCKETS: Final = ApiCall(_S, "ListBuckets")
GET_BUCKET_ENCRYPTION: Final = ApiCall(_S, "GetBucketEncryption")
LIST_USERS: Final = ApiCall(_S, "ListUsers")
LIST_ROLES: Final = ApiCall(_S, "ListRoles")

type Record = AssetRecord | RelationshipRecord


def _items(page: Mapping[str, JSON], key: str) -> list[dict[str, JSON]]:
    """Validate the shape of a list field in an (untrusted) response."""
    value = page.get(key, [])
    if not isinstance(value, list) or not all(isinstance(i, dict) for i in value):
        msg = f"unexpected response shape for {key}"
        raise TypeError(msg)
    return cast(list[dict[str, JSON]], value)


def _tags(item: Mapping[str, JSON]) -> dict[str, str]:
    tags = item.get("tags") or {}
    return {str(k): str(v) for k, v in tags.items()} if isinstance(tags, dict) else {}


def _native(kind: str, item_id: JSON) -> str:
    return f"fake://{ACCOUNT_ID}/{kind}/{item_id}"


class FakeConnector:
    """Implements :class:`skyline_connectors.base.Connector` for the fake cloud."""

    provider: ClassVar[str] = "fake"
    api_allowlist: ClassVar[frozenset[ApiCall]] = frozenset(
        {
            GET_CALLER_IDENTITY,
            LIST_REGIONS,
            DESCRIBE_INSTANCES,
            DESCRIBE_SECURITY_GROUPS,
            LIST_BUCKETS,
            GET_BUCKET_ENCRYPTION,
            LIST_USERS,
            LIST_ROLES,
        }
    )

    def __init__(self, *, gateway: ApiGateway) -> None:
        self._gw = gateway

    async def validate_credentials(self) -> ValidationResult:
        identity = await self._gw.call(GET_CALLER_IDENTITY)
        return ValidationResult(ok=True, identity=str(identity.get("Principal", "")))

    async def discover_scopes(self) -> Sequence[Scope]:
        regions = (await self._gw.call(LIST_REGIONS)).get("Regions", [])
        if not isinstance(regions, list):
            msg = "unexpected response shape for Regions"
            raise TypeError(msg)
        scopes = [Scope(kind="account", id=ACCOUNT_ID)]
        scopes += [Scope(kind="region", id=str(r), parent_id=ACCOUNT_ID) for r in regions]
        return scopes

    async def collect(self, scope: Scope) -> AsyncIterator[Record]:
        if scope.kind == "account":
            async for record in self._collect_identity(scope):
                yield record
        else:
            async for record in self._collect_region(scope):
                yield record

    async def _collect_identity(self, scope: Scope) -> AsyncIterator[Record]:
        for role in _items(await self._gw.call(LIST_ROLES), "Roles"):
            yield AssetRecord(
                resource_type="fake.identity.role",
                native_id=_native("role", role["id"]),
                name=str(role.get("name", role["id"])),
                account_id=ACCOUNT_ID,
                region=None,
                tags={},
                raw_config=role,
                scope_id=scope.id,
            )
        for user in _items(await self._gw.call(LIST_USERS), "Users"):
            yield AssetRecord(
                resource_type="fake.identity.user",
                native_id=_native("user", user["id"]),
                name=str(user["id"]),
                account_id=ACCOUNT_ID,
                region=None,
                tags={},
                raw_config=user,
                scope_id=scope.id,
            )
            for role_id in cast(list[JSON], user.get("roles") or []):
                yield RelationshipRecord(
                    _native("user", user["id"]), _native("role", role_id), "member_of"
                )

    async def _collect_region(self, scope: Scope) -> AsyncIterator[Record]:
        region = scope.id
        for group in _items(
            await self._gw.call(DESCRIBE_SECURITY_GROUPS, Region=region), "SecurityGroups"
        ):
            yield self._asset("fake.network.security_group", "sg", group, scope)
        async for page in self._gw.paginate(DESCRIBE_INSTANCES, Region=region):
            for vm in _items(page, "Instances"):
                yield self._asset("fake.compute.vm", "vm", vm, scope)
                for group_id in cast(list[JSON], vm.get("security_groups") or []):
                    yield RelationshipRecord(
                        _native("vm", vm["id"]), _native("sg", group_id), "attached_to"
                    )
                if vm.get("role"):
                    yield RelationshipRecord(
                        _native("vm", vm["id"]), _native("role", vm["role"]), "uses_role"
                    )
        for bucket in _items(await self._gw.call(LIST_BUCKETS, Region=region), "Buckets"):
            encryption = await self._gw.call(GET_BUCKET_ENCRYPTION, Bucket=bucket["id"])
            yield self._asset(
                "fake.storage.bucket",
                "bucket",
                {**bucket, "encryption": encryption.get("Encryption")},
                scope,
            )

    @staticmethod
    def _asset(resource_type: str, kind: str, item: dict[str, JSON], scope: Scope) -> AssetRecord:
        return AssetRecord(
            resource_type=resource_type,
            native_id=_native(kind, item["id"]),
            name=str(item.get("name") or item["id"]),
            account_id=ACCOUNT_ID,
            region=scope.id,
            tags=_tags(item),
            raw_config={k: v for k, v in item.items() if k != "tags"},
            scope_id=scope.id,
        )
