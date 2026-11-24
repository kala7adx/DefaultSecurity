"""Read-only allowlist validation (ADR-0005 layer 2).

Every allowlist entry must look like a read operation for its connector's API style, and must
not be one of the reviewed **data-plane or credential-minting "reads"**:

* ``sdk``  (AWS-style operation names): must start with ``Describe``, ``List`` or ``Get``
  followed by an upper-case letter, e.g. ``DescribeInstances``, and must not be in
  :data:`DENIED_SDK_OPERATIONS` (``GetSecretValue``, ``GetObject``, ``GetSessionToken`` …).
* ``http`` (Graph, Google, Azure REST): must be ``GET <path>`` with no ``..`` segment and no
  content endpoint (mail, files, ``$value`` …). Read-only POSTs (query endpoints) need an ADR
  note and an explicit entry in ``REVIEWED_READ_ONLY_POSTS``.

Checked when a connector is registered, so these can't even be declared. The onboarding IAM
policies (Phase 1) deny the same operations a second time, in the customer's account.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from enum import StrEnum
from typing import Final

from skyline_connectors.base import ApiCall, ReadOnlyViolationError

_SDK_READ: Final = re.compile(r"^(Describe|List|Get)[A-Z][A-Za-z0-9]*$")
_HTTP_GET: Final = re.compile(r"^GET /[A-Za-z0-9._~/{}$=,:@-]*$")
_SERVICE: Final = re.compile(r"^[a-z][a-z0-9-]{1,40}$")

#: "Reads" that return customer data or secrets, or mint credentials. Never allowed, whatever
#: the service. Extend it whenever a provider adds one; each entry has a negative test.
#: A name list can never be complete: it is a tripwire. The hard boundary is the customer-
#: side read-only role with explicit Denies (ADR-0005 layer 1). Each name is re-checked
#: against the AWS Service Authorization Reference when its service gets a collector.
DENIED_SDK_OPERATIONS: Final = frozenset(
    {
        # Secrets and parameters
        "GetSecretValue",
        "BatchGetSecretValue",
        "GetParameter",
        "GetParameters",
        "GetParametersByPath",
        "GetParameterHistory",
        # Object, record and log data
        "GetObject",
        "GetObjectTorrent",
        "GetRecords",
        "GetShardIterator",
        "GetItem",
        "BatchGetItem",
        "GetLogEvents",
        "GetQueryResults",
        "GetBlob",
        "GetDownloadUrlForLayer",
        # Instance data and console output
        "GetPasswordData",
        "GetConsoleOutput",
        "GetConsoleScreenshot",
        # Function code (presigned code URL) — use GetFunctionConfiguration instead
        "GetFunction",
        # Credential minting
        "GetSessionToken",
        "GetFederationToken",
        "GetAuthorizationToken",
        "GetSigninToken",
        "GetClusterCredentials",
        "GetCredentialsForIdentity",
        "GetOpenIdToken",
        "GetId",
        "GetRoleCredentials",
        "GetTemporaryGlueTableCredentials",
        "GetClusterCredentialsWithIAM",
        "GetCredentials",
        "GetOpenIdTokenForDeveloperIdentity",
        "GetTemporaryGluePartitionCredentials",
        "GetDataAccess",
        "GetServiceBearerToken",
        "GetClusterSessionCredentials",
        "GetEnvironmentCredentials",
        "GetWebIdentityToken",
        # Secrets returned by "configuration" reads
        "GetInstanceAccessDetails",
        "GetRelationalDatabaseMasterUserPassword",
        "GetConnection",
        "GetConnections",
        "GetApiKey",
        "GetApiKeys",
        "ListApiKeys",
        # Content, payloads and presigned URLs
        "GetLayerVersion",
        "GetLayerVersionByArn",
        "GetFile",
        "GetLogRecord",
        "GetCommandInvocation",
        "GetConfiguration",
        "GetLatestConfiguration",
        "GetHostedConfigurationVersion",
        "GetExecutionHistory",
        "DescribeExecution",
        "GetMedia",
        "GetMediaForFragmentList",
        "GetClip",
        "GetIceServerConfig",
        "GetDashboardEmbedUrl",
        "GetSessionEmbedUrl",
        "GetPersistentAppUIPresignedURL",
        "GetOnClusterAppUIPresignedURL",
    }
)

#: HTTP paths that read content rather than configuration (Graph mail, files, calendars …).
_HTTP_DENIED: Final = re.compile(
    r"(?i)(/\.\.(/|$)|/(messages|attachments|mailfolders|events|calendarview|content|\$value"
    r"|chats|channels/[^/]+/messages)(/|$))"
)

#: Reviewed read-only POST endpoints, each with an ADR reference. Empty in Phase 0.
REVIEWED_READ_ONLY_POSTS: Final[frozenset[ApiCall]] = frozenset()


class AllowlistStyle(StrEnum):
    SDK = "sdk"
    HTTP = "http"


def is_read_only(api: ApiCall, style: AllowlistStyle) -> bool:
    """True if ``api`` is an acceptable read-only, configuration-only operation."""
    if not _SERVICE.match(api.service):
        return False
    if style is AllowlistStyle.SDK:
        return bool(_SDK_READ.match(api.operation)) and api.operation not in DENIED_SDK_OPERATIONS
    if api in REVIEWED_READ_ONLY_POSTS:
        return True
    return bool(_HTTP_GET.match(api.operation)) and not _HTTP_DENIED.search(api.operation)


def validate_allowlist(calls: Iterable[ApiCall], style: AllowlistStyle) -> frozenset[ApiCall]:
    """Return the allowlist, or raise :class:`ReadOnlyViolationError` naming bad entries."""
    allowlist = frozenset(calls)
    if not allowlist:
        msg = "a connector must declare at least one API call"
        raise ReadOnlyViolationError(msg)
    bad = sorted(str(api) for api in allowlist if not is_read_only(api, style))
    if bad:
        msg = f"allowlist contains non-read-only operations: {', '.join(bad)}"
        raise ReadOnlyViolationError(msg)
    return allowlist
