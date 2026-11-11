"""Normalize AWS field projections into safe, provider-neutral inventory records."""

import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any


@dataclass(frozen=True)
class ResourceReference:
    """A relationship endpoint resolved against inventory after the scan batch."""

    resource_type: str
    resource_id: str
    region_code: str
    relationship_type: str


@dataclass(frozen=True)
class NormalizedAsset:
    """Safe, provider-neutral projection of one discovered cloud resource."""

    resource_type: str
    resource_id: str
    resource_arn: str | None
    region_code: str
    name: str | None
    tags: dict[str, str]
    owner_metadata: dict[str, str] | None
    attributes: dict[str, Any]
    relationships: tuple[ResourceReference, ...]


def normalize_aws_resource(
    resource_type: str,
    resource_id: str,
    name: Any,
    region_code: str,
    raw_tags: Any = None,
    *,
    attributes: dict[str, Any] | None = None,
    arn: str | None = None,
    relationships: tuple[ResourceReference, ...] = (),
) -> NormalizedAsset:
    """Convert selected collector fields to JSON-safe shared asset attributes."""
    tags = _normalize_tags(raw_tags)
    return NormalizedAsset(
        resource_type=resource_type,
        resource_id=str(resource_id),
        resource_arn=arn,
        region_code=region_code,
        name=str(name) if name is not None else None,
        tags=tags,
        owner_metadata={"owner": tags["Owner"]} if tags.get("Owner") else None,
        attributes=_json_safe(attributes or {}),
        relationships=relationships,
    )


def _normalize_tags(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {
            str(key): str(item)
            for key, item in value.items()
            if item is not None and not _sensitive_tag_key(str(key))
        }
    if isinstance(value, list):
        return {
            str(item.get("Key", item.get("key"))): str(item.get("Value", item.get("value")))
            for item in value
            if item.get("Key", item.get("key")) is not None
            and item.get("Value", item.get("value")) is not None
            and not _sensitive_tag_key(str(item.get("Key", item.get("key"))))
        }
    return {}


def _sensitive_tag_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    return any(
        marker in normalized
        for marker in (
            "secret",
            "password",
            "credential",
            "token",
            "accesskey",
            "privatekey",
            "apikey",
        )
    )


def sanitize_evidence(value: Any) -> Any:
    """Convert JSON values and omit fields whose keys commonly carry credentials."""
    if isinstance(value, dict):
        return {
            str(key): sanitize_evidence(item)
            for key, item in value.items()
            if not _sensitive_tag_key(str(key)) and item is not None
        }
    if isinstance(value, (list, tuple)):
        return [sanitize_evidence(item) for item in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items() if item is not None}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)
