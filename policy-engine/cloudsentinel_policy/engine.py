"""Safe, data-driven policy evaluation over normalized cloud assets."""

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator


class RiskInputs(BaseModel):
    """Documented 0–100 contextual factors carried by a policy rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    exploitability: int = Field(ge=0, le=100)
    exposure: int = Field(ge=0, le=100)
    asset_criticality: int = Field(ge=0, le=100)
    business_impact: int = Field(ge=0, le=100)
    compliance_impact: int = Field(ge=0, le=100)


class ComplianceReference(BaseModel):
    """A versioned framework control reference attached to a rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    framework: str
    control: str
    title: str = Field(default="UNRESOLVED", max_length=300)


class RuleDefinition(BaseModel):
    """Versioned policy-as-code rule loaded from a JSON package resource."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Z0-9][A-Z0-9_.-]+$")
    name: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1, max_length=2000)
    version: str = Field(min_length=1, max_length=40)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    category: str = Field(min_length=1, max_length=100)
    resource_types: tuple[str, ...] = Field(min_length=1, max_length=20)
    condition: dict[str, Any]
    remediation: str = Field(min_length=1, max_length=2000)
    risk: RiskInputs | None = None
    compliance_controls: tuple[ComplianceReference, ...] = ()

    @model_validator(mode="after")
    def validate_condition_tree(self) -> "RuleDefinition":
        _validate_condition(self.condition)
        return self


@dataclass(frozen=True)
class PolicyEvaluation:
    """One applicable rule and the limited fields that triggered its condition."""

    rule: RuleDefinition
    matched: bool
    observed: dict[str, Any]


@lru_cache(maxsize=1)
def load_aws_rules() -> tuple[RuleDefinition, ...]:
    """Load and validate packaged JSON rule definitions."""
    directory = files("cloudsentinel_policy.rules.aws")
    rules: list[RuleDefinition] = []
    for resource in sorted(directory.iterdir(), key=lambda item: item.name):
        if resource.name.endswith(".json"):
            try:
                rules.append(RuleDefinition.model_validate(json.loads(resource.read_text())))
            except (json.JSONDecodeError, ValidationError) as error:
                raise RuntimeError(f"Invalid bundled policy rule: {resource.name}") from error
    return tuple(rules)


def evaluate_asset(asset: dict[str, Any]) -> tuple[PolicyEvaluation, ...]:
    """Evaluate applicable AWS rules without executing policy-document code."""
    evaluations: list[PolicyEvaluation] = []
    for rule in load_aws_rules():
        if asset.get("resource_type") not in rule.resource_types:
            continue
        matched, observed = _evaluate_condition(rule.condition, asset)
        evaluations.append(PolicyEvaluation(rule=rule, matched=matched, observed=observed))
    return tuple(evaluations)


def evaluate_rule(rule: RuleDefinition, asset: dict[str, Any]) -> PolicyEvaluation | None:
    """Evaluate one validated rule against one canonical asset, if applicable."""
    if asset.get("resource_type") not in rule.resource_types:
        return None
    matched, observed = _evaluate_condition(rule.condition, asset)
    return PolicyEvaluation(rule=rule, matched=matched, observed=observed)


def _evaluate_condition(
    condition: dict[str, Any], asset: dict[str, Any]
) -> tuple[bool, dict[str, Any]]:
    if set(condition) == {"all"} and isinstance(condition["all"], list):
        matches = [_evaluate_condition(child, asset) for child in condition["all"]]
        return all(matched for matched, _ in matches), {
            key: value
            for _matched, observed in matches
            for key, value in observed.items()
        }
    if set(condition) == {"any"} and isinstance(condition["any"], list):
        matches = [_evaluate_condition(child, asset) for child in condition["any"]]
        return any(matched for matched, _ in matches), {
            key: value
            for _matched, observed in matches
            for key, value in observed.items()
        }
    if set(condition) != {"path", "op", "value"}:
        raise ValueError("Policy condition has an unsupported shape")
    path, operator, expected = condition["path"], condition["op"], condition["value"]
    if not isinstance(path, str) or not path or len(path) > 160:
        raise ValueError("Policy path is invalid")
    observed = _get_path(asset, path)
    matched = _compare(operator, observed, expected)
    return matched, {path: observed}


def _validate_condition(condition: dict[str, Any]) -> None:
    if set(condition) in ({"all"}, {"any"}):
        children = next(iter(condition.values()))
        if not isinstance(children, list) or not children:
            raise ValueError("Policy boolean groups must contain at least one condition")
        for child in children:
            if not isinstance(child, dict):
                raise ValueError("Policy child conditions must be objects")
            _validate_condition(child)
        return
    if set(condition) != {"path", "op", "value"}:
        raise ValueError("Policy condition has an unsupported shape")
    if condition["op"] not in {"equals", "contains_port_source"}:
        raise ValueError("Policy operator is unsupported")
    if not isinstance(condition["path"], str) or not condition["path"]:
        raise ValueError("Policy path is invalid")


def _get_path(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _compare(operator: Any, observed: Any, expected: Any) -> bool:
    if operator == "equals":
        return bool(observed == expected)
    if operator == "contains_port_source":
        if not isinstance(observed, list) or not isinstance(expected, dict):
            return False
        port = expected.get("port")
        source = expected.get("source")
        if not isinstance(port, int) or not isinstance(source, str):
            return False
        for permission in observed:
            if not isinstance(permission, dict):
                continue
            protocol = permission.get("IpProtocol")
            from_port, to_port = permission.get("FromPort"), permission.get("ToPort")
            includes_port = protocol == "-1" or (
                isinstance(from_port, int)
                and isinstance(to_port, int)
                and from_port <= port <= to_port
            )
            if not includes_port:
                continue
            sources = [item.get("CidrIp") for item in permission.get("IpRanges", [])] + [
                item.get("CidrIpv6") for item in permission.get("Ipv6Ranges", [])
            ]
            if source in sources:
                return True
    return False
