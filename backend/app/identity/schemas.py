"""Validated administration and token-exchange contracts for enterprise identity."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class SamlSettingsWrite(BaseModel):
    metadata_xml: str = Field(min_length=128, max_length=100_000)
    is_active: bool = True
    enforce_sso: bool = False
    jit_provisioning: bool = False
    require_mfa: bool = False
    default_role_code: Literal[
        "ORG_ADMIN",
        "SECURITY_ADMIN",
        "SECURITY_ANALYST",
        "CLOUD_ENGINEER",
        "AUDITOR",
        "VIEWER",
    ] = "VIEWER"
    email_attribute: str = Field(default="email", min_length=1, max_length=200)
    name_attribute: str = Field(default="name", min_length=1, max_length=200)
    mfa_contexts: list[str] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def validate_mfa_policy(self) -> "SamlSettingsWrite":
        if self.require_mfa and not self.enforce_sso:
            raise ValueError("Organization MFA enforcement requires SSO enforcement to prevent password-login bypass.")
        if self.require_mfa and not self.mfa_contexts:
            raise ValueError("At least one IdP MFA authentication context is required when MFA is enforced.")
        return self

    @field_validator("metadata_xml")
    @classmethod
    def reject_external_entities(cls, value: str) -> str:
        normalized = value.lower()
        if "<!doctype" in normalized or "<!entity" in normalized:
            raise ValueError("SAML metadata must not declare document types or entities")
        return value

    @field_validator("email_attribute", "name_attribute")
    @classmethod
    def validate_attribute_name(cls, value: str) -> str:
        if any(ord(character) < 32 for character in value):
            raise ValueError("Attribute names cannot contain control characters")
        return value.strip()

    @field_validator("mfa_contexts")
    @classmethod
    def validate_mfa_contexts(cls, values: list[str]) -> list[str]:
        cleaned = list(dict.fromkeys(value.strip() for value in values if value.strip()))
        if any(len(value) > 300 or not value.startswith("urn:") for value in cleaned):
            raise ValueError("Authentication contexts must be URN identifiers")
        return cleaned


class SamlSettingsRead(BaseModel):
    configured: bool
    active: bool
    enforce_sso: bool
    jit_provisioning: bool
    require_mfa: bool
    default_role_code: str
    email_attribute: str
    name_attribute: str
    mfa_contexts: list[str]
    metadata_url: str
    login_url: str


class ScimTokenCreate(BaseModel):
    description: str = Field(default="SCIM provisioning", min_length=1, max_length=200)


class ScimTokenCreated(BaseModel):
    token: str
    expires_at: str
    scim_base_url: str


class ScimGroupMappingWrite(BaseModel):
    display_name: str = Field(min_length=1, max_length=200)
    role_code: Literal[
        "ORG_ADMIN",
        "SECURITY_ADMIN",
        "SECURITY_ANALYST",
        "CLOUD_ENGINEER",
        "AUDITOR",
        "VIEWER",
    ]


class SsoExchangeRequest(BaseModel):
    code: str = Field(min_length=32, max_length=128)
