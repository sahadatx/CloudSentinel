"""SCIM protocol errors that preserve the standard error response envelope."""


class ScimProtocolError(Exception):
    def __init__(self, status_code: int, message: str, scim_type: str | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.scim_type = scim_type
