"""Safe domain errors translated to stable API error responses."""


class DomainError(Exception):
    """Application error safe to present at the HTTP boundary."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


class NotFoundError(DomainError):
    """A resource is missing or outside the caller's organization scope."""

    def __init__(self, resource: str = "Resource") -> None:
        super().__init__(404, "not_found", f"{resource} was not found.")


class ConflictError(DomainError):
    """A request conflicts with an existing resource or invariant."""

    def __init__(self, message: str = "The request conflicts with current state.") -> None:
        super().__init__(409, "conflict", message)


class InvalidOperationError(DomainError):
    """A requested transition violates an application invariant."""

    def __init__(self, message: str = "The requested operation is not valid.") -> None:
        super().__init__(400, "invalid_operation", message)


class ServiceUnavailableError(DomainError):
    """A required asynchronous service is temporarily unavailable."""

    def __init__(self, message: str = "The requested service is temporarily unavailable.") -> None:
        super().__init__(503, "service_unavailable", message)
