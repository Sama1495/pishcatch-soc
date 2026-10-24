"""Application errors that map to a uniform JSON envelope."""


class AppError(Exception):
    """Controlled failure returned to API clients.

    ``message`` must be generic. Do not include email bodies, headers that
    may contain personal data, secrets, or parser internals.
    """

    def __init__(
        self,
        code: str,
        message: str,
        status_code: int,
        details: dict | list | str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details
