"""Parser failures that the API turns into controlled errors."""


class ParseRejection(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
