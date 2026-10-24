"""Map failures onto one JSON shape. Responses never include tracebacks or mail bodies."""

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.errors import AppError
from app.core.logging import get_logger

logger = get_logger()


def install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def handle_app_error(_request: Request, exc: AppError) -> JSONResponse:
        logger.warning("request_failed code=%s status=%s", exc.code, exc.status_code)
        return JSONResponse(status_code=exc.status_code, content=_body(exc.code, exc.message, exc.details))

    @app.exception_handler(HTTPException)
    async def handle_http_error(_request: Request, exc: HTTPException) -> JSONResponse:
        if exc.status_code == 404:
            code, message = "not_found", "The resource was not found."
        else:
            code, message = "http_error", "The request could not be processed."
        logger.warning("request_failed code=%s status=%s", code, exc.status_code)
        return JSONResponse(status_code=exc.status_code, content=_body(code, message, None))

    @app.exception_handler(RequestValidationError)
    async def handle_validation(_request: Request, _exc: RequestValidationError) -> JSONResponse:
        logger.warning("request_failed code=validation_error status=422")
        return JSONResponse(
            status_code=422,
            content=_body("validation_error", "Request validation failed.", None),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected(_request: Request, exc: Exception) -> JSONResponse:
        logger.error("unhandled_error type=%s", type(exc).__name__)
        return JSONResponse(
            status_code=500,
            content=_body("internal_error", "The request could not be processed.", None),
        )


def _body(code: str, message: str, details) -> dict:
    return {"error": {"code": code, "message": message, "details": details}}
