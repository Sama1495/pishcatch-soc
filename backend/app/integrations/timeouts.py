"""Bound a stub or future provider call so a hang cannot stall triage."""

from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout


def call_with_timeout(func, timeout: float, *args, **kwargs):
    """Run ``func`` and raise ``TimeoutError`` when ``timeout`` seconds elapse.

    ``shutdown(wait=False)`` returns control to the caller if the worker is still
    running. Live providers must also set their own socket timeouts.
    """
    if timeout <= 0:
        raise TimeoutError("timeout must be positive")
    pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="phishcatch-io")
    try:
        future = pool.submit(func, *args, **kwargs)
        try:
            return future.result(timeout=timeout)
        except FuturesTimeout as exc:
            raise TimeoutError(f"timed out after {timeout} seconds") from exc
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
