import time
import asyncio
from functools import wraps
from apps.core.types import EngineResult

def monitor_engine(engine_name):
    """
    Centralized decorator to measure latency, catch exceptions, and unify response schema.
    Works for both synchronous and asynchronous functions.
    """
    def decorator(func):
        if asyncio.iscoroutinefunction(func):
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                start = time.monotonic()
                try:
                    result = await func(*args, **kwargs)
                    status = result.get("status", "ok") if isinstance(result, dict) else "ok"
                    error = result.get("error") if isinstance(result, dict) else None
                    # Strict Unified Data Contract: Do not flatten details.
                    data = result
                except asyncio.TimeoutError:
                    result = None
                    status = "timeout"
                    error = "Timeout occurred"
                    data = None
                except Exception as e:
                    result = None
                    status = "error"
                    error = str(e)
                    data = None

                latency = (time.monotonic() - start) * 1000
                
                # Slow engine detection
                if status == "ok" and latency > 2000:
                    status = "slow"

                return EngineResult(
                    engine=engine_name,
                    status=status,
                    latency_ms=round(latency, 2),
                    data=data,
                    error=error
                ).to_dict()

            return async_wrapper
        else:
            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                start = time.monotonic()
                try:
                    result = func(*args, **kwargs)
                    status = result.get("status", "ok") if isinstance(result, dict) else "ok"
                    error = result.get("error") if isinstance(result, dict) else None
                    # Strict Unified Data Contract: Do not flatten details.
                    data = result
                except Exception as e:
                    result = None
                    status = "error"
                    error = str(e)
                    data = None

                latency = (time.monotonic() - start) * 1000
                
                # Slow engine detection
                if status == "ok" and latency > 2000:
                    status = "slow"

                return EngineResult(
                    engine=engine_name,
                    status=status,
                    latency_ms=round(latency, 2),
                    data=data,
                    error=error
                ).to_dict()

            return sync_wrapper
    return decorator
