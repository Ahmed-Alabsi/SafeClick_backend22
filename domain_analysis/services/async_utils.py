import asyncio
import aiohttp
import logging
import threading
import time
from typing import Callable, Any, Optional

logger = logging.getLogger(__name__)

# --- Persistent Background Event Loop ---
# Solves the 'Event loop is closed' bug caused by asyncio.run() destroying
# the loop after each call, orphaning the global aiohttp session.
_bg_loop: Optional[asyncio.AbstractEventLoop] = None
_bg_thread: Optional[threading.Thread] = None
_bg_lock = threading.Lock()

def _get_bg_loop() -> asyncio.AbstractEventLoop:
    """Returns a persistent background event loop running in a daemon thread."""
    global _bg_loop, _bg_thread
    if _bg_loop is not None and _bg_loop.is_running():
        return _bg_loop
    with _bg_lock:
        if _bg_loop is not None and _bg_loop.is_running():
            return _bg_loop
        _bg_loop = asyncio.new_event_loop()
        _bg_thread = threading.Thread(target=_bg_loop.run_forever, daemon=True)
        _bg_thread.start()
        logger.info("[AsyncUtils] Background event loop started.")
    return _bg_loop

def run_async(coro):
    """
    Runs an async coroutine from synchronous Django code.
    Uses a persistent background event loop instead of asyncio.run()
    to prevent the 'Event loop is closed' bug.
    """
    loop = _get_bg_loop()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return future.result(timeout=30)  # 30s hard timeout

# --- DNS over HTTPS (DoH) Resolver ---
# Bypasses local ISP blocking and Transparent DNS Proxying
import socket
from aiohttp.abc import AbstractResolver
from aiohttp.resolver import ThreadedResolver

class DoHResolver(AbstractResolver):
    def __init__(self):
        self.fallback = ThreadedResolver()

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET) -> list:
        # Check if already IP
        try:
            socket.inet_aton(host)
            return await self.fallback.resolve(host, port, family)
        except socket.error:
            pass

        try:
            import urllib.request, json, ssl, asyncio
            def fetch_doh():
                req = urllib.request.Request(
                    f'https://8.8.8.8/resolve?name={host}&type=A',
                    headers={'Host':'dns.google', 'Accept':'application/dns-json'}
                )
                ctx = ssl._create_unverified_context()
                with urllib.request.urlopen(req, context=ctx, timeout=3.0) as res:
                    return json.loads(res.read())
            
            loop = asyncio.get_running_loop()
            data = await loop.run_in_executor(None, fetch_doh)
            if data and data.get('Status') == 0 and 'Answer' in data:
                ips = [a['data'] for a in data['Answer'] if a['type'] == 1]
                if ips:
                    ip = ips[0]
                    try:
                        from aiohttp.resolver import ResolveResult
                        return [ResolveResult(hostname=host, host=ip, port=port, family=socket.AF_INET, proto=0, flags=socket.AI_NUMERICHOST)]
                    except ImportError:
                        return [{'hostname': host, 'host': ip, 'port': port, 'family': socket.AF_INET, 'proto': 0, 'flags': socket.AI_NUMERICHOST}]
        except Exception as e:
            logger.debug(f"[DoH] Failed to resolve {host}: {e}")
            
        return await self.fallback.resolve(host, port, family)

    async def close(self) -> None:
        await self.fallback.close()

# Global Async Session — initialized lazily inside the event loop
_global_session: Optional[aiohttp.ClientSession] = None
# BUG #2 FIX: Do NOT create asyncio.Lock() at module level.
# It must be created inside a running event loop (Python 3.10+ requirement).
_session_lock: Optional[asyncio.Lock] = None

def _is_session_alive(session: aiohttp.ClientSession) -> bool:
    """Check if the session is still usable (not closed and loop alive)."""
    if session is None or session.closed:
        return False
    try:
        loop = session._connector._loop  # internal check
        if loop is not None and loop.is_closed():
            return False
    except (AttributeError, Exception):
        pass
    return True

async def get_async_session() -> aiohttp.ClientSession:
    """
    Returns a persistent, globally shared aiohttp.ClientSession.
    Ensures connection pooling and eliminates the overhead of creating a session per request.
    Includes stale loop detection to prevent 'Event loop is closed' errors.
    """
    global _global_session, _session_lock
    # BUG #2 FIX: Lazy-initialize the lock inside the running event loop.
    if _session_lock is None:
        _session_lock = asyncio.Lock()
    if not _is_session_alive(_global_session):
        async with _session_lock:
            if not _is_session_alive(_global_session):
                # Close old session if it exists but is stale
                if _global_session is not None:
                    try:
                        await _global_session.close()
                    except Exception:
                        pass
                # Custom DNS Resolver to bypass ISP blocks
                try:
                    resolver = DoHResolver()
                    connector = aiohttp.TCPConnector(resolver=resolver, limit=100, keepalive_timeout=30)
                    logger.info("[AsyncUtils] DNS over HTTPS (DoH) Resolver activated to bypass local blocking.")
                except Exception as e:
                    logger.warning(f"[AsyncUtils] Failed to initialize DoH Resolver: {e}")
                    connector = aiohttp.TCPConnector(limit=100, keepalive_timeout=30)
                _global_session = aiohttp.ClientSession(
                    connector=connector,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    }
                )
                logger.debug("[AsyncUtils] New aiohttp session created.")
    return _global_session

async def close_async_session():
    """Closes the global session gracefully."""
    global _global_session
    if _global_session and not _global_session.closed:
        await _global_session.close()

# --- Circuit Breaker Pattern ---
class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 60.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failures = 0
        self.state = "CLOSED" # CLOSED (normal), OPEN (broken), HALF_OPEN (recovering)
        self.last_failure_time = 0.0

    def record_failure(self):
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.state = "OPEN"
            # BUG #3 FIX: Use time.monotonic() — thread-safe, no event loop needed.
            self.last_failure_time = time.monotonic()
            logger.warning(f"[CircuitBreaker] State changed to OPEN. Too many failures.")

    def record_success(self):
        if self.state in ("OPEN", "HALF_OPEN"):
            logger.info(f"[CircuitBreaker] State changed to CLOSED. Service recovered.")
        self.failures = 0
        self.state = "CLOSED"

    def can_execute(self) -> bool:
        if self.state == "CLOSED":
            return True
        elif self.state == "OPEN":
            # BUG #3 FIX: Use time.monotonic() — no event loop dependency.
            now = time.monotonic()
            if now - self.last_failure_time > self.recovery_timeout:
                self.state = "HALF_OPEN"
                return True
            return False
        elif self.state == "HALF_OPEN":
            # Only allow one test request to go through
            return True
        return True

# Global circuit breakers for specific external services
RDAP_CIRCUIT_BREAKER = CircuitBreaker(failure_threshold=10, recovery_timeout=30.0)
DNS_CIRCUIT_BREAKER = CircuitBreaker(failure_threshold=15, recovery_timeout=20.0)

# --- Retry Strategy & Engine Wrapper ---
async def execute_with_retry_and_timeout(
    engine_name: str,
    call: Callable,
    *args,
    max_retries: int = 2,
    timeout: float = 3.0,
    circuit_breaker: Optional[CircuitBreaker] = None,
    **kwargs
) -> dict:
    """
    Enterprise-level wrapper for engine execution:
    1. Enforces strict timeouts (Observability).
    2. Enforces retry policies for transient failures.
    3. Respects Circuit Breaker state to prevent cascading failures.
    """
    if circuit_breaker and not circuit_breaker.can_execute():
        logger.warning(f"Engine {engine_name} skipped due to OPEN Circuit Breaker.")
        return {"status": "error", "error": "Circuit Breaker OPEN. Service temporarily skipped."}

    for attempt in range(max_retries + 1):
        try:
            # Wrap the actual call with a strict wait_for timeout
            result = await asyncio.wait_for(call(*args, **kwargs), timeout=timeout)
            
            if circuit_breaker:
                circuit_breaker.record_success()
                
            return result
        except asyncio.TimeoutError:
            logger.debug(f"Engine {engine_name} timeout (attempt {attempt + 1}/{max_retries + 1})")
            if attempt == max_retries:
                if circuit_breaker:
                    circuit_breaker.record_failure()
                return {"status": "error", "error": f"Timeout after {timeout}s"}
        except Exception as e:
            logger.debug(f"Engine {engine_name} error: {e} (attempt {attempt + 1}/{max_retries + 1})")
            if attempt == max_retries:
                if circuit_breaker:
                    circuit_breaker.record_failure()
                logger.error(f"Engine {engine_name} failed completely: {e}", exc_info=False)
                return {"status": "error", "error": str(e)}
            
        # Exponential backoff for I/O bounds
        await asyncio.sleep(0.5 * (2 ** attempt))

    return {"status": "error", "error": "Max retries exceeded"}

# --- CPU/IO Separation Wrapper ---
async def run_cpu_bound(func: Callable, *args, **kwargs) -> Any:
    """
    Offloads heavy CPU-bound algorithms (e.g., rapidfuzz calculations) to a thread pool
    so the async event loop is never blocked.
    """
    import functools
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, functools.partial(func, *args, **kwargs))
