# services/url_scan_service.py
"""
URL Scan API Wrapper
────────────────────
Provides a backward-compatible wrapper for the ScanOrchestrator.
Maintains multi-tier deduplication locking (Redis distributed lock + Local process fallback lock)
with post-lock cache resolution to prevent concurrent duplicate scans.
"""

import hashlib
import logging
import threading
import time
from django.utils import timezone
from django.core.cache import cache

from services.scan_orchestrator import ScanOrchestrator

logger = logging.getLogger(__name__)

# Process-level fallback locks for deduplication when Redis is absent
_local_locks: dict[str, threading.Lock] = {}
_master_lock = threading.Lock()

def _get_local_lock(url_hash: str) -> threading.Lock:
    with _master_lock:
        if url_hash not in _local_locks:
            _local_locks[url_hash] = threading.Lock()
        return _local_locks[url_hash]

def scan_url(url: str, user=None, guest_id=None, scan_level='basic', ignore_cache: bool = False):
    """
    Main entry point for API views.
    Passes execution to ScanOrchestrator (Decision Engine).
    Implements multi-tier deduplication locking (Redis distributed lock + Local process fallback lock).
    """
    url_hash = hashlib.sha256(url.encode('utf-8')).hexdigest()
    lock_id = f"lock:scan:{url_hash}"
    lock_func = getattr(cache, 'lock', None)
    
    redis_lock = None
    local_lock = None
    redis_locked = False
    local_locked = False

    try:
        # Only use deduplication locking if not ignoring cache (forced scans run immediately)
        if not ignore_cache:
            # 1. Try distributed Redis lock
            if lock_func:
                try:
                    redis_lock = lock_func(lock_id, timeout=15)
                    redis_locked = redis_lock.acquire(blocking=False)
                    if not redis_locked:
                        logger.info(f"[LOCK] Concurrent scan detected for {url_hash}. Waiting for ongoing scan...")
                        try:
                            redis_locked = redis_lock.acquire(blocking=True, timeout=10)
                        except Exception:
                            time.sleep(2)
                except Exception as redis_err:
                    logger.warning(f"[SYSTEM] Redis lock unavailable, using process lock: {redis_err}")
                    redis_locked = False
                    redis_lock = None

            # 2. If Redis lock not acquired (or Redis unavailable), use process-level lock fallback
            if not redis_locked:
                local_lock = _get_local_lock(url_hash)
                local_locked = local_lock.acquire(timeout=10)

        # Execute scan via ScanOrchestrator (reads cache if previous concurrent scan just finished)
        orchestrator = ScanOrchestrator(request_user=user, guest_id=guest_id)
        result_dict = orchestrator.scan(url, scan_level=scan_level, ignore_cache=ignore_cache)
        
        # Add metadata and status for the view
        result_dict['success'] = True
        result_dict['safe'] = result_dict.get('result') == 'safe'
        result_dict['threats_count'] = len([
            s for s in result_dict.get('sources', []) 
            if s.get('verdict') in ('suspicious', 'malicious', 'dangerous')
        ])
        result_dict['scanned_at'] = timezone.now().isoformat()
        
        # Add cache meta info
        result_dict['meta'] = {
            'cache_hit': result_dict.get('cached', False),
            'scan_level': result_dict.get('scan_level_used')
        }
        
        return result_dict

    except Exception as e:
        logger.error(f"[SYSTEM] Unexpected orchestration error: {str(e)}", exc_info=True)
        return {
            "success": False,
            "error": "Failed to scan URL due to an internal error."
        }
    finally:
        if redis_locked and redis_lock:
            try:
                redis_lock.release()
            except Exception:
                pass
        if local_locked and local_lock:
            try:
                local_lock.release()
            except Exception:
                pass
