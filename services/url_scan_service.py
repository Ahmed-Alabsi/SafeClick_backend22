# services/url_scan_service.py
"""
URL Scan API Wrapper
────────────────────
Provides a backward-compatible wrapper for the ScanOrchestrator.
Maintains the lock/cache logic while delegating complex analysis.
"""

import hashlib
import logging
import time
from django.utils import timezone
from django.core.cache import cache

from services.scan_orchestrator import ScanOrchestrator

logger = logging.getLogger(__name__)

def scan_url(url: str, user=None, guest_id=None, scan_level='basic', ignore_cache: bool = False):
    """
    Main entry point for API views.
    Passes execution to ScanOrchestrator (Decision Engine).
    """
    try:
        # Prevent concurrent identical scans by using a short Redis lock
        url_hash = hashlib.sha256(url.encode('utf-8')).hexdigest()
        lock_id = f"lock:scan:{url_hash}"
        lock = getattr(cache, 'lock', None)
        
        locked = False
        redis_lock = None
        
        # Only use lock if not ignoring cache (forced scans should run immediately)
        try:
            if lock and not ignore_cache:
                redis_lock = lock(lock_id, timeout=10)
                locked = redis_lock.acquire(blocking=False)
                if not locked:
                    # Wait briefly if another thread is scanning the exact same URL right now
                    time.sleep(2)
        except Exception as cache_err:
            logger.warning(f"[SYSTEM] Redis lock failed, bypassing: {cache_err}")
            locked = False
            redis_lock = None
        
        try:
            orchestrator = ScanOrchestrator(request_user=user, guest_id=guest_id)
            # Route through the Phase 1..4 Decision Engine pipeline
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
            
        finally:
            if locked and lock and redis_lock:
                try:
                    redis_lock.release()
                except Exception:
                    pass
                
    except Exception as e:
        logger.error(f"[SYSTEM] Unexpected orchestration error: {str(e)}", exc_info=True)
        return {
            "success": False,
            "error": "Failed to scan URL due to an internal error."
        }
