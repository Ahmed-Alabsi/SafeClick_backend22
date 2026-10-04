# apps/monitoring/services.py
"""
Engine Health Service
─────────────────────
Centralised, non-blocking writer for EngineHealthLog.

Design decisions
────────────────
1. Never raises — all paths are guarded so a monitoring failure
   NEVER aborts the scan pipeline (fail-safe principle).
2. Called once per scan from the orchestrator's _finalize() method,
   so every engine call in a Scan gets a corresponding health record.
3. Uses bulk_create for performance (one INSERT per scan, not N).
4. sync_to_async-safe: writes are dispatched to a thread pool via
   Django's database router, compatible with async callers.

Engine name → EngineHealthLog.ENGINE_CHOICES mapping
─────────────────────────────────────────────────────
Orchestrator source key     │ EngineHealthLog key
────────────────────────────┼─────────────────────
domain_analysis / engines   │ (sub-engines below)
  └─ dns                    │ dns
  └─ ssl                    │ ssl
  └─ domain_age             │ domain_age
  └─ typosquatting          │ typosquatting
  └─ homoglyph              │ homoglyph
  └─ phishing_patterns      │ phishing_patterns
  └─ url_features           │ url_features
  └─ threat_intelligence    │ threat_intel
  └─ url_unshortener        │ url_unshortener
  └─ fast_path (bloom)      │ bloom_filter
gsb                         │ gsb
vt                          │ vt
ai                          │ ai_model
blacklist                   │ blacklist
"""

import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Maps engine key from raw_data['engines'] → EngineHealthLog.ENGINE_CHOICES key
_SUB_ENGINE_MAP: dict[str, str] = {
    "dns":                 "dns",
    "ssl":                 "ssl",
    "domain_age":          "domain_age",
    "typosquatting":       "typosquatting",
    "homoglyph":           "homoglyph",
    "phishing_patterns":   "phishing_patterns",
    "url_features":        "url_features",
    "threat_intelligence": "threat_intel",
    "url_unshortener":     "url_unshortener",
    "fast_path":           "bloom_filter",
    "trusted_source":      "bloom_filter",   # alias used in domain_analyzer
}

# Maps top-level source_type → EngineHealthLog.ENGINE_CHOICES key
_SOURCE_TYPE_MAP: dict[str, str] = {
    "gsb":       "gsb",
    "vt":        "vt",
    "ai":        "ai_model",
    "blacklist": "blacklist",
}

# Valid ENGINE_CHOICES keys (mirrors apps/monitoring/models.py)
_VALID_ENGINE_KEYS = frozenset([
    "gsb", "vt", "domain_age", "typosquatting", "homoglyph",
    "phishing_patterns", "url_features", "dns", "ssl", "threat_intel",
    "url_unshortener", "ai_model", "bloom_filter", "blacklist",
])

# Status constants
_STATUS_OK       = "ok"
_STATUS_ERROR    = "error"
_STATUS_TIMEOUT  = "timeout"
_STATUS_SKIPPED  = "skipped"
_STATUS_DEGRADED = "degraded"


def _resolve_status(engine_result: dict) -> str:
    """Map an engine result dict to an EngineHealthLog status string."""
    status = engine_result.get("status", "")
    if status in ("ok", "safe", "malicious", "suspicious"):
        return _STATUS_OK
    if status == "skipped":
        return _STATUS_SKIPPED
    if status == "error":
        error_msg = str(engine_result.get("error", "")).lower()
        if "timeout" in error_msg or "timed out" in error_msg:
            return _STATUS_TIMEOUT
        return _STATUS_ERROR
    # Fallback: if we have details but no explicit status, treat as degraded
    if engine_result.get("details"):
        return _STATUS_DEGRADED
    return _STATUS_ERROR


def _extract_latency(engine_result: dict, top_level_latency: float = 0.0) -> float:
    """
    Pull latency_ms from engine result.
    Priority:
      1. top_level_latency — set by orchestrator via time.monotonic() (most accurate)
      2. engine_result['details']['latency_ms'] — set by individual engine internals
    """
    if top_level_latency > 0:
        return top_level_latency
    # Check top-level (Standard EngineResult Schema)
    if "latency_ms" in engine_result:
        return float(engine_result["latency_ms"])
    # Fallback to details dict
    details = engine_result.get("details", {})
    if isinstance(details, dict):
        return float(details.get("latency_ms", 0.0))
    return 0.0


def _build_log_entries(sources: list[dict], scan_url: str) -> list:
    """
    Convert the orchestrator's sources list into a list of
    unsaved EngineHealthLog instances ready for bulk_create.

    Handles two tiers:
      Tier 1 — top-level source_type (gsb, vt, ai, blacklist)
      Tier 2 — sub-engines inside raw_data['engines'] (dns, ssl, etc.)
    """
    from apps.monitoring.models import EngineHealthLog

    entries: list[EngineHealthLog] = []
    seen_engines: set[str] = set()   # deduplicate per scan

    for src in sources:
        source_type: str = src.get("source_type", "")
        raw_data: dict  = src.get("raw_data", {})
        verdict: str    = src.get("verdict", "")

        # ── Tier 1: direct source mappings (gsb, vt, ai, blacklist) ────────
        mapped_key = _SOURCE_TYPE_MAP.get(source_type)
        if mapped_key and mapped_key in _VALID_ENGINE_KEYS and mapped_key not in seen_engines:
            if isinstance(raw_data, dict) and "status" in raw_data:
                status = _resolve_status(raw_data)
            else:
                status = _STATUS_OK if verdict not in ("error",) else _STATUS_ERROR
                if verdict == "skipped":
                    status = _STATUS_SKIPPED
            
            confidence = src.get("confidence", 0.0)
            # Degraded: result returned but confidence is very low
            if status == _STATUS_OK and confidence < 0.4:
                status = _STATUS_DEGRADED

            error_msg = ""
            if status == _STATUS_ERROR:
                error_msg = str(raw_data.get("error", "Unknown error"))[:500]

            # Use the orchestrator-measured latency (most accurate)
            top_lat = float(src.get('latency_ms', 0.0))
            entries.append(EngineHealthLog(
                engine_name=mapped_key,
                status=status,
                latency_ms=_extract_latency(raw_data, top_level_latency=top_lat),
                error_message=error_msg,
                scan_url=scan_url[:2000],
            ))
            seen_engines.add(mapped_key)

        # ── Tier 2: sub-engines inside raw_data['engines'] ──────────────────
        sub_engines: dict = raw_data.get("engines", {})
        # The parent source (e.g. domain_analysis) measured its total latency.
        # Use it as the ceiling estimate for sub-engines (they ran in parallel).
        parent_latency = float(src.get("latency_ms", 0.0))

        if isinstance(sub_engines, dict):
            for engine_key, engine_result in sub_engines.items():
                mapped_sub = _SUB_ENGINE_MAP.get(engine_key)
                if not mapped_sub or mapped_sub not in _VALID_ENGINE_KEYS:
                    continue
                if mapped_sub in seen_engines:
                    continue

                if not isinstance(engine_result, dict):
                    continue

                status    = _resolve_status(engine_result)
                # Try to get exact latency from engine detail first, then
                # fall back to the parent's total (parallel execution estimate).
                latency   = _extract_latency(engine_result, top_level_latency=parent_latency)
                error_msg = ""
                if status in (_STATUS_ERROR, _STATUS_TIMEOUT):
                    error_msg = str(engine_result.get("error", ""))[:500]

                entries.append(EngineHealthLog(
                    engine_name=mapped_sub,
                    status=status,
                    latency_ms=latency,
                    error_message=error_msg,
                    scan_url=scan_url[:2000],
                ))
                seen_engines.add(mapped_sub)

    return entries


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class EngineHealthService:
    """
    Singleton-style service (stateless, safe to instantiate anywhere).

    Usage (from scan_orchestrator._finalize):
        EngineHealthService.record(sources=all_sources, scan_url=url)
    """

    @staticmethod
    def record(sources: list[dict], scan_url: str) -> None:
        """
        Persist health logs for every engine that participated in this scan.

        This method is intentionally synchronous and fail-safe.
        It will never raise — any failure is logged as a WARNING.

        Parameters
        ----------
        sources   : list of source dicts as built by ScanOrchestrator
        scan_url  : the original URL being scanned (stored for traceability)
        """
        if not sources:
            return

        try:
            from apps.monitoring.models import EngineHealthLog

            entries = _build_log_entries(sources, scan_url)

            if not entries:
                logger.debug("[EngineHealth] No loggable entries found in sources.")
                return

            EngineHealthLog.objects.bulk_create(entries, ignore_conflicts=True)
            logger.debug(
                "[EngineHealth] Logged %d engine health entries for %s",
                len(entries), scan_url[:80],
            )

        except Exception as exc:
            # CRITICAL: Never let monitoring failure propagate to the scan pipeline
            logger.warning(
                "[EngineHealth] Failed to write health logs (non-fatal): %s",
                exc,
                exc_info=False,
            )

    @staticmethod
    def get_engine_summary(engine_name: str, last_n: int = 100) -> dict:
        """
        Returns a quick health summary for a single engine:
            - uptime_pct   : % of last_n calls that returned 'ok'
            - avg_latency  : average latency in ms across last_n calls
            - error_rate   : % of last_n calls that returned 'error' or 'timeout'

        Used by the admin dashboard and monitoring API endpoints.
        """
        from apps.monitoring.models import EngineHealthLog
        from django.db.models import Avg, Count, Q

        try:
            qs = (
                EngineHealthLog.objects
                .filter(engine_name=engine_name)
                .order_by("-checked_at")[:last_n]
            )
            total = qs.count()
            if total == 0:
                return {"engine": engine_name, "total": 0, "uptime_pct": None,
                        "avg_latency_ms": None, "error_rate": None}

            agg = qs.aggregate(
                ok_count=Count("id", filter=Q(status="ok")),
                avg_lat=Avg("latency_ms"),
                err_count=Count("id", filter=Q(status__in=["error", "timeout"])),
            )

            return {
                "engine":         engine_name,
                "total":          total,
                "uptime_pct":     round((agg["ok_count"] / total) * 100, 1),
                "avg_latency_ms": round(agg["avg_lat"] or 0, 2),
                "error_rate":     round((agg["err_count"] / total) * 100, 1),
            }
        except Exception as exc:
            logger.warning("[EngineHealth] get_engine_summary failed: %s", exc)
            return {"engine": engine_name, "error": str(exc)}

    @staticmethod
    def get_all_engines_summary(last_n: int = 100) -> list[dict]:
        """
        Returns health summaries for all known engines.
        Useful for the admin dashboard overview widget.
        """
        from apps.monitoring.models import EngineHealthLog

        engine_keys = [k for k, _ in EngineHealthLog.ENGINE_CHOICES]
        return [EngineHealthService.get_engine_summary(k, last_n) for k in engine_keys]
