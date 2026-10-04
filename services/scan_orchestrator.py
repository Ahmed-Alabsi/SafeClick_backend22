# services/scan_orchestrator.py
"""
Scan Orchestrator — SafeClick v2.0
──────────────────────────────────
Central coordinator for the multi-layer scanning architecture.

Architecture:
  Phase 1: Local Heuristics (< 50ms) -> Early exit if possible
  Phase 2: Fast Intelligence (< 3s) -> GSB, Typosquatting, Homoglyph
  Phase 3: AI Model -> Runs if heuristic score > threshold
  Phase 4: Deep Analysis (< 12s) -> VT, DNS, SSL (if deep scan requested)
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from django.db import models
from django.core.cache import cache
from django.utils import timezone

from apps.scans.models import Scan, ScanSourceResult, ScanCache, Blacklist
from apps.monitoring.services import EngineHealthService
from domain_analysis.services.domain_analyzer import analyze_domain
from domain_analysis.services.bloom_filter import is_legit_domain
from domain_analysis.services.domain_utils import extract_domain
from domain_analysis.services.gsb_engine import check_gsb_threat
from domain_analysis.services.async_utils import run_async
from domain_analysis.services.typosquatting_engine import _normalize_domain, BRAND_REAL_DOMAINS
from domain_analysis.services.constants import SENSITIVE_BRANDS
from apps.ai.services.feature_extractor import FeatureExtractor
from apps.ai.services.model_service import ModelService
from services.decision_engine import DecisionEngine

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    # Tunable weights matching Google Safe Systems logic
    SOURCE_WEIGHTS = {
        'blacklist': 0.95,
        'gsb': 0.75,
        'vt': 0.85,
        'engines': 0.80,
        'ai': 0.70,
        'heuristic': 0.50,
    }

    def __init__(self, request_user=None, guest_id=None):
        self.user = request_user
        self.guest_id = guest_id
        self.decision_engine = DecisionEngine()
        self.feature_extractor = FeatureExtractor()
        self.model_service = ModelService()
        self.executor = ThreadPoolExecutor(max_workers=6)

    def scan(self, url: str, scan_level: str = 'basic', ignore_cache: bool = False) -> dict:
        """Main entry point for scanning a URL."""
        import hashlib
        url_hash = hashlib.sha256(url.encode('utf-8')).hexdigest()
        
        # Initialize primary scan record immediately to ensure history is logged
        scan_record = Scan.objects.create(
            url=url,
            url_hash=url_hash,
            domain_name=extract_domain(url),
            scan_level=scan_level,
            user=self.user,
            guest_id=self.guest_id
        )

        domain = extract_domain(url)
        fqdn = urlparse(url).netloc
        domains_to_check = [domain]
        if fqdn and fqdn != domain:
            domains_to_check.append(fqdn)

        # ── 0. Strict Blacklist Priority Check (Blacklist ALWAYS overrides Cache) ──
        active_blacklist = Blacklist.objects.filter(
            domain__in=domains_to_check, is_active=True
        ).filter(
            models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=timezone.now())
        ).first()

        if active_blacklist:
            logger.warning(f"[BLACKLIST] Instant block: {domain} is blacklisted (Active blacklist overrides any cache).")
            # Invalidate any stale cache entries for this URL
            ScanCache.objects.filter(url_hash=url_hash).delete()
            all_sources = [{
                'source_type': 'blacklist',
                'verdict': 'malicious',
                'risk_score': 100,
                'weight': self.SOURCE_WEIGHTS['blacklist'],
                'confidence': 1.0,
                'raw_data': {
                    'threat_type': active_blacklist.threat_type,
                    'severity': active_blacklist.severity,
                    'description': active_blacklist.description
                }
            }]
            return self._finalize(scan_record, 100, 'malicious', all_sources)

        # ── 1. Priority Cache Check (Only for non-blacklisted URLs) ─────────
        if not ignore_cache:
            cached = self._check_cache_priority(url, url_hash, scan_level)
            if cached:
                # Update scan record with cached result
                scan_record.final_verdict = cached.get('result')
                scan_record.risk_score = cached.get('risk_score', 0)
                scan_record.scan_scenario = cached.get('scan_scenario', '')
                scan_record.reason = cached.get('reason', '')
                scan_record.details = cached.get('detailed_report', '')
                
                # Legacy compatibility fields (for Flutter frontend)
                scan_record.score = cached.get('risk_score', 0)
                scan_record.result = cached.get('result')
                scan_record.safe = (cached.get('result') == 'safe')
                scan_record.save()
                
                cached['id'] = scan_record.id
                return cached
        else:
            logger.info(f"[CACHE] Bypassing cache for URL: {url}")

        all_sources = []
        
        # ── Phase 1: Heuristics ─────────────────────────────────────────
        phase1 = self._phase1_heuristic(url)
        all_sources.extend(phase1['sources'])
        
        decision = phase1['decision']
        heuristic_score = phase1['preliminary_score']

        if decision == 'BLACKLISTED':
            return self._finalize(scan_record, 100, 'malicious', all_sources)
            
        if decision == 'WHITELISTED_CLEAN':
            # Whitelisted + No bad patterns
            # Note: We NO LONGER skip basic scans here! 
            # We defer to the domain_analyzer's fast path or lite_mode to ensure safety checks run.
            pass

        # Phase 2: Fast Intelligence (< 3s for deep, <0.1s for basic)
        lite_mode = scan_level == 'basic'
        phase2_sources = self._phase2_intelligence(url, ignore_cache=ignore_cache, lite_mode=lite_mode)
        all_sources.extend(phase2_sources)
        
        # Helper to get the raw domain analysis for Phase 3
        domain_intel = next((s['raw_data'] for s in phase2_sources if s['engine'] == 'domain_analysis'), None)

        # ── Phase 3: AI Model ───────────────────────────────────────────
        if self.decision_engine.should_run_ai(scan_level, heuristic_score, phase2_sources):
            ai_sources = self._phase3_ai(url, scan_record, domain_analysis=domain_intel)
            all_sources.extend(ai_sources)

        # ── Phase 4: Deep Analysis ──────────────────────────────────────
        was_whitelisted = False
        if domain_intel:
            was_whitelisted = 'fast_path' in domain_intel.get('engines', {})

        if self.decision_engine.should_run_vt(scan_level, heuristic_score, phase2_sources):
            deep_sources = self._phase4_deep(url, scan_level, was_whitelisted=was_whitelisted)
            all_sources.extend(deep_sources)
            
        # ── Aggregation & Finalize ──────────────────────────────────────
        final_score, verdict = self.decision_engine.aggregate_score(all_sources, domain=domain)
        return self._finalize(scan_record, final_score, verdict, all_sources)

    def _check_cache_priority(self, url: str, url_hash: str, requested_level: str) -> dict:
        """
        Implements Cache Priority logic (deep > standard > basic).
        If requesting a basic scan but a deep scan is cached, return it.
        """
        levels_to_check = ['deep', 'standard', 'basic']
        
        # If requesting basic, check deep, standard, basic
        # If requesting standard, check deep, standard
        # If requesting deep, check deep ONLY
        start_idx = levels_to_check.index(requested_level)
        valid_levels = levels_to_check[:start_idx + 1]

        for level in valid_levels:
            # Check DB Cache (L2)
            try:
                db_cache = ScanCache.objects.get(
                    url_hash=url_hash, 
                    scan_level=level,
                    expires_at__gt=timezone.now()
                )
                logger.info(f"Priority cache HIT: requested {requested_level}, found {level}")
                return {
                    'url': url,
                    'result': db_cache.result,
                    'risk_score': db_cache.risk_score,
                    'sources': db_cache.source_results,
                    'cached': True,
                    'scan_level_used': level,
                    'scan_scenario': db_cache.scan_scenario,
                    'reason': db_cache.reason,
                    'detailed_report': db_cache.source_results # or reconstruction
                }
            except ScanCache.DoesNotExist:
                continue
                
        return None

    # Phishing keywords that amplify risk when combined with impersonation
    PHISHING_KEYWORDS = frozenset([
        'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification',
        'confirm', 'secure', 'security', 'account', 'update', 'suspend',
        'unlock', 'restore', 'recovery', 'password', 'credential',
        'billing', 'payment', 'invoice', 'support', 'helpdesk',
        'malware', 'phishing', 'gift', 'bonus', 'claim', 'win', 'prize',
    ])

    def _phase1_heuristic(self, url: str) -> dict:
        """CPU-based checks. Extremely fast."""
        from apps.scans.models import WhitelistEntry
        
        domain = extract_domain(url)
        sources = []
        
        # 1. Blacklist O(1)
        fqdn = urlparse(url).netloc
        domains_to_check = [domain]
        if fqdn and fqdn != domain:
            domains_to_check.append(fqdn)
            
        if Blacklist.objects.filter(domain__in=domains_to_check, is_active=True).filter(
            models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=timezone.now())
        ).exists():
            sources.append({
                'source_type': 'blacklist',
                'verdict': 'malicious',
                'risk_score': 100,
                'weight': self.SOURCE_WEIGHTS['blacklist'],
                'confidence': 1.0,
            })
            return {'decision': 'BLACKLISTED', 'sources': sources, 'preliminary_score': 100}

        # 2. Bloom Filter O(1) — 17M static domains
        is_safe = is_legit_domain(domain)
        
        # 3. DB Whitelist check — admin-managed dynamic whitelist
        if not is_safe:
            from django.utils import timezone as tz
            is_db_whitelisted = WhitelistEntry.objects.filter(
                domain__in=domains_to_check, is_active=True
            ).filter(
                models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=tz.now())
            ).exists()
            if is_db_whitelisted:
                is_safe = True
                logger.info(f"[WHITELIST_DB] Domain {domain} or {fqdn} found in admin whitelist")
        
        # Real URL pattern analysis instead of mock check
        url_lower = url.lower()
        suspicious_keyword_count = sum(1 for kw in self.PHISHING_KEYWORDS if kw in url_lower)
        has_at_symbol = '@' in url
        has_ip = bool(extract_domain(url) and extract_domain(url).replace('.', '').isdigit())
            
        decision, score = self.decision_engine.evaluate_phase1(
            False, is_safe, 
            {'details': {'keyword_count': suspicious_keyword_count}},
            {'details': {'has_at_symbol': has_at_symbol, 'is_ip': has_ip}}
        )
        
        # ── Brand Proximity Guard (v5.1) ───────────────────────────────
        # Even if bloom filter says "legit", verify the domain isn't a
        # character-manipulation variant of a sensitive brand.
        # This defeats bloom filter poisoning attacks.
        #
        # v5.1 FIX: If the domain is ALREADY in the Bloom Filter whitelist
        # (is_safe=True), trust it. The 17M-domain whitelist is far more
        # authoritative than the ~100-entry BRAND_REAL_DOMAINS list.
        # This prevents false positives on regional domains like google.de.
        if decision == 'WHITELISTED_CLEAN':
            normalized = _normalize_domain(domain)
            for brand in SENSITIVE_BRANDS:
                if normalized == _normalize_domain(brand):
                    real_domains = BRAND_REAL_DOMAINS.get(brand, set())
                    if domain not in real_domains and not is_safe:
                        logger.warning(
                            f"[BRAND GUARD] Bloom filter override: {domain} → "
                            f"normalizes to '{brand}' but is NOT real domain. "
                            f"Forcing full analysis."
                        )
                        decision = 'NEEDS_ANALYSIS'
                        score = max(score, 40)  # Floor at suspicious level
                        break
        
        # Only add heuristic source if it has a meaningful score.
        # Zero-score sources dilute Phase 2 signals via weighted averaging.
        if score > 0:
            sources.append({
                'source_type': 'heuristic',
                'engine': 'heuristic',
                'verdict': 'suspicious' if score > 30 else 'safe',
                'risk_score': score,
                'weight': self.SOURCE_WEIGHTS['heuristic'],
                'confidence': 0.6,
            })
        
        return {
            'decision': decision,
            'sources': sources,
            'preliminary_score': score
        }

    def _phase2_intelligence(self, url: str, ignore_cache: bool = False, lite_mode: bool = False) -> list:
        """GSB + Engine Analysis"""
        domain = extract_domain(url)
        sources = []
        
        try:
            # Use persistent background loop instead of asyncio.run()
            # to prevent 'Event loop is closed' errors on subsequent scans
            analysis = run_async(analyze_domain(url, use_cache=not ignore_cache, lite_mode=lite_mode))
            risk_score = analysis.get('risk_score', 0)
            
            # Determine verdict from domain_analysis
            if risk_score >= 50:
                verdict = 'malicious'
            elif risk_score > 20:
                verdict = 'suspicious'
            else:
                verdict = 'safe'
            
            # Check if domain was explicitly whitelisted (fast-pathed)
            engines = analysis.get('engines', {})
            was_whitelisted = 'fast_path' in engines
            
            # ── Compound Threat Escalation ────────────────────────────────
            # If typosquatting/homoglyph is detected AND the URL contains
            # phishing keywords, this is almost certainly a phishing attack.
            # Floor the score at 70 (malicious threshold).
            is_impersonation = False
            typo_result = engines.get('typosquatting', {})
            homo_result = engines.get('homoglyph', {})
            
            if typo_result.get('status') == 'ok':
                typo_data = typo_result.get('data', {})
                typo_details = typo_data.get('details', {})
                if typo_details.get('is_typosquatting') or typo_details.get('brand_impersonation'):
                    is_impersonation = True
            
            if homo_result.get('status') == 'ok':
                homo_data = homo_result.get('data', {})
                homo_details = homo_data.get('details', {})
                if homo_details.get('punycode') or homo_details.get('confusable'):
                    is_impersonation = True
            
            if is_impersonation:
                url_lower = url.lower()
                phishing_kw_hits = sum(1 for kw in self.PHISHING_KEYWORDS if kw in url_lower)
                if phishing_kw_hits > 0:
                    # Impersonation + phishing keywords = certain phishing attack
                    escalated_score = max(risk_score, 70 + min(phishing_kw_hits * 5, 20))
                    logger.info(f"[COMPOUND THREAT] Impersonation + {phishing_kw_hits} phishing keywords → score escalated {risk_score} → {escalated_score}")
                    risk_score = escalated_score
                    verdict = 'malicious'
                elif risk_score < 50:
                    # Impersonation alone without keywords: ensure at least suspicious
                    risk_score = max(risk_score, 50)
                    verdict = 'malicious' if risk_score >= 50 else 'suspicious'
            
            # ALWAYS include domain_analysis, even when safe.
            # This provides critical counter-evidence against VT false positives
            # on whitelisted domains like youtube.com, google.com, etc.
            sources.append({
                'source_type': 'engines',
                'engine': 'domain_analysis',
                'verdict': verdict,
                'risk_score': risk_score,
                'weight': self.SOURCE_WEIGHTS['engines'],
                'confidence': 0.9 if was_whitelisted else 0.8,
                'raw_data': analysis
            })
        except Exception as e:
            logger.error(f"Phase 2 engines failed: {e}", exc_info=True)
            
        # ── Standalone Google Safe Browsing ──────────────────────────
        try:
            gsb_res = run_async(check_gsb_threat(url))
            gsb_status = gsb_res.get("status", "unknown")
            gsb_data = gsb_res.get("data", {})
            gsb_verdict = gsb_data.get("status", "safe") if isinstance(gsb_data, dict) else "safe"
            if gsb_status != 'unknown':
                sources.append({
                    'source_type': 'gsb',
                    'engine': 'gsb_standalone',
                    'verdict': gsb_verdict,
                    'risk_score': 100 if gsb_verdict == 'malicious' else 0,
                    'weight': self.SOURCE_WEIGHTS['gsb'],
                    'confidence': 0.9,
                    'latency_ms': gsb_res.get("latency_ms", 0.0),
                    'raw_data': gsb_res
                })
        except Exception as e:
            logger.error(f"GSB standalone lookup failed: {e}")

        return sources

    def _phase3_ai(self, url: str, scan_record: Scan, domain_analysis: dict = None) -> list:
        """Call ML Model."""
        # 1. Extract features (25 features v1)
        features_payload = self.feature_extractor.extract(url, domain_analysis=domain_analysis)
        
        # 2. Get prediction & Record in DB for feedback loop
        prediction = self.model_service.predict(scan_record, features_payload)
        
        status = prediction.get("status", "ok")
        if status == "disabled":
            # Engine is disabled (e.g. model deleted from DB), skip entirely
            return []
            
        data = prediction.get("data", {})
        
        return [{
            'source_type': 'ai',
            'verdict': data.get('verdict', 'safe'),
            'risk_score': data.get('score', 0),
            'weight': self.SOURCE_WEIGHTS['ai'],
            'confidence': data.get('confidence', 0.5),
            'latency_ms': prediction.get("latency_ms", 0.0),
            'raw_data': prediction
        }]

    def _phase4_deep(self, url: str, scan_level: str, was_whitelisted: bool = False) -> list:
        """VirusTotal and heavy network checks."""
        if scan_level != 'deep':
            return []
            
        # Call VT logic
        from apps.scans.threat_detection import ThreatDetector
        
        detector = ThreatDetector()
        vt_engine_result = detector.detect(url, scan_level='deep')
        vt_data = vt_engine_result.get("data") if isinstance(vt_engine_result, dict) and isinstance(vt_engine_result.get("data"), dict) else vt_engine_result
        if not isinstance(vt_data, dict):
            vt_data = {}

        # Extract findings from the actual detection payload
        vt_internal_score = vt_data.get('score', 100)
        threats = vt_data.get('threats_found', [])
        scan_failed = vt_data.get('scan_failed', False) or vt_engine_result.get("status") in ("error", "timeout")
        is_inconclusive = vt_data.get('final_status') in ('غير محدد', 'غير مؤكد', 'فشل الفحص')
        
        # If scan failed or inconclusive, return 'error' verdict so it doesn't dilute other threat findings
        if scan_failed or is_inconclusive:
            return [{
                'source_type': 'vt',
                'verdict': 'error',
                'risk_score': 0,
                'weight': self.SOURCE_WEIGHTS['vt'],
                'confidence': 0.0,  # Zero confidence: cannot be used for scoring
                'latency_ms': vt_engine_result.get("latency_ms", 0.0),
                'raw_data': vt_engine_result
            }]
        
        # No threats found → safe with high confidence
        if not threats:
            return [{
                'source_type': 'vt',
                'verdict': 'safe',
                'risk_score': 0,
                'weight': self.SOURCE_WEIGHTS['vt'],
                'confidence': 0.85,
                'latency_ms': vt_engine_result.get("latency_ms", 0.0),
                'raw_data': vt_engine_result
            }]
        
        # Threats found: determine severity from actual VT data
        # Parse the malicious count from the detail strings
        malicious_count = 0
        for detail in vt_data.get('details', []):
            if isinstance(detail, str) and 'محرك رصد' in detail:
                # Extract number: "⚠️ VirusTotal: X محرك رصد تهديداً (Y)"
                try:
                    parts = detail.split(':')
                    if len(parts) >= 2:
                        num_str = parts[-1].strip().split(' ')[0]
                        malicious_count = int(num_str)
                except (ValueError, IndexError):
                    malicious_count = 1
        
        # If we couldn't parse count, assume at least 1
        if malicious_count == 0:
            malicious_count = 1
        
        # ── Context-Aware VT Scoring ─────────────────────────────
        # For WHITELISTED domains (google.com, youtube.com):
        #   1-4 engines  → noise/false positive (common)
        #   5+ engines   → suspicious/malicious
        # For UNKNOWN domains (phishing samples, new sites):
        #   1 engine     → suspicious (don't ignore even 1 hit!)
        #   2+ engines   → malicious
        
        if was_whitelisted:
            if malicious_count <= 10:
                verdict = 'safe'
                risk_score = malicious_count  # 0-10
                confidence = 0.6
            elif malicious_count <= 20:
                verdict = 'suspicious'
                risk_score = 40 + (malicious_count - 10) * 3  # 40-70
                confidence = 0.8
            else:
                verdict = 'malicious'
                risk_score = 80 + min(20, malicious_count) # 80-100
                confidence = 0.95
        else:
            # UNKNOWN DOMAIN - BE STRICT
            if malicious_count <= 1:
                verdict = 'suspicious' # Even 1 hit on unknown = suspicious
                risk_score = 30
                confidence = 0.6
            elif malicious_count <= 4:
                verdict = 'malicious' # 2-4 hits on unknown = malicious
                risk_score = 70
                confidence = 0.8
            else:
                verdict = 'malicious'
                risk_score = 85 + min(15, malicious_count) # 85-100
                confidence = 0.98
        
        return [{
            'source_type': 'vt',
            'verdict': verdict,
            'risk_score': min(100, risk_score),
            'weight': self.SOURCE_WEIGHTS['vt'],
            'confidence': confidence,
            'malicious_engine_count': malicious_count,
            'was_whitelisted': was_whitelisted,
            'latency_ms': vt_engine_result.get("latency_ms", 0.0),
            'raw_data': vt_engine_result
        }]

    def _finalize(self, scan_record: Scan, score: int, verdict: str, sources: list) -> dict:
        """Save results to DB and Cache, and update Domain Intelligence."""
        from services.scenario_engine import generate_scenario_summary, generate_final_reason
        
        # ── Scenario Engine Integration ──────────────────────────────────
        scan_scenario = generate_scenario_summary(scan_record.scan_level, sources)
        final_reason = generate_final_reason(scan_record.scan_level, verdict, sources)
        
        # ── Domain Intelligence Pipeline ─────────────────────────────────
        # Persist engine results (SSL, DNS, Age) into the Domain table for
        # knowledge accumulation and admin dashboard visibility.
        domain_name = extract_domain(scan_record.url)
        domain_obj = None
        if domain_name:
            try:
                domain_obj = self._update_domain_intelligence(domain_name, verdict, sources)
            except Exception as e:
                logger.warning(f"[DOMAIN_INTEL] Failed to update domain intelligence: {e}")
        
        scan_record.risk_score = score
        scan_record.final_verdict = verdict
        scan_record.scan_scenario = scan_record.scan_level.capitalize()
        scan_record.reason = final_reason
        scan_record.details = scan_scenario # Store the human-readable report in details
        scan_record.domain_name = domain_name or ''
        if domain_obj:
            scan_record.domain = domain_obj
        
        # Legacy compatibility fields (for Flutter frontend)
        scan_record.score = score
        scan_record.result = 'dangerous' if verdict == 'malicious' else verdict
        scan_record.safe = (verdict == 'safe')
        
        scan_record.save()
        
        # Save source results
        src_objects = []
        for src in sources:
            src_objects.append(ScanSourceResult(
                scan=scan_record,
                source_type=src['source_type'],
                verdict=src.get('verdict', 'unknown'),
                risk_score=src.get('risk_score', 0),
                confidence=src.get('confidence', 0.5),
                source_weight=src.get('weight', 0.8),
                raw_data=src.get('raw_data', {})
            ))
        ScanSourceResult.objects.bulk_create(src_objects, ignore_conflicts=True)
        
        # Save L2 DB Cache
        from datetime import timedelta
        ttl = 300 if verdict == 'malicious' else 3600
        ScanCache.objects.update_or_create(
            url_hash=scan_record.url_hash,
            scan_level=scan_record.scan_level,
            defaults={
                'url': scan_record.url,
                'result': 'dangerous' if verdict == 'malicious' else verdict,
                'threat_level': verdict,
                'risk_score': score,
                'scan_scenario': scan_record.scan_level.capitalize(),
                'reason': final_reason,
                'source_results': sources,
                'expires_at': timezone.now() + timedelta(seconds=ttl)
            }
        )
        
        # ── Engine Health Monitoring ─────────────────────────────────────────
        # Non-blocking: failure here NEVER aborts the scan result.
        EngineHealthService.record(sources=sources, scan_url=scan_record.url)

        return {
            'id': str(scan_record.id),
            'url': scan_record.url,
            'result': 'dangerous' if verdict == 'malicious' else verdict, # flutter compat
            'risk_score': score,
            'sources': sources,
            'cached': False,
            'scan_level_used': scan_record.scan_level,
            'scan_scenario': scan_record.scan_scenario,
            'reason': final_reason,
            'detailed_report': scan_scenario
        }

    def _update_domain_intelligence(self, domain_name: str, verdict: str, sources: list):
        """
        Persist engine intelligence into the Domain table for reuse.
        
        This is the core of the Knowledge Accumulation Pipeline:
        - SSL, DNS, Domain Age results are extracted from raw_data and saved
          as structured fields in the Domain model.
        - total_scans and threat_detections counters are incremented.
        - threat_ratio is recalculated for admin dashboard visibility.
        
        Returns the Domain object for FK linkage to the Scan record.
        """
        from apps.domains.models import Domain

        domain_obj, created = Domain.objects.get_or_create(domain=domain_name)

        # ── Update scan statistics ───────────────────────────────────────
        domain_obj.total_scans = (domain_obj.total_scans or 0) + 1
        if verdict in ('suspicious', 'malicious'):
            domain_obj.threat_detections = (domain_obj.threat_detections or 0) + 1
        domain_obj.update_threat_ratio()

        # ── Extract engine results from domain_analysis raw_data ─────────
        engine_src = next(
            (s for s in sources if s.get('engine') == 'domain_analysis'), None
        )
        if engine_src:
            raw = engine_src.get('raw_data', {})
            engines = raw.get('engines', {})

            # SSL Intelligence
            ssl_engine = engines.get('ssl', {})
            if ssl_engine.get('status') == 'ok':
                ssl_data = ssl_engine.get('details', {})
                domain_obj.has_ssl = ssl_data.get('has_ssl', False)
                issuer = ssl_data.get('issuer')
                if issuer:
                    domain_obj.ssl_issuer = str(issuer)[:255]
                domain_obj.ssl_is_self_signed = ssl_data.get('is_self_signed', False)
                domain_obj.ssl_is_expired = ssl_data.get('is_expired', False)
                domain_obj.ssl_expiry_days = ssl_data.get('days_until_expiry')

            # DNS Intelligence
            dns_engine = engines.get('dns', {})
            if dns_engine.get('status') == 'ok':
                dns_data = dns_engine.get('details', {})
                domain_obj.dns_resolves = dns_data.get('resolves', False)
                domain_obj.dns_has_mx = dns_data.get('has_mx', False)
                domain_obj.dns_has_ns = dns_data.get('has_ns', False)
                domain_obj.dns_abnormal_config = dns_data.get('abnormal_config', False)

            # Domain Age (RDAP/WHOIS)
            age_engine = engines.get('domain_age', {})
            if age_engine.get('status') == 'ok':
                age_data = age_engine.get('details', {})
                age_days = age_data.get('age_days')
                if age_days is not None:
                    domain_obj.age_days = age_days
                reg_date = age_data.get('registration_date')
                if reg_date:
                    try:
                        from django.utils.dateparse import parse_datetime
                        parsed = parse_datetime(str(reg_date))
                        if parsed:
                            domain_obj.registration_date = parsed
                    except (ValueError, TypeError):
                        pass

        domain_obj.save()

        if created:
            logger.info(f"[DOMAIN_INTEL] New domain registered: {domain_name}")

        return domain_obj

