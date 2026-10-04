# services/decision_engine.py
"""
Decision Engine
───────────────
Separates decision logic from orchestration logic.
Calculates early exits, identifies skip conditions (like skipping VT for typosquatting),
and performs the final weighted aggregation.
"""

import logging
from typing import List, Dict, Any, Tuple

logger = logging.getLogger(__name__)


class DecisionEngine:
    
    @staticmethod
    def evaluate_phase1(is_blacklisted: bool, is_whitelisted: bool, phishing_patterns: dict, url_features: dict) -> Tuple[str, int]:
        """
        Evaluates Phase 1 (Heuristic) logic to determine early exit or preliminary score.
        Returns: (decision, preliminary_score)
                 Decision choices: 'BLACKLISTED', 'WHITELISTED_CLEAN', 'NEEDS_ANALYSIS'
        """
        if is_blacklisted:
            return 'BLACKLISTED', 100
            
        has_suspicious = False
        score = 0
        
        # Check patterns
        details = phishing_patterns.get('details', {})
        if details.get('keyword_count', 0) > 0:
            has_suspicious = True
            score += 15 * details.get('keyword_count', 1)
        if details.get('suspicious_tld', False):
            has_suspicious = True
            score += 25
            
        # Check features
        features = url_features.get('details', {})
        if features.get('has_at_symbol', False):
            has_suspicious = True
            score += 40
        if features.get('is_ip', False):
            has_suspicious = True
            score += 35
        if features.get('has_encoded_chars', False):
            score += 10
            
        # Fast exit for known safe domains
        if is_whitelisted and not has_suspicious:
            return 'WHITELISTED_CLEAN', 0
            
        return 'NEEDS_ANALYSIS', score

    @staticmethod
    def should_run_ai(scan_level: str, heuristic_score: int, phase2_results: List[Dict[str, Any]]) -> bool:
        """
        Determines if AI model should be invoked.
        """
        if scan_level in ('standard', 'deep'):
            return True
        if heuristic_score > 30:
            return True
            
        # Also run AI if typo or homoglyph is detected, even in basic
        for res in phase2_results:
            if res['source_type'] == 'engines' and getattr(res, 'engine', '') in ('typosquatting', 'homoglyph'):
                if res['risk_score'] > 50:
                    return True
                    
        return False

    @staticmethod
    def should_run_vt(scan_level: str, heuristic_score: int, phase2_results: List[Dict[str, Any]]) -> bool:
        """
        Determines if VirusTotal should be invoked.
        Crucial insight: VT cannot detect typosquatting/homoglyph effectively,
        so skip VT to avoid wasting quota/latency if we ALREADY know it's a domain spoof.
        """
        if scan_level != 'deep' and heuristic_score < 70:
            return False
            
        # If we already firmly convicted it of typosquatting, skip VT
        for res in phase2_results:
            if res.get('source_type') == 'engines' and res.get('engine') in ('typosquatting', 'homoglyph'):
                if res.get('risk_score', 0) >= 80:
                    return False
                    
        return True

    # ── Critical sources that can hard-override the verdict ──────────────
    # If VirusTotal or GSB says "malicious" with high confidence,
    # the final score CANNOT be diluted below the malicious threshold.
    CRITICAL_SOURCES = frozenset(['vt', 'gsb', 'blacklist'])

    @staticmethod
    def aggregate_score(sources: List[Dict[str, Any]], domain: str = None) -> Tuple[int, str]:
        """
        Calculates final score using explicit component weighting (Enterprise Level).
        Prevents single-source overriding while gracefully handling network instability.
        Also implements a 'Critical Source Floor' to prevent dilution of malicious findings.
        
        v5 Changes:
          - Decision Hierarchy: 'heuristic' is a separate, lower-weight component
          - Open Redirect Trust Override: uses target_domain for trust checks
          - Whitelist Override: fast_path nullifies heuristic noise
        """
        from domain_analysis.services.risk_scoring import RiskScorer
        
        # ── Supported component types (v5: added 'heuristic') ────────────
        component_types = ['engines', 'heuristic', 'ai', 'vt', 'gsb', 'blacklist']
        scores = {k: 0 for k in component_types}
        confidences = {k: 0.0 for k in component_types}
        
        has_network_instability = False
        has_strong_typosquatting = False
        is_vt_clean = False
        was_whitelisted = False
        open_redirect_target_domain = None
        
        # Track strongest critical signal
        max_critical_score = 0
        max_critical_confidence = 0.0

        for src in sources:
            if src.get('verdict') in ('error', 'skipped'):
                continue
                
            src_type = src.get('source_type', 'unknown')
            risk = src.get('risk_score', 0)
            conf = src.get('confidence', 0.5)
            
            if src_type in scores:
                # Use max risk if multiple sources of same type (e.g. multiple engines)
                if risk > scores[src_type]:
                    scores[src_type] = risk
                # v5 FIX: Always keep the highest confidence for this component type.
                # Previously, max() took the risk score's confidence, which could be
                # lower than a safe result's confidence (e.g. heuristic 0.6 vs domain_analysis 0.9).
                confidences[src_type] = max(confidences[src_type], conf)
            
            # Track critical signals (GSB, VT, Blacklist)
            if src_type in DecisionEngine.CRITICAL_SOURCES:
                if risk > max_critical_score:
                    max_critical_score = risk
                    max_critical_confidence = conf
            
            # Extract context from engines
            if src_type == 'engines':
                raw = src.get('raw_data', {})
                eng_details = raw.get('engines', {})
                
                # Check for network instability
                if eng_details.get('dns', {}).get('details', {}).get('resolution_status') == 'timeout':
                    has_network_instability = True
                if eng_details.get('domain_age', {}).get('details', {}).get('network_error'):
                    has_network_instability = True
                    
                # Check for strong typosquatting & homoglyph (safely unwrap from EngineResult)
                typo_res = eng_details.get('typosquatting', {})
                typo_payload = typo_res.get('data') if isinstance(typo_res.get('data'), dict) else typo_res
                typo_details = typo_payload.get('details', {}) if isinstance(typo_payload, dict) else {}
                if typo_details.get('is_typosquatting') or typo_details.get('brand_impersonation'):
                    has_strong_typosquatting = True

                homo_res = eng_details.get('homoglyph', {})
                homo_payload = homo_res.get('data') if isinstance(homo_res.get('data'), dict) else homo_res
                homo_details = homo_payload.get('details', {}) if isinstance(homo_payload, dict) else {}
                if homo_details.get('confusable') or homo_details.get('punycode') or homo_details.get('latin_tricks'):
                    has_strong_typosquatting = True
                
                # v5: Detect whitelisted (fast_path) domains
                if 'fast_path' in eng_details:
                    was_whitelisted = True
                
                # v5: Extract Open Redirect target domain for trust override
                open_redir = eng_details.get('open_redirect', {})
                if open_redir.get('status') == 'ok':
                    redir_details = open_redir.get('details', {})
                    if redir_details.get('is_open_redirect'):
                        open_redirect_target_domain = redir_details.get('target_domain')
                    
            # Check VT clean status
            if src_type == 'vt' and risk == 0 and conf > 0.5:
                is_vt_clean = True
        
        # ── v5: Whitelist Override ────────────────────────────────────────────
        # If domain_analysis confirmed this domain is whitelisted (fast_path)
        # AND no critical source (VT/GSB/Blacklist) flags it, nullify heuristic.
        # Heuristic noise (like Brand Guard false positives on google.de) cannot
        # override a 17M-domain whitelist + 0-risk domain analysis.
        if was_whitelisted and max_critical_score < 50:
            scores['heuristic'] = 0
            confidences['heuristic'] = 0.0
                
        # ── Component Weighting ──────────────────────────────────────────────
        # v5: Added 'heuristic' at 0.30 weight — much lower than 'engines' (0.60)
        # because heuristic checks are surface-level pattern matching, while
        # domain_analysis (engines) uses real network intelligence.
        weights = {
            'blacklist': 0.95,
            'gsb': 0.85,
            'engines': 0.60, 
            'vt': 0.50,
            'ai': 0.40, 
            'heuristic': 0.30,
        }
        
        active_weight_sum = 0.0
        weighted_score = 0.0
        
        # Zero-Day Threat Anti-Dilution:
        # External databases (VT/GSB) only contain KNOWN reported threats.
        # If internal engines firmly detected a threat (score >= 70 or strong impersonation),
        # an absence of hit on VT/GSB (score 0) must NOT dilute the internal finding.
        is_internal_threat = scores['engines'] >= 70 or has_strong_typosquatting

        for key in component_types:
            if confidences[key] > 0:
                eff_weight = weights.get(key, 0.5) * confidences[key]
                if is_internal_threat and key in ('vt', 'gsb') and scores[key] == 0:
                    eff_weight *= 0.15  # Downweight clean status of signature DBs on new attacks
                weighted_score += scores[key] * eff_weight
                active_weight_sum += eff_weight
                
        if active_weight_sum > 0:
            final_score = weighted_score / active_weight_sum
        else:
            final_score = 0.0
            
        # ── Critical Source Floor ───────────────────────────────────────────
        # If a critical source (GSB, Blacklist) is 100% certain it's malicious,
        # do not let other engines dilute it below the malicious threshold.
        if max_critical_score >= 90 and max_critical_confidence >= 0.8:
            final_score = max(final_score, max_critical_score * 0.9) # Ensure it stays malicious
            
        # ── Tiered Trust Reduction (GLOBAL) ──────────────────────────────────
        # v5: When Open Redirect is detected, use the TARGET domain for trust
        # checks instead of the WRAPPER domain. youtube.com's HIGH trust must
        # NOT shield evil-example.com from detection.
        trust_domain = domain
        if open_redirect_target_domain:
            trust_domain = open_redirect_target_domain
            logger.info(f"[TRUST] Open Redirect override: using target domain '{trust_domain}' instead of wrapper '{domain}'")
        
        if trust_domain:
            trust_level = RiskScorer._is_trusted(trust_domain)
            if trust_level and not has_strong_typosquatting and max_critical_score < 70:
                multiplier = 0.3 if trust_level == "HIGH" else 0.6
                
                original_score = final_score
                final_score *= multiplier
                
                # Ceiling for trusted platforms without critical proof
                if trust_level == "MEDIUM":
                    final_score = min(final_score, 59)
                else: # HIGH trust
                    final_score = min(final_score, 35)
                    
                logger.info(f"[TRUST] Reduced score from {original_score:.1f} to {final_score:.1f} for {trust_level} trust domain: {trust_domain}")

        # ── Contextual Adjustments ───────────────────────────────────────────
        
        # Network Instability: Reduces confidence in automated findings
        if has_network_instability and max_critical_score < 70 and not is_internal_threat:
            final_score *= 0.85
            
        # Impersonation: Strong signal that shouldn't be diluted
        if has_strong_typosquatting:
            final_score = max(final_score, 75) # Force dangerous/malicious (threshold >= 60)
            
        # VT Clean: Slightly reduces risk, but ONLY when engines don't have
        # a strong conviction. VT "clean" on an unknown URL just means
        # "not in our database", not "verified safe".
        if is_vt_clean and max_critical_score < 70 and scores['engines'] < 50:
            final_score -= 10
        
        # ── Engine Conviction Floor (FINAL SAFETY NET) ────────────────────
        # Must be applied AFTER all adjustments to ensure a concrete engine
        # finding can never be diluted below the malicious threshold.
        if scores['engines'] >= 70 and confidences['engines'] >= 0.7:
            floor = 70
            if final_score < floor:
                logger.info(
                    f"[CONVICTION] Engine Conviction Floor: "
                    f"engines={scores['engines']} (conf={confidences['engines']:.1f}) "
                    f"→ floor score from {final_score:.1f} to {floor}"
                )
                final_score = floor
        elif scores['engines'] >= 50 and confidences['engines'] >= 0.7:
            floor = 45
            if final_score < floor:
                final_score = floor
            
        final_score = min(100, max(0, int(round(final_score))))
        
        # ── Verdict Logic ────────────────────────────────────────────────────
        if final_score >= 60:
            verdict = 'malicious'
        elif final_score >= 25:
            verdict = 'suspicious'
        else:
            verdict = 'safe'
            
        return final_score, verdict
