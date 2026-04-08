"""
Risk Scoring Engine
───────────────────
Calculates a weighted risk score from all engine outputs and assigns a verdict.

Weight Distribution (Professional Grade):
    - threat_intel:   25% — blacklist match is the strongest single signal
    - typosquatting:  20% — visual deception is a top phishing technique
    - patterns:       20% — keyword/URL structure analysis
    - homoglyph:      10% — Unicode-based attacks
    - domain_age:     10% — newly registered domains correlate with phishing
    - dns:             5% — DNS anomalies are a supporting signal
    - ssl:             5% — SSL issues are a supporting signal
    - url_shortener:   5% — shortened URLs add obfuscation risk
    Total:           100%
"""

import enum
from typing import Dict, Any


class Verdict(str, enum.Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class RiskScorer:
    """
    Handles risk score calculation using weighted internal engines.
    """

    @classmethod
    def calculate(cls, engine_results: Dict[str, Any]) -> Dict[str, Any]:
        # Component scores (0-100 each, negative values allowed for safe signals)
        components = {
            "threat_intel": 0,
            "typosquatting": 0,
            "patterns": 0,
            "homoglyph": 0,
            "domain_age": 0,
            "dns": 0,
            "ssl": 0,
            "url_shortener": 0,
        }

        # ─── 1. Threat Intelligence (Immediate Override) ───────────────────
        threat = engine_results.get("threat_intelligence", {})
        threat_is_blacklisted = False
        if threat.get("status") == "ok":
            if threat.get("details", {}).get("blacklisted"):
                components["threat_intel"] = 100
                threat_is_blacklisted = True
        elif threat.get("status") == "unavailable":
            components["threat_intel"] = 0

        # ─── 2. Typosquatting (20%) ────────────────────────────────────────
        typo = engine_results.get("typosquatting", {})
        if typo.get("status") == "ok":
            details = typo.get("details", {})
            if details.get("is_typosquatting"):
                components["typosquatting"] = 90
            elif details.get("is_subdomain_spoof"):
                components["typosquatting"] = 80

        # ─── 3. Homoglyphs (10%) ──────────────────────────────────────────
        homoglyph = engine_results.get("homoglyph", {})
        if homoglyph.get("status") == "ok":
            details = homoglyph.get("details", {})
            h_score = max([
                85 if details.get("punycode") else 0,
                65 if details.get("mixed_script") else 0,
                90 if details.get("confusable") else 0,
                75 if details.get("latin_tricks") else 0,
                0
            ])
            components["homoglyph"] = min(100, h_score)

        # ─── 4. Phishing Patterns (Keywords + URL Features) (20%) ──────────
        phish = engine_results.get("phishing_patterns", {})
        if phish.get("status") == "ok":
            phish_details = phish.get("details", {})
            kw_count = phish_details.get("keyword_count", 0)
            if kw_count > 0:
                # 1 keyword = 25, 2 = 50, 3+ = 75
                components["patterns"] = min(100, kw_count * 25)
            # Compound patterns are high-confidence (e.g., "secure-login")
            compound_count = len(phish_details.get("compound_patterns", []))
            if compound_count > 0:
                components["patterns"] = min(100, components.get("patterns", 0) + compound_count * 40)
            # Suspicious TLDs add risk
            if phish_details.get("suspicious_tld"):
                components["patterns"] = min(100, components.get("patterns", 0) + 25)

        # URL Structure features
        url_feat = engine_results.get("url_features", {})
        if url_feat.get("status") == "ok":
            feat_details = url_feat.get("details", {})
            if feat_details.get("is_ip"):
                components["patterns"] = max(components.get("patterns", 0), 85)
            if feat_details.get("subdomain_count", 0) > 2:
                components["patterns"] = min(100, components.get("patterns", 0) + 35)
            if feat_details.get("has_encoded_chars") or feat_details.get("has_at_symbol"):
                components["patterns"] = min(100, components.get("patterns", 0) + 40)

        # ─── 5. Domain Age (10%) ──────────────────────────────────────────
        age = engine_results.get("domain_age", {})
        if age.get("status") == "ok":
            age_days = age.get("details", {}).get("age_days", 999)
            if age_days < 7:
                components["domain_age"] = 100
            elif age_days < 30:
                components["domain_age"] = 70
            elif age_days < 90:
                components["domain_age"] = 40
            elif age_days > 1095:
                components["domain_age"] = -15  # Strong safe signal
        elif age.get("status") in ["unknown", "error"]:
            components["domain_age"] = 70

        # ─── 6. DNS Intelligence (5%) ────────────────────────────────────
        dns = engine_results.get("dns", {})
        if dns.get("status") == "ok":
            details = dns.get("details", {})
            d_score = 0
            if not details.get("resolves"):
                d_score += 80
            if details.get("abnormal_config"):
                d_score += 30
            components["dns"] = min(100, d_score)
        elif dns.get("status") in ["unknown", "error"]:
            components["dns"] = 60

        # ─── 7. SSL Intelligence (5%) ────────────────────────────────────
        ssl_result = engine_results.get("ssl", {})
        if ssl_result.get("status") == "ok":
            details = ssl_result.get("details", {})
            s_score = 0
            if not details.get("has_ssl"):
                s_score += 30
            if details.get("is_self_signed"):
                s_score += 50
            if details.get("is_expired"):
                s_score += 50
            if (not details.get("is_self_signed") and
                not details.get("is_expired") and
                details.get("has_ssl")):
                s_score -= 40  # Strong safe signal
            components["ssl"] = min(100, max(-40, s_score))
        elif ssl_result.get("status") in ["unknown", "error"]:
            components["ssl"] = 50

        # ─── 8. URL Shortener (5%) ───────────────────────────────────────
        unshortener = engine_results.get("url_unshortener", {})
        if unshortener and unshortener.get("status") == "ok":
            details = unshortener.get("details", {})
            if details.get("was_shortened"):
                hop_count = details.get("hop_count", 0)
                # Shortened URL = minor risk signal (30 base + 5 per extra hop)
                components["url_shortener"] = min(80, 30 + (hop_count - 1) * 5)

        # ─── Weighted Score Calculation ──────────────────────────────────
        weights = {
            "threat_intel": 0.25,
            "typosquatting": 0.20,
            "patterns": 0.20,
            "homoglyph": 0.10,
            "domain_age": 0.10,
            "dns": 0.05,
            "ssl": 0.05,
            "url_shortener": 0.05,
        }
        weighted_score = sum(components.get(k, 0) * w for k, w in weights.items())

        # Risk Amplification: shift borderline scores into detection range
        if weighted_score >= 15:
            weighted_score *= 1.6

        final_score = min(100, round(weighted_score))

        # ─── Verdict Thresholds ──────────────────────────────────────────
        # 50+ = MALICIOUS (High confidence phishing/threat)
        # 20-49 = SUSPICIOUS (Manual review or warn user)
        # 0-19 = SAFE
        verdict = Verdict.SAFE

        if threat_is_blacklisted or final_score >= 50:
            verdict = Verdict.MALICIOUS
            if threat_is_blacklisted:
                final_score = max(final_score, 100)
        elif final_score >= 20:
            verdict = Verdict.SUSPICIOUS

        return {
            "risk_score": final_score,
            "verdict": verdict.value,
            "raw_score": weighted_score,
            "component_scores": components
        }
