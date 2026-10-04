"""
Risk Scoring Engine (v4 - Production Grade)
──────────────────────────────────────────
Implements a weighted, resilient risk calculation with Tiered Trust
and Critical Engine Overrides.
"""

import enum
import math
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class Verdict(str, enum.Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"

# --- Configuration ---
CRITICAL_ENGINES = {"threat_intel", "dns"}

ENGINE_WEIGHTS = {
    "threat_intel": 2.0,
    "dns": 1.5,
    "typosquatting": 1.5,
    "open_redirect": 1.3,
    "patterns": 1.2,
    "homoglyph": 1.0,
    "domain_age": 1.0,
    "ssl": 1.0,
    "url_features": 0.8,
    "url_shortener": 0.5
}

TRUST_HIERARCHY = {
    # Big Tech
    "google.com": "HIGH", "youtube.com": "HIGH", "microsoft.com": "HIGH",
    "apple.com": "HIGH", "amazon.com": "HIGH", "meta.com": "HIGH",
    "facebook.com": "HIGH", "instagram.com": "HIGH", "whatsapp.com": "HIGH",
    "twitter.com": "HIGH", "x.com": "HIGH", "linkedin.com": "HIGH",
    # Microsoft ecosystem
    "live.com": "HIGH", "outlook.com": "HIGH", "office.com": "HIGH",
    "microsoftonline.com": "HIGH", "azure.com": "HIGH",
    "login.microsoftonline.com": "HIGH",
    # Finance
    "paypal.com": "HIGH", "chase.com": "HIGH", "bankofamerica.com": "HIGH",
    "wellsfargo.com": "HIGH", "visa.com": "HIGH", "mastercard.com": "HIGH",
    "stripe.com": "HIGH", "square.com": "HIGH",
    # Developer / Cloud
    "github.com": "HIGH", "githubusercontent.com": "HIGH",
    "gitlab.com": "HIGH", "stackoverflow.com": "HIGH",
    "cloudflare.com": "HIGH", "heroku.com": "HIGH",
    "vercel.com": "HIGH", "netlify.com": "HIGH",
    # Communication
    "slack.com": "HIGH", "discord.com": "HIGH", "zoom.us": "HIGH",
    "telegram.org": "HIGH",
    # Entertainment
    "netflix.com": "HIGH", "spotify.com": "HIGH", "twitch.tv": "HIGH",
    "tiktok.com": "HIGH", "reddit.com": "HIGH",
    # Shopping
    "ebay.com": "HIGH", "etsy.com": "HIGH", "shopify.com": "HIGH",
    "walmart.com": "HIGH", "target.com": "HIGH",
    # Cloud Providers
    "aws.amazon.com": "HIGH", "cloud.google.com": "HIGH",
    # ── Shared Hosting Platforms ──────────────────────────────────────
    # Platform infrastructure is trusted, but individual sites are unknown.
    # MEDIUM trust = risk reduction without blind trust.
    "vercel.app": "MEDIUM", "netlify.app": "MEDIUM",
    "github.io": "MEDIUM", "gitlab.io": "MEDIUM", "pages.dev": "MEDIUM",
    "herokuapp.com": "MEDIUM", "fly.dev": "MEDIUM",
    "firebaseapp.com": "MEDIUM", "web.app": "MEDIUM",
    "appspot.com": "MEDIUM", "run.app": "MEDIUM",
    "azurewebsites.net": "MEDIUM", "cloudfront.net": "MEDIUM",
    "render.com": "MEDIUM", "railway.app": "MEDIUM",
    # Hosting / Platforms (not as high trust — used for both legit and phishing)
    "wix.com": "MEDIUM", "squarespace.com": "MEDIUM",
    "godaddy.com": "MEDIUM", "namecheap.com": "MEDIUM",
    "wordpress.com": "MEDIUM",
    # Education / Government
    "edu": "MEDIUM", "gov": "MEDIUM", "mil": "MEDIUM",
    # Authoritative Regional Namespaces (Namespace Trust Signals)
    "gov.sa": "HIGH", "edu.sa": "HIGH", "med.sa": "HIGH",
    "gov.eg": "HIGH", "edu.eg": "HIGH",
    "gov.ae": "HIGH", "ac.ae": "HIGH",
    "bank": "HIGH",

    # Other major
    "adobe.com": "HIGH", "dropbox.com": "HIGH", "notion.so": "HIGH",
    "figma.com": "HIGH", "canva.com": "HIGH", "medium.com": "HIGH",
    "wikipedia.org": "HIGH", "mozilla.org": "HIGH",
    "bbc.com": "HIGH", "cnn.com": "HIGH", "nytimes.com": "HIGH",
    "reuters.com": "HIGH",
}

class RiskScorer:
    """
    Handles risk score calculation using weighted internal engines.
    Produces a structured evidence-based verdict.
    """

    # ── Hard Constraint Rules ──────────────────────────────────────────
    # M#3 FIX: Condition now checks `was_shortened` to avoid applying a
    # min_score of 50 on URLs that were never shortened in the first place.
    MIN_RISK_CONSTRAINTS = [
        {
            "condition": lambda er: (
                er.get("url_unshortener", {}).get("status") == "error"
                and er.get("url_unshortener", {}).get("details", {}).get("was_shortened", True)
            ),
            "min_score": 50,
            "reason": "Shortened URL could not be resolved (Possible Crawler Evasion)"
        }
    ]

    @classmethod
    def _is_trusted(cls, domain: str) -> str:
        """Determines the trust level of a domain using strict suffix matching."""
        if not domain: return None
        for trusted, level in TRUST_HIERARCHY.items():
            if domain == trusted or domain.endswith("." + trusted):
                return level
        return None

    @classmethod
    def _sigmoid_score(cls, score: float) -> int:
        """Maps raw weighted scores to [0, 100] using a logistic sigmoid curve.
        
        Design Decision (Intentional):
            Center=50, Slope=0.05 produces a curve that pushes scores toward
            extremes (0 or 100). This is optimal for binary verdict systems
            (SAFE vs MALICIOUS) where middle-ground scores are undesirable.
            Scores < 30 compress toward 0 (SAFE), scores > 70 compress toward
            100 (MALICIOUS). This behavior is by design.
        """
        if score <= 0: return 0
        return int(100 * (1 / (1 + math.exp(-0.05 * (score - 50)))))

    @classmethod
    def calculate(cls, engine_results: Dict[str, Any], domain: str, url: str) -> Dict[str, Any]:
        # Strict Unified Contract: Safely unwrap data from EngineResult.
        # Ensure we always deal with dictionaries to prevent AttributeError.
        unwrapped_results = {}
        for name, result in engine_results.items():
            if isinstance(result, dict) and "data" in result:
                data = result.get("data", {})
                unwrapped_results[name] = data if isinstance(data, dict) else {}
            else:
                unwrapped_results[name] = result if isinstance(result, dict) else {}
        
        engine_results = unwrapped_results

        evidence_list = []
        components = {}
        
        # ─── 0. Open Redirect Detection ────────────────────────────────
        open_redir = engine_results.get("open_redirect", {})
        is_open_redirect = False
        if open_redir.get("status") == "ok":
            redir_details = open_redir.get("details", {})
            if redir_details.get("is_open_redirect"):
                is_open_redirect = True
                components["open_redirect"] = 40
                evidence_list.append({
                    "signal": "open_redirect",
                    "evidence": f"Open Redirect: {redir_details.get('wrapper_domain')} → {redir_details.get('target_domain')}",
                    "severity": "HIGH",
                    "weight": 40
                })

        # ─── 1. Threat Intelligence ──────────────────────────────────────
        threat = engine_results.get("threat_intelligence", {})
        threat_is_blacklisted = False
        if threat.get("status") == "ok":
            details = threat.get("details", {})
            if details.get("blacklisted"):
                threat_is_blacklisted = True
                components["threat_intel"] = 100
                evidence_list.append({
                    "signal": "threat_intel",
                    "evidence": details.get("evidence"),
                    "severity": "CRITICAL",
                    "weight": 100
                })
        
        # ─── 2. Typosquatting & Homoglyphs ───────────────────────────────
        typo = engine_results.get("typosquatting", {})
        is_impersonation = False
        if typo.get("status") == "ok":
            details = typo.get("details", {})
            if details.get("is_typosquatting") or details.get("is_subdomain_spoof"):
                is_impersonation = True
                score = 90 if details.get("is_typosquatting") else 80
                components["typosquatting"] = score
                evidence_list.append({
                    "signal": "typosquatting",
                    "evidence": details.get("reason", "Brand impersonation detected"),
                    "severity": "HIGH",
                    "weight": score
                })

        homoglyph = engine_results.get("homoglyph", {})
        if homoglyph.get("status") == "ok":
            details = homoglyph.get("details", {})
            if details.get("punycode") or details.get("confusable"):
                is_impersonation = True
                score = 90 if details.get("confusable") else 85
                components["homoglyph"] = score
                evidence_list.append({
                    "signal": "homoglyph",
                    "evidence": "Unicode/Punycode visual deception detected",
                    "severity": "HIGH",
                    "weight": score
                })

        # ─── 2.5. Compound Threat Escalation ─────────────────────────────
        # When impersonation (typosquatting/homoglyph) is combined with
        # phishing patterns, the threat level is exponentially higher.
        # Apply a 1.5x multiplier to the impersonation scores.
        if is_impersonation:
            impersonation_boost = 0
            if "typosquatting" in components:
                impersonation_boost += components["typosquatting"]
            if "homoglyph" in components:
                impersonation_boost += components["homoglyph"]
            
            # Check for phishing keyword presence in the URL
            url_lower = url.lower()
            phishing_kws = ["login", "signin", "verify", "account", "secure",
                           "update", "confirm", "password", "support", "billing"]
            kw_hits = sum(1 for kw in phishing_kws if kw in url_lower)
            
            if kw_hits > 0:
                # Apply escalation multiplier
                for key in ("typosquatting", "homoglyph"):
                    if key in components:
                        boosted = min(100, int(components[key] * 1.5))
                        components[key] = boosted
                evidence_list.append({
                    "signal": "compound_threat",
                    "evidence": f"Impersonation combined with {kw_hits} phishing keywords — high-confidence phishing",
                    "severity": "CRITICAL",
                    "weight": 95
                })

        # ─── 3. DNS Intelligence ─────────────────────────────────────────
        dns = engine_results.get("dns", {})
        dns_resolves = True
        if dns.get("status") == "ok":
            details = dns.get("details", {})
            dns_resolves = details.get("resolves", False)
            if not dns_resolves:
                res_status = details.get("resolution_status", "unknown")
                # Only nxdomain is a strong signal — timeout/no_answer are network issues
                if res_status == "nxdomain":
                    score = 80  # Domain definitely doesn't exist
                elif res_status == "servfail":
                    score = 30  # DNS server issue, not conclusive
                elif res_status in ("timeout", "no_answer"):
                    # Context-Aware DNS Penalty
                    # If there are other suspicious signals (like keywords), timeout is suspicious (DGA evasion)
                    phish = engine_results.get("phishing_patterns", {}).get("details", {})
                    has_other_signals = phish.get("keyword_count", 0) > 0 or is_impersonation
                    score = 25 if has_other_signals else 10
                    dns_resolves = True  # Treat as inconclusive but with a penalty
                else:
                    score = 20  # Unknown status, minor concern
                
                if score > 0:
                    components["dns"] = score
                    evidence_list.append({
                        "signal": "dns",
                        "evidence": f"DNS Resolution Failed: {res_status}",
                        "severity": "HIGH" if res_status == "nxdomain" else "MEDIUM",
                        "weight": score
                    })

        # ─── 4. Domain Age ───────────────────────────────────────────────
        age = engine_results.get("domain_age", {})
        age_data_missing = True
        if age.get("status") == "ok":
            age_details = age.get("details", {})
            age_data_missing = age_details.get("age_hidden", False)
            
            if not age_details.get("network_error", False):
                age_days = age_details.get("age_days", 999)
                if age_days < 30 and age_details.get("is_new", False):
                    score = 100 if age_days < 7 else 70
                    components["domain_age"] = score
                    evidence_list.append({
                        "signal": "domain_age",
                        "evidence": f"Recently registered domain ({age_days} days old)",
                        "severity": "MEDIUM",
                        "weight": score
                    })
                elif age_days > 1095:
                    components["domain_age"] = -20 # Established trust

        # ─── 5. Advanced Heuristics (v4 Proxies) ─────────────────────────
        # Age Heuristic: If age missing + DNS failure
        if age_data_missing and not dns_resolves:
            components["domain_age"] = components.get("domain_age", 0) + 15
            evidence_list.append({
                "signal": "age_heuristic",
                "evidence": "Missing age data combined with DNS failure (High Risk Proxy)",
                "severity": "MEDIUM",
                "weight": 15
            })
            
        # Pattern signals — only meaningful if combined with other risk indicators
        phish = engine_results.get("phishing_patterns", {})
        has_phishing_pattern = False
        if phish.get("status") == "ok":
            details = phish.get("details", {})
            kw_count = details.get("keyword_count", 0)
            compound_count = len(details.get("compound_patterns", []))
            is_brand_spoof = details.get("is_brand_spoof", False)
            
            if kw_count > 0:
                # Compound patterns are much more suspicious than single keywords
                if compound_count > 0 or is_brand_spoof:
                    has_phishing_pattern = True
                    score = min(85, compound_count * 40 + kw_count * 15)
                else:
                    # Single keywords like "login" or "account" appear in legitimate URLs
                    # Only score if there are multiple keywords together
                    score = min(60, max(0, (kw_count - 1) * 20))  # First keyword is FREE
                    if score >= 40:
                        has_phishing_pattern = True
                
                if score > 0:
                    components["patterns"] = score
                    evidence_list.append({
                        "signal": "patterns",
                        "evidence": f"Found {kw_count} phishing keywords" + (f" + {compound_count} compound patterns" if compound_count else ""),
                        "severity": "HIGH" if compound_count > 0 or is_brand_spoof else "MEDIUM",
                        "weight": score
                    })

        # ─── 6. URL Structure Features ───────────────────────────────────
        url_feat = engine_results.get("url_features", {})
        if url_feat.get("status") == "ok":
            feat_details = url_feat.get("details", {})
            feat_score = 0
            feat_signals = []

            if feat_details.get("is_ip"):
                feat_score += 30
                feat_signals.append("IP-based URL")
            if feat_details.get("has_at_symbol"):
                feat_score += 40
                feat_signals.append("@ symbol in URL (credential phishing)")
            if feat_details.get("has_encoded_chars"):
                feat_score += 15
                feat_signals.append("Percent-encoded characters in path")
            if feat_details.get("subdomain_count", 0) > 3:
                feat_score += 20
                feat_signals.append(f"Excessive subdomains ({feat_details.get('subdomain_count')})")

            if feat_score > 0:
                components["url_features"] = min(feat_score, 85)
                evidence_list.append({
                    "signal": "url_features",
                    "evidence": "; ".join(feat_signals),
                    "severity": "MEDIUM",
                    "weight": components["url_features"]
                })

        # ─── 7. SSL/TLS Intelligence ─────────────────────────────────────
        ssl_res = engine_results.get("ssl", {})
        if ssl_res.get("status") == "ok":
            ssl_details = ssl_res.get("details", {})
            ssl_score = 0
            ssl_signals = []
            ssl_errors = ssl_details.get("errors", [])
            
            # Only penalize for SSL issues if we actually connected and confirmed
            # Do NOT penalize if the connection timed out or was refused
            has_network_error = any(
                err_kw in str(ssl_errors).lower() 
                for err_kw in ["timeout", "refused", "reset", "getaddrinfo", "unreachable"]
            )
            
            if not has_network_error:
                if not ssl_details.get("has_ssl"):
                    ssl_score += 20
                    ssl_signals.append("No SSL certificate")
                else:
                    if ssl_details.get("is_self_signed"):
                        ssl_score += 35
                        ssl_signals.append("Self-signed certificate")
                    if ssl_details.get("is_expired"):
                        ssl_score += 50
                        ssl_signals.append("Expired certificate")
                    protocol = ssl_details.get("protocol") or ""
                    if protocol and ("TLSv1.0" in protocol or "TLSv1.1" in protocol or "SSLv" in protocol):
                        ssl_score += 15
                        ssl_signals.append(f"Weak protocol: {protocol}")
                        
                    # Adaptive SSL Analysis
                    # BUG FIX: ssl_details may have "issuer": None (key exists
                    # with None value). Using (x or "") handles both None and
                    # missing key, preventing AttributeError: 'NoneType'.lower()
                    issuer = (ssl_details.get("issuer") or "").lower()
                    if "let's encrypt" in issuer or "cpanel" in issuer or "zerossl" in issuer:
                        # Free/Auto SSL providers are common in phishing
                        phish = engine_results.get("phishing_patterns", {}).get("details", {})
                        if phish.get("keyword_count", 0) > 0 or is_impersonation:
                            ssl_score += 25
                            ssl_signals.append(f"Free SSL Provider ({ssl_details.get('issuer')}) + Suspicious Context")
                            
                    cert_age = ssl_details.get("cert_age_days")
                    if cert_age is not None and cert_age < 3:
                        phish = engine_results.get("phishing_patterns", {}).get("details", {})
                        if phish.get("keyword_count", 0) > 0 or is_impersonation:
                            ssl_score += 20
                            ssl_signals.append(f"Newly issued certificate ({cert_age} days old) + Suspicious Context")

            if ssl_score > 0:
                components["ssl"] = min(ssl_score, 85)
                evidence_list.append({
                    "signal": "ssl",
                    "evidence": "; ".join(ssl_signals),
                    "severity": "MEDIUM" if ssl_score < 40 else "HIGH",
                    "weight": components["ssl"]
                })



        # ─── Confidence & Weighting ───────────────
        total_possible_weight = sum(ENGINE_WEIGHTS.values())
        success_weight = 0
        raw_weighted_score = 0
        
        for name, weight in ENGINE_WEIGHTS.items():
            # Standardizing engine names between analyzer and scorer
            lookup_name = name
            if name == "patterns":      lookup_name = "phishing_patterns"
            if name == "threat_intel":  lookup_name = "threat_intelligence"
            # Note: url_features, dns, ssl, etc. already match engine_results keys

            st = engine_results.get(lookup_name, {}).get("status")
            if st == "ok":
                success_weight += weight
                raw_weighted_score += components.get(name, 0) * weight
        
        confidence = success_weight / total_possible_weight
        
        # --- Critical Override ---
        for crit in CRITICAL_ENGINES:
            lookup_name = "threat_intelligence" if crit == "threat_intel" else "dns"
            if engine_results.get(lookup_name, {}).get("status") != "ok":
                confidence = min(confidence, 0.5)

        # ─── Tiered Trust Integration ───────────────
        trust_level = cls._is_trusted(domain)
        final_normalized_score = cls._sigmoid_score(raw_weighted_score)
        
        # CRITICAL: Do NOT reduce risk for trusted domains when an Open Redirect
        # is detected. The trusted domain (e.g. youtube.com) is just the WRAPPER;
        # the actual threat is the TARGET domain (e.g. evil-example.com).
        if trust_level and not is_impersonation and not is_open_redirect:
            multiplier = 0.3 if trust_level == "HIGH" else 0.6
            reduction_type = "Strong (HIGH TRUST)" if trust_level == "HIGH" else "Moderate (MEDIUM TRUST)"
            
            # Cautious reduction for high scores even on trusted domains
            if final_normalized_score > 70:
                multiplier = max(multiplier, 0.6) 

            final_normalized_score *= multiplier
            evidence_list.append({
                "signal": "trust_reduction",
                "evidence": f"Risk reduced by {int((1-multiplier)*100)}% due to {reduction_type} domain status",
                "severity": "LOW",
                "weight": 0
            })

        final_score = min(100, max(0, round(final_normalized_score)))

        # ─── Generalized Conviction Engine (Hard Constraints) ──────
        for rule in cls.MIN_RISK_CONSTRAINTS:
            if rule["condition"](engine_results):
                if final_score < rule["min_score"]:
                    final_score = rule["min_score"]
                    evidence_list.append({
                        "signal": "hard_constraint",
                        "evidence": rule["reason"],
                        "severity": "HIGH",
                        "weight": final_score
                    })

        # ─── Verdict Logic (v6.0 - Enterprise Grade) ───────────────────────────────────
        
        # 1. Calculate Engine Reliability
        engines_list = list(engine_results.values())
        total_engines = len(engines_list)
        failed_engines = sum(1 for e in engines_list if isinstance(e, dict) and e.get("status") != "ok")
        failure_ratio = failed_engines / max(total_engines, 1)

        # 2. Calculate Weighted Critical Signals
        critical_score = 0
        if is_impersonation:
            critical_score += 2
        if has_phishing_pattern:
            critical_score += 2
        if is_open_redirect:
            critical_score += 1

        # 3. Decision Tree
        if threat_is_blacklisted:
            verdict = Verdict.MALICIOUS
            
        elif critical_score >= 3:
            verdict = Verdict.MALICIOUS
            
        elif critical_score >= 1:
            if final_score >= 70 and confidence >= 0.6:
                verdict = Verdict.MALICIOUS
            else:
                verdict = Verdict.SUSPICIOUS
                
        elif final_score >= 80:
            verdict = Verdict.MALICIOUS
            
        elif final_score >= 40:
            verdict = Verdict.SUSPICIOUS
            
        else:
            # 4. Observability & Reliability Guardrails
            if total_engines < 2:
                verdict = Verdict.SUSPICIOUS
            elif failure_ratio > 0.5:
                verdict = Verdict.SUSPICIOUS
            elif confidence < 0.5:
                verdict = Verdict.SUSPICIOUS
            else:
                verdict = Verdict.SAFE

        # Final Malicious Override for Blacklist
        if threat_is_blacklisted:
            final_score = max(final_score, 100)

        return {
            "risk_score": final_score,
            "verdict": verdict.value,
            "confidence": round(confidence, 2),
            "evidence": evidence_list,
            "component_scores": components,
            "raw_weighted": round(raw_weighted_score, 2)
        }
