"""
Homoglyph Detection Engine
───────────────────────────
Detects Unicode-based and Latin-based domain spoofing attacks:
- Punycode (xn--) internationalized domain names
- Mixed-script characters (e.g., Cyrillic + Latin)
- Confusable look-alike characters (non-ASCII only)
- Latin character manipulation (rn→m, 1→l, 0→o, vv→w)
"""

import idna
import unicodedata
from typing import Dict, Any, List
from confusable_homoglyphs import confusables
from .constants import LATIN_TRICKS


def _detect_latin_tricks(domain: str) -> list:
    """Detect Latin character manipulation tricks in a domain."""
    found = []
    lower = domain.lower()
    for trick, looks_like in LATIN_TRICKS.items():
        if trick in lower:
            found.append(f"'{trick}' looks like '{looks_like}'")
    return found


def detect_homoglyph_attack(domain: str) -> Dict[str, Any]:
    """
    Detects if a domain uses homoglyphs, mixed-script, or Latin tricks.
    """
    if not domain:
        return {
            "status": "error",
            "error": "No domain provided",
            "details": {}
        }

    result = {
        "punycode": False,
        "mixed_script": False,
        "confusable": False,
        "latin_tricks": False,
        "severity": "low",
        "details": []
    }

    try:
        main_domain = domain.split(".")[0]

        # 1. Detect punycode
        try:
            ascii_domain = idna.encode(domain).decode()
            if ascii_domain.startswith("xn--"):
                result["punycode"] = True
                result["details"].append("punycode domain detected")
        except (idna.core.InvalidCodepoint, idna.core.InvalidCodepointContext,
                UnicodeError, UnicodeDecodeError, Exception):
            if any(ord(c) > 127 for c in domain):
                result["punycode"] = True
                result["details"].append("Non-ASCII domain with encoding issues")

        # 2. Detect mixed scripts
        scripts = set()
        for char in main_domain:
            if char in ".-_0123456789":
                continue
            try:
                name = unicodedata.name(char, "")
                if name:
                    script = name.split(" ")[0]
                    scripts.add(script)
            except ValueError:
                continue

        if len(scripts) > 1:
            result["mixed_script"] = True
            result["details"].append(f"Mixed unicode scripts: {', '.join(scripts)}")

        # 3. Detect confusable characters (non-ASCII domains only)
        from .dataset_loader import SAFETY_WHITELIST

        has_non_ascii = any(ord(c) > 127 for c in domain)
        if domain not in SAFETY_WHITELIST and has_non_ascii and confusables.is_confusable(domain):
            result["confusable"] = True
            result["details"].append("Confusable unicode characters detected")

        # 4. Detect Latin character manipulation (ASCII-level tricks)
        # This catches rn→m (rnicrosoft → microsoft), cl→d, vv→w
        if domain not in SAFETY_WHITELIST:
            tricks_found = _detect_latin_tricks(main_domain)
            if tricks_found:
                result["latin_tricks"] = True
                result["details"].extend([f"Latin trick: {t}" for t in tricks_found])

        # Determine severity
        points = 0
        if result["punycode"]:
            points += 2
        if result["mixed_script"]:
            points += 1
        if result["confusable"]:
            points += 3
        if result["latin_tricks"]:
            points += 2

        if points >= 5:
            result["severity"] = "critical"
        elif points >= 3:
            result["severity"] = "high"
        elif points >= 1:
            result["severity"] = "medium"
        else:
            result["severity"] = "low"

        return {
            "status": "ok",
            "details": result
        }

    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "details": {}
        }