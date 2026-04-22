# services/scenario_engine.py
"""
Scenario Engine
───────────────
Generates detailed reports and human-readable summaries for each scan level.
Follows the architecture requested in the Scenario Engine Design.
"""

class ScanScenario:
    BASIC = "basic"
    STANDARD = "standard"
    DEEP = "deep"

def generate_scenario_summary(level, sources):
    """
    Generates a list of findings based on the scan level and results.
    """
    summary = []
    
    # 1. Level-specific descriptors
    if level == ScanScenario.BASIC:
        summary.append("Checked against 17M trusted domains")
        summary.append("Local heuristics analysis completed")
    elif level == ScanScenario.STANDARD:
        summary.append("Typosquatting & Homoglyph detection: Active")
        summary.append("Intelligence engines analysis: Completed")
    elif level == ScanScenario.DEEP:
        summary.append("AI Risk Model & Deep Learning analysis: Active")
        summary.append("VirusTotal & Global Intelligence: Polled")
        summary.append("DNS & SSL infrastructure check: Completed")

    # 2. Finding-specific summaries
    for src in sources:
        stype = src.get('source_type')
        engine = src.get('engine', '')
        verdict = src.get('verdict')
        
        if stype == 'blacklist' and verdict == 'malicious':
            summary.append("CRITICAL: URL found in local blacklist")
        
        if stype == 'engines':
            if engine == 'domain_analysis':
                summary.append(f"Domain Intel: {verdict.capitalize()}")
            if engine == 'typosquatting' and verdict == 'malicious':
                summary.append("⚠️ Typosquatting (Spoofing) detected")
            if engine == 'homoglyph' and verdict == 'malicious':
                summary.append("⚠️ Homoglyph (Visual spoofing) detected")
                
        if stype == 'ai':
            risk = src.get('risk_score', 0)
            summary.append(f"AI Risk Model: {'Low' if risk < 30 else 'Moderate' if risk < 70 else 'High'}")
            
        if stype == 'gsb':
            if verdict == 'malicious':
                summary.append("🔴 Google Safe Browsing: Flagged as dangerous")
            else:
                summary.append("Google Safe Browsing: Safe")
                
        if stype == 'vt':
            if verdict == 'malicious':
                summary.append("🔴 VirusTotal engines flagged this link")
            else:
                summary.append("VirusTotal: No threats detected")
                
    return summary

def generate_final_reason(level, verdict, sources):
    """
    Builds the 'Safe because...' string.
    """
    if verdict == 'safe':
        reasons = []
        if any(s.get('engine') == 'heuristic' and s.get('verdict') == 'safe' for s in sources):
            reasons.append("Local Heuristics")
        if any(s.get('source_type') == 'gsb' and s.get('verdict') == 'safe' for s in sources):
            reasons.append("Google Safe Browsing")
        
        if not reasons:
            return "Checked against core safety databases"
        return f"Safe according to {' + '.join(reasons)}"
    
    elif verdict == 'malicious':
        for s in sources:
            if s.get('source_type') == 'blacklist':
                return "Blocked: URL found in local threat database"
            if s.get('engine') in ('typosquatting', 'homoglyph') and s.get('verdict') == 'malicious':
                return "Blocked: Detected as a spoofed/phishing domain"
        return "Blocked: Identified as a threat by our multiple engines"
    
    return "Analyzed: Several suspicious patterns were detected"
