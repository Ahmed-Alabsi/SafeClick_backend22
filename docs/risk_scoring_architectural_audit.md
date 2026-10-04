# SafeClick Risk Scoring Architecture: Deep Technical Audit
**Document Version:** 4.0.0-PROD  
**Author:** Senior Staff Security Software Engineer & Lead Backend Architect  
**Classification:** Internal Core Architecture Review  
**Target Systems:** 
1. `domain_analysis.services.risk_scoring.RiskScorer` (Internal Micro Risk Engine)
2. `services.decision_engine.DecisionEngine` (Master Correlation & Orchestration Engine)

---

## 1. Executive Summary & Philosophy

In enterprise-grade security platforms (such as Google Web Risk, Microsoft Defender SmartScreen, and Cloudflare Radar), threat scoring cannot rely on naive linear averaging. A single naive average creates a fatal vulnerability: **Signature Dilution**, where a newly minted zero-day phishing link scores `0` on external signature databases (VirusTotal/GSB) and dilutes a 100% confirmed internal typosquatting detection down to an innocent score.

SafeClick solves this via a **Two-Tiered Asymmetric Scoring Architecture**:
1. **Tier 1 (`RiskScorer`)**: Local heuristic and telemetry correlation inside the domain analysis pipeline. It evaluates physical link geometry, cryptographic status, brand impersonation, and protocol signals, mapping them through a **Non-Linear Sigmoid Transfer Function**.
2. **Tier 2 (`DecisionEngine`)**: Global scan orchestrator correlation. It combines local telemetry with cloud intelligence, enforcing **Anti-Dilution Constraints**, **Tiered Trust Hierarchies**, and **Hard Conviction Floors**.

---

## 2. Tier 1: Micro Risk Scoring Engine (`RiskScorer`)

Located at: [`domain_analysis/services/risk_scoring.py`](file:///e:/SafeClick/backend_SafeClick/domain_analysis/services/risk_scoring.py)

### 2.1 The Mathematics of Raw Score Mapping (Sigmoid Function)

Instead of clamping raw scores linearly, `RiskScorer` applies a modified Logistic Sigmoid Curve:

$$\text{RiskScore}(x) = \left\lfloor 100 \times \left( \frac{1}{1 + e^{-0.05 \cdot (x - 50)}} \right) \right\rfloor \quad \text{for } x > 0$$

```python
@classmethod
def _sigmoid_score(cls, score: float) -> int:
    if score <= 0: return 0
    return int(100 * (1 / (1 + math.exp(-0.05 * (score - 50)))))
```

#### Why Center = 50 and Slope = 0.05?
* **Bimodal Distribution Push:** Security decision systems suffer when scores hover around the ambiguous middle (40–60).
* **Mathematical Property:**
  * When $x = 0 \implies \text{Score} = 0$ (Hard clamp).
  * When $x = 20 \implies \text{Score} \approx 18$ (Safe range compression).
  * When $x = 50 \implies \text{Score} = 50$ (Inflection threshold).
  * When $x = 80 \implies \text{Score} \approx 81$.
  * When $x = 100 \implies \text{Score} \approx 92$.
  * When $x \ge 120 \implies \text{Score} \to 100$.
* This ensures that low-level noise does not generate false alarms, while compound suspicious indicators quickly saturate toward 100.

---

### 2.2 Component Weight Matrix (`ENGINE_WEIGHTS`)

Each internal telemetry engine has an assigned intrinsic credibility weight:

| Engine Key | Weight | Architectural Rationale |
|---|---|---|
| `threat_intel` | **2.0** | Local verified blacklist hits are deterministic; highest authority. |
| `dns` | **1.5** | Core internet routing; non-existent domains (`nxdomain`) indicate dead or malicious infrastructure. |
| `typosquatting` | **1.5** | Levenshtein brand distance is targeted attacker intent, rarely accidental. |
| `open_redirect` | **1.3** | Exploitation vector; hides malicious target behind a trusted wrapper. |
| `patterns` | **1.2** | Heuristic keywords (login, auth, secure); indicates credential harvesting. |
| `homoglyph` | **1.0** | Punycode/Cyrillic deception; visual spoofing. |
| `domain_age` | **1.0** | Newly registered domains (< 14 days) represent 85%+ of active phishing campaigns. |
| `ssl` | **1.0** | Cryptographic posture (expired, self-signed, untrusted CA). |
| `url_features` | **0.8** | Structural anomalies (IP host, `@` token, excessive subdomains, path entropy). |
| `url_shortener` | **0.5** | Link masking; suspicious but widely used legitimately. |

**Total Maximum Weight:** $\sum W_i = 11.8$

---

### 2.3 Granular Signal Decomposition (Letter-by-Letter Analysis)

#### 1. Threat Intelligence (`threat_intel`)
* **Trigger:** Exact match in `master_blacklist.csv` or OpenPhish live feed.
* **Component Score:** Assigned **100**.
* **Impact:** Automatically forces final verdict to `MALICIOUS` and locks `risk_score = 100` via hard override:
  ```python
  if threat_is_blacklisted:
      final_score = max(final_score, 100)
      verdict = Verdict.MALICIOUS
  ```

#### 2. Impersonation & Compound Threat Escalation (`typosquatting` & `homoglyph`)
* **Base Scoring:**
  * Exact typosquatting domain: `90` points.
  * Subdomain spoofing (`paypal.something.com`): `80` points.
  * Homoglyph confusable characters: `90` points.
  * Punycode spoofing: `85` points.
* **The Compound Threat Multiplier ($1.5\times$ Escalation):**
  A typosquatted domain alone might be parked or a defensive registration. However, **Typosquatting + Phishing Keywords** (`login`, `verify`, `account`) is an active attack vector.
  ```python
  if is_impersonation and kw_hits > 0:
      for key in ("typosquatting", "homoglyph"):
          components[key] = min(100, int(components[key] * 1.5))
  ```
  This immediately elevates the raw score to $90 \times 1.5 = 135 \implies$ Sigmoid saturates to **98–100%**.

#### 3. DNS Context-Aware Penalty
* `nxdomain` (Confirmed non-existent): **80 points** (High Severity).
* `servfail` (DNS server fault): **30 points** (Inconclusive).
* `timeout` / `no_answer`:
  * If other suspicious signals exist (keywords, entropy): **25 points** (Assumed DGA evasion or blocking).
  * Pure timeout without other signals: **10 points** (Transient network issue).

#### 4. Adaptive SSL Scoring
* Does not penalize if connection was dropped due to network timeouts (avoids False Positives during ISP drops).
* Expired Certificate: **+50 points**.
* Self-Signed Certificate: **+35 points**.
* Weak Protocol (TLSv1.0/1.1): **+15 points**.
* **Contextual Free SSL Provider (Let's Encrypt / cPanel / ZeroSSL):**
  * Free SSL alone: **0 points** (Millions of legit sites use Let's Encrypt).
  * Free SSL + Phishing Keywords: **+25 points** (Attackers leverage automated free certs on burner domains).
* Newly Issued Certificate (< 3 days old) + Phishing Keywords: **+20 points**.

#### 5. Open Redirect Target Decoupling
* When an Open Redirect is detected (e.g., `google.com/url?q=https://evil.com`), the wrapper domain is ignored for trust evaluation.
* The risk score is anchored to the **target domain** to prevent attackers from using Google or YouTube as an immunity shield.

---

### 2.4 The Enterprise Tiered Trust Hierarchy (`TRUST_HIERARCHY`)

To eliminate False Positives on critical enterprise endpoints (Google Auth, Microsoft Live, GitHub raw links), domains are classified into two trust tiers:

* **HIGH Trust (`0.3x` Risk Multiplier / 70% reduction):**
  * Core global infrastructure: `google.com`, `microsoft.com`, `apple.com`, `amazon.com`, `meta.com`, `paypal.com`, `github.com`, `cloudflare.com`, etc.
* **MEDIUM Trust (`0.6x` Risk Multiplier / 40% reduction):**
  * Shared platforms and developer hosting: `vercel.app`, `netlify.app`, `github.io`, `firebaseapp.com`, `herokuapp.com`, `.edu`, `.gov`.
* **Hard Guardrail:**
  If an attack is visually proven (`is_impersonation == True`) or wrapped in an Open Redirect, **trust reduction is completely bypassed**.

---

### 2.5 Observability & Reliability Guardrails

A security engine must know when it is blind. In `RiskScorer`:
```python
if total_engines < 2:
    verdict = Verdict.SUSPICIOUS
elif failure_ratio > 0.5:
    verdict = Verdict.SUSPICIOUS
elif confidence < 0.5:
    verdict = Verdict.SUSPICIOUS
```
If more than 50% of the internal engines fail or timeout due to network partitions, SafeClick **refuses to issue a `SAFE` verdict**. It degrades gracefully to `SUSPICIOUS`, honoring the **Fail-Secure Principle**.

---

## 3. Tier 2: Master Decision & Orchestration Engine (`DecisionEngine`)

Located at: [`services/decision_engine.py`](file:///e:/SafeClick/backend_SafeClick/services/decision_engine.py)

### 3.1 Component Weight Distribution

At the global orchestration level, inputs from various pipelines are correlated using normalized effective weights:

| Source Type | Base Weight ($W_c$) | Role in Verdict |
|---|---|---|
| `blacklist` | **0.95** | Local threat database / OpenPhish |
| `gsb` | **0.85** | Google Safe Browsing Cloud Feed |
| `engines` | **0.60** | SafeClick Deep Internal Domain Analysis |
| `vt` | **0.50** | VirusTotal Multi-AV Aggregation |
| `ai` | **0.40** | XGBoost Feature Vector Model (Future) |
| `heuristic` | **0.30** | Surface-level string checks (Phase 1) |

$$\text{WeightedScore} = \frac{\sum (S_c \times W_c \times C_c)}{\sum (W_c \times C_c)}$$
Where $S_c$ is component score, $W_c$ is component base weight, and $C_c$ is confidence.

---

### 3.2 Zero-Day Threat Anti-Dilution Engine

#### The Architectural Defect in Traditional Systems:
Suppose an attacker registers `paypa1-update.com` 10 minutes ago.
* SafeClick `engines`: **95** (Confirmed typosquatting + phishing keyword).
* Google Safe Browsing: **0** (No reports yet; clean).
* VirusTotal: **0** (0/72 scanners detect it; clean).

Under standard weighted averaging:
$$\text{Score} = \frac{(95 \times 0.6) + (0 \times 0.85) + (0 \times 0.50)}{0.6 + 0.85 + 0.50} = \frac{57}{1.95} = \mathbf{29.2\%} \implies \text{SUSPICIOUS or SAFE!}$$
The zero-day attack bypassed the system because the external databases did not know about it yet!

#### SafeClick's Anti-Dilution Solution:
When an internal threat is detected (`scores['engines'] >= 70 or has_strong_typosquatting`):
```python
if is_internal_threat and key in ('vt', 'gsb') and scores[key] == 0:
    eff_weight *= 0.15  # Downweight clean status of signature DBs on new attacks
```
Furthermore, the **Engine Conviction Floor** clamps the minimum score:
```python
if scores['engines'] >= 70 and confidences['engines'] >= 0.7:
    floor = 70
    if final_score < floor:
        final_score = floor
```
**Result:** The zero-day phishing domain stays firmly at **$\ge 75\%$ (`MALICIOUS`)**. The lack of external signatures can never pardon an internal high-confidence conviction.

---

### 3.3 Final Verdict Mapping Thresholds

| Final Score Range | Verdict | Action Taken |
|---|---|---|
| **$0 \le \text{Score} \le 24$** | `safe` | Access granted; zero user interruption. |
| **$25 \le \text{Score} \le 59$** | `suspicious` | Advisory warning; user prompt required. |
| **$60 \le \text{Score} \le 100$** | `malicious` | Hard block; automated incident report. |

---

## 4. Strengths & Architectural Evaluation (Senior Perspective)

1. **Deterministic Defense:** Blacklists and confirmed brand spoofs trigger non-negotiable overrides, eliminating statistical lottery in clear-cut attacks.
2. **Asymmetric Weighting:** External signature databases act as amplifiers for malicious convictions, but are silenced from diluting zero-day detections.
3. **Resilience to Environmental Failure:** If local DNS fails or network drops occur, the engine calculates reliability metrics and drops confidence rather than falsely declaring safety.

---

## 5. Potential Long-Term Enhancements (For Post-Launch Roadmap)

1. **Dynamic Sigmoid Calibration:** Allow the steepness parameter ($k=0.05$) to dynamically adjust based on the user's organization profile (e.g., higher sensitivity for executive VIP accounts).
2. **Bayesian Score Fusion:** Once the AI XGBoost engine is reintroduced, transition the master aggregator from weighted heuristic averaging to Bayesian Evidence Updating ($P(\text{Malicious} \mid E_1, E_2, \dots, E_n)$).
