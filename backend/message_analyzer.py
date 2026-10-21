"""
PhishGuard - Social Engineering Message Detector
Rule-based analysis engine that identifies social engineering patterns in emails and messages.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


# ─── Rule categories & their signals ─────────────────────────────────────────

URGENCY_PHRASES = [
    r"\bact now\b", r"\burgent\b", r"\bimmediately\b", r"\bwithin \d+ hours?\b",
    r"\bwithin \d+ minutes?\b", r"\bexpires? (today|soon|now|tonight)\b",
    r"\blast chance\b", r"\btime[- ]sensitive\b", r"\bdeadline\b",
    r"\bdo not (delay|wait|ignore)\b", r"\brespond immediately\b",
    r"\baction required\b", r"\byour account (will be|has been) (suspended|locked|terminated|disabled)\b",
    r"\bfailure to (respond|verify|act|confirm)\b",
    r"\bimmediate attention\b", r"\bcritical alert\b", r"\bwarning:\b",
    r"\bfinal (notice|warning|reminder)\b", r"\bimminent\b",
]

THREAT_PHRASES = [
    r"\baccount (will be|has been|is being) (closed|suspended|locked|terminated|deactivated|deleted)\b",
    r"\blegal action\b", r"\bprosecuted\b", r"\bpenalty\b", r"\bfine of\b",
    r"\bblocked\b", r"\bban(ned)?\b", r"\bsuspended\b",
    r"\bunauthorized (access|activity|login|use)\b",
    r"\bsecurity (breach|incident|violation|alert|threat)\b",
    r"\byour (information|data|account) (has been|may have been) (compromised|stolen|hacked|leaked)\b",
    r"\bwe detected (suspicious|unusual|unauthorized)\b",
    r"\bsomeone (else )?(is|tried|attempted) (accessing|using|logging into)\b",
]

REWARD_BAIT_PHRASES = [
    r"\bcongratulations\b", r"\byou (have|'ve) (won|been selected|been chosen)\b",
    r"\bwinner\b", r"\bprize\b", r"\bgift card\b", r"\bfree (iphone|laptop|gift|reward|prize|money|cash)\b",
    r"\b\$\d+[\.,]?\d* (reward|gift|cash|prize)\b",
    r"\bclaim (your|this) (prize|reward|gift|money)\b",
    r"\blucky (winner|draw|customer)\b",
    r"\bexclusive (offer|deal|reward)\b",
    r"\blimited[- ]time (offer|deal)\b",
    r"\bno purchase necessary\b",
    r"\byou (qualify|are eligible) for\b",
    r"\b(refund|cashback) of \$?\d+\b",
]

CREDENTIAL_REQUEST_PHRASES = [
    r"\b(enter|provide|confirm|verify|update|submit|send) (your )?(password|pin|otp|passcode|credentials|login|username|ssn|social security)\b",
    r"\bverify (your )?(identity|account|email|phone|details|information)\b",
    r"\bclick (here|the link|below) to (verify|confirm|update|reset|access|login|sign in)\b",
    r"\breset (your )?password\b",
    r"\b(your )?(account|billing|payment) (information|details|data) (is|are) (required|needed|outdated|expired)\b",
    r"\bupdate (your )?(payment|billing|card|credit card|bank) (information|details|method)\b",
    r"\benter (your )?(card|credit card|debit card|bank account) (number|details|information)\b",
    r"\bconfirm (your )?(personal|payment|billing|account) (information|details)\b",
    r"\bwe need (to verify|your|you to confirm)\b",
]

IMPERSONATION_PHRASES = [
    r"\b(paypal|amazon|google|microsoft|apple|netflix|facebook|instagram|twitter|bank of america|wells fargo|chase|citibank|irs|usps|fedex|dhl|dropbox|linkedin)\b.*\b(team|support|security|service|customer care)\b",
    r"\bthis is (a message from|an official|an automated message)\b",
    r"\bofficial (notice|communication|alert|email)\b",
    r"\bdo not reply to this email\b",
    r"\bnoreply@\b",
    r"\bautomated (message|notification|alert)\b",
    r"\bIT (department|support|helpdesk|team)\b",
    r"\bsystem administrator\b",
    r"\btech(nical)? support\b.*\b(call|contact|reach)\b",
]

SUSPICIOUS_LINK_PHRASES = [
    r"http[s]?://[^\s]*(login|signin|verify|secure|account|update|confirm|billing)[^\s]*",
    r"\bclick (here|this link|the link|below)\b",
    r"\bvisit (the link|our website|our secure)\b",
    r"\bopen (the link|attachment|file)\b",
    r"\bdownload (the file|attachment|document|invoice)\b",
    r"\benable (macros|editing|content)\b",
    r"\bsee (attached|attachment|the attached)\b",
]

INFORMATION_HARVEST_PHRASES = [
    r"\b(reply|respond|send|email) (with|us|back) (your )?(name|address|phone|date of birth|dob|ssn|social security|mother'?s? maiden name)\b",
    r"\b(send|provide|share) (your )?(full name|address|phone|date of birth|dob|credit card number|bank details)\b",
    r"\b(fill|complete|submit) (this|the|our) (form|survey|questionnaire)\b",
    r"\byour (personal|private|sensitive|confidential) information\b",
    r"\bkyc\b", r"\bknow your customer\b",
    r"\bidentity (verification|check|confirm)\b",
    r"\bproof of (identity|address|income)\b",
]


# ─── Weights per category (used for risk score) ────────────────────────────────
CATEGORY_WEIGHTS = {
    "urgency":              15,
    "threat":               20,
    "reward_bait":          15,
    "credential_request":   25,
    "impersonation":        20,
    "suspicious_link":      20,
    "information_harvest":  20,
}

CATEGORY_LABELS = {
    "urgency":              "Urgency / Pressure tactics",
    "threat":               "Threat / Account suspension warning",
    "reward_bait":          "Fake reward / Prize bait",
    "credential_request":   "Credential or password request",
    "impersonation":        "Brand or authority impersonation",
    "suspicious_link":      "Suspicious link or attachment",
    "information_harvest":  "Personal information harvesting",
}


# ─── Compile patterns once at module load ─────────────────────────────────────
def _compile(patterns: list[str]) -> list[re.Pattern]:
    return [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]


_COMPILED = {
    "urgency":              _compile(URGENCY_PHRASES),
    "threat":               _compile(THREAT_PHRASES),
    "reward_bait":          _compile(REWARD_BAIT_PHRASES),
    "credential_request":   _compile(CREDENTIAL_REQUEST_PHRASES),
    "impersonation":        _compile(IMPERSONATION_PHRASES),
    "suspicious_link":      _compile(SUSPICIOUS_LINK_PHRASES),
    "information_harvest":  _compile(INFORMATION_HARVEST_PHRASES),
}


# ─── Analysis result dataclass ─────────────────────────────────────────────────
@dataclass
class MessageAnalysisResult:
    risk_score: int                    # 0-100
    verdict: str                       # "safe" | "suspicious" | "dangerous"
    categories_triggered: list[str]    # human-readable category labels
    warning_signs: list[str]           # specific matched phrase descriptions
    category_hits: dict                # category -> count of matches
    word_count: int
    has_urls: bool
    url_count: int
    caps_ratio: float
    exclamation_count: int


def analyze_message(text: str) -> MessageAnalysisResult:
    """
    Analyze a message or email body for social engineering signals.
    Returns a structured result with risk score and explanation.
    """
    if not text or not text.strip():
        return MessageAnalysisResult(
            risk_score=0, verdict="safe",
            categories_triggered=[], warning_signs=[],
            category_hits={}, word_count=0,
            has_urls=False, url_count=0,
            caps_ratio=0.0, exclamation_count=0,
        )

    # ── Text statistics ───────────────────────────────────────────────────────
    words = text.split()
    word_count = len(words)

    # CAPS ratio (suspicious if very high)
    alpha_chars = [c for c in text if c.isalpha()]
    caps_ratio = sum(1 for c in alpha_chars if c.isupper()) / max(len(alpha_chars), 1)

    # Exclamation marks
    exclamation_count = text.count('!')

    # URL detection
    url_pattern = re.compile(r'https?://[^\s]+|www\.[^\s]+', re.IGNORECASE)
    urls_found = url_pattern.findall(text)
    has_urls = bool(urls_found)
    url_count = len(urls_found)

    # ── Pattern matching per category ────────────────────────────────────────
    category_hits: dict[str, int] = {}
    warning_signs: list[str] = []
    categories_triggered: list[str] = []
    raw_score = 0

    for cat, patterns in _COMPILED.items():
        hit_count = 0
        for pattern in patterns:
            if pattern.search(text):
                hit_count += 1

        if hit_count > 0:
            category_hits[cat] = hit_count
            categories_triggered.append(CATEGORY_LABELS[cat])
            # A single detected tactic matters; repeated signals increase its
            # contribution without allowing one category to dominate the score.
            contribution = CATEGORY_WEIGHTS[cat] * (1 + 0.5 * (min(hit_count, 2) - 1))
            raw_score += contribution
            warning_signs.append(
                f"{CATEGORY_LABELS[cat]} — {hit_count} signal{'s' if hit_count > 1 else ''} detected"
            )

    # ── Bonus signals ──────────────────────────────────────────────────────────
    if caps_ratio > 0.5 and word_count > 5:
        raw_score += 8
        warning_signs.append("Excessive use of capital letters (common pressure tactic)")

    if exclamation_count >= 3:
        raw_score += 5
        warning_signs.append(f"Many exclamation marks ({exclamation_count}) — urgency amplifier")

    if has_urls and url_count >= 2:
        raw_score += 5
        warning_signs.append(f"Multiple URLs embedded ({url_count}) — possible misdirection")

    # Combination multiplier: urgency + threat together is especially dangerous
    if "urgency" in category_hits and "threat" in category_hits:
        raw_score = min(raw_score * 1.25, 100)

    # Credential request + suspicious link is a classic phishing combo
    if "credential_request" in category_hits and "suspicious_link" in category_hits:
        raw_score = min(raw_score * 1.3, 100)

    risk_score = min(int(raw_score), 100)

    # ── Verdict ────────────────────────────────────────────────────────────────
    if risk_score >= 60:
        verdict = "dangerous"
    elif risk_score >= 25:
        verdict = "suspicious"
    else:
        verdict = "safe"

    # If no warning signs, add a positive note
    if not warning_signs:
        warning_signs.append("No social engineering patterns detected")

    return MessageAnalysisResult(
        risk_score=risk_score,
        verdict=verdict,
        categories_triggered=categories_triggered,
        warning_signs=warning_signs,
        category_hits={k: v for k, v in category_hits.items()},
        word_count=word_count,
        has_urls=has_urls,
        url_count=url_count,
        caps_ratio=round(caps_ratio, 3),
        exclamation_count=exclamation_count,
    )
