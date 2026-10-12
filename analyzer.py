#!/usr/bin/env python3
"""
Phishing email analyzer — beginner SOC project starter.

Feed it a sample_suspicious .eml file and it produces a triage verdict report:
header anomalies, spoofed domains, lookalike URLs, risky attachments,
and urgency language — the same checks a Tier 1 SOC analyst runs by hand.

Usage:
    python3 analyzer.py sample_suspicious.eml

Pure Python standard library, no installs needed.
"""

import re
import sys
from email.parser import BytesParser
from email.utils import parseaddr, getaddresses
from urllib.parse import urlparse

# --- Tunables ----------------------------------------------------------------

# Attachments worth flagging. .zip is context-dependent, so it's weighted lower.
DANGEROUS_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs",
                        ".ps1", ".msi", ".com", ".lnk"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso"}

# Phrases that manufacture panic — a classic phishing tell.
URGENCY_WORDS = ["urgent", "immediately", "action required", "verify your account",
                 "account suspended", "expires today", "last chance",
                 "security alert", "unauthorized access", "confirm now"]

# Well-known brands phishers love to impersonate. Used for lookalike detection.
COMMON_BRANDS = ["paypal", "microsoft", "amazon", "apple", "chase", "wellsfargo",
                 "bankofamerica", "google", "outlook", "office365", "dhl", "fedex"]

URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


# --- Small helpers ------------------------------------------------------------

def domain_of(addr):
    """Pull the domain out of an email address, lowercased."""
    _, address = parseaddr(addr)
    return address.split("@")[-1].lower() if "@" in address else ""


def root_domain(host):
    """Rough registrable domain: last two labels (paypal-secure-login.com -> paypal-secure-login.com)."""
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def levenshtein(a, b):
    """Tiny edit-distance for lookalike-domain spotting."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1,
                         prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def is_lookalike(host):
    """True if host looks like a typo-squatted or lookalike version of a known brand."""
    root = root_domain(host)
    for brand in COMMON_BRANDS:
        if brand in host.replace("-", "") and brand not in root:
            # brand appears with extra junk, e.g. paypal-secure-login.com
            return True, brand
        if levenshtein(root.split(".")[0], brand) in (1, 2) and brand != root.split(".")[0]:
            # one or two edits off the real brand, e.g. paypa1.com
            return True, brand
    return False, ""


# --- Checks -------------------------------------------------------------------

def check_headers(msg):
    """Look for header anomalies: mismatched From/Return-Path/Reply-To."""
    findings = []
    from_d = domain_of(msg.get("From", ""))
    return_path_d = domain_of(msg.get("Return-Path", ""))
    reply_d = domain_of(msg.get("Reply-To", ""))

    if return_path_d and from_d and return_path_d != from_d:
        findings.append((3, f"Return-Path domain ({return_path_d}) != From domain ({from_d}) — possible spoofing"))
    if reply_d and from_d and reply_d != from_d:
        findings.append((2, f"Reply-To domain ({reply_d}) != From domain ({from_d}) — replies go elsewhere"))

    # SPF/DKIM/DMARC Authentication-Results: present = good, absent = can't verify.
    auth = msg.get("Authentication-Results", "")
    if auth:
        findings.append((0, f"Authentication-Results header present: {auth[:80]}..."))
    else:
        findings.append((1, "No Authentication-Results header — SPF/DKIM/DMARC status unknown"))
    return findings


def extract_text_and_links(msg):
    """Pull plain text, HTML links (display text + href), and attachment names."""
    plain, links, attachments = [], [], []
    for part in msg.walk():
        ctype = part.get_content_type()
        disp = part.get_content_disposition()
        if disp == "attachment":
            attachments.append(part.get_filename() or "(unnamed attachment)")
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        if ctype == "text/plain":
            plain.append(text)
        elif ctype == "text/html":
            for href in HREF_RE.findall(text):
                links.append(("html", href, text))
    body = "\n".join(plain)
    # bare URLs in plain text
    for url in URL_RE.findall(body):
        links.append(("text", url, body))
    return body, links, attachments


def check_links(links):
    """Flag display-text vs href mismatches, lookalikes, and bare IPs."""
    findings, seen = [], set()
    for kind, href, context in links:
        if href in seen:
            continue
        seen.add(href)
        try:
            host = urlparse(href).hostname or ""
        except ValueError:
            continue
        if not host:
            continue
        # IP-based link — rare in legit mail, common in phishing kits.
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            findings.append((3, f"Link uses a raw IP address: {href[:60]}"))
        lookalike, brand = is_lookalike(host)
        if lookalike:
            findings.append((3, f"Lookalike domain '{host}' impersonating '{brand}'"))
        # Display text shows a URL but the href points somewhere else.
        if kind == "html":
            for shown in URL_RE.findall(context):
                shown_host = urlparse(shown).hostname or ""
                if shown_host and shown_host != host:
                    findings.append((3, f"Link text shows '{shown_host}' but href goes to '{host}'"))
                    break
    return findings


def check_attachments(attachments):
    findings = []
    for name in attachments:
        ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext in DANGEROUS_EXTENSIONS:
            findings.append((3, f"High-risk attachment type: {name}"))
        elif ext in ARCHIVE_EXTENSIONS:
            findings.append((1, f"Archive attachment (could hide anything): {name} — extract in a sandbox"))
    if not attachments:
        findings.append((0, "No attachments"))
    return findings


def check_urgency(subject, body):
    hits = [w for w in URGENCY_WORDS if w in (subject + " " + body).lower()]
    if hits:
        return [(1, f"Urgency/manipulation language detected: {', '.join(hits[:4])}")]
    return [(0, "No urgency/manipulation language found")]


# --- Verdict ------------------------------------------------------------------

def verdict(score):
    if score >= 6:
        return "HIGH RISK — treat as phishing. Do not click, do not reply; report per your SOC playbook."
    if score >= 3:
        return "MEDIUM RISK — suspicious. Verify the sender through a separate channel before acting."
    return "LOW RISK — no strong phishing indicators found."


def analyze(path):
    with open(path, "rb") as f:
        msg = BytesParser().parse(f)

    subject = msg.get("Subject", "(no subject)")
    from_raw = msg.get("From", "(unknown)")

    findings = []
    findings += check_headers(msg)
    body, links, attachments = extract_text_and_links(msg)
    findings += check_links(links)
    findings += check_attachments(attachments)
    findings += check_urgency(str(subject), body)

    score = sum(w for w, _ in findings)

    print("=" * 64)
    print(f"PHISHING TRIAGE REPORT — {path}")
    print("=" * 64)
    print(f"From:    {from_raw}")
    print(f"Subject: {subject}\n")
    print("Findings (severity 0=info, 1=low, 2=med, 3=high):")
    for weight, text in sorted(findings, key=lambda x: -x[0]):
        marker = {0: "ℹ", 1: "·", 2: "!", 3: "⚠"}[weight]
        print(f"  [{marker}] {text}")
    print(f"\nRisk score: {score}")
    print(f"Verdict: {verdict(score)}")
    print("=" * 64)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 analyzer.py <suspicious_email.eml>")
        sys.exit(1)
    analyze(sys.argv[1])
