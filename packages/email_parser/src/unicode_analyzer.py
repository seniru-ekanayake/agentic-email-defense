"""
UnicodeSecurityAnalyzer: Forensic Unicode Evasion & Anomaly Inspection.
Scans email headers (Subject, From, Reply-To, To, Cc), MIME body sections,
attachment filenames, and parameters for lexical evasion techniques.
Reports findings with explicit evidence location tags.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class UnicodeAnomalyFinding(BaseModel):
    location: str  # e.g., "HEADER: Subject", "HEADER: From", "BODY: text/html", "FILENAME: exploit.exe"
    anomaly_type: str  # RTLO, ZERO_WIDTH, UNICODE_TAG, CONFUSABLE_HOMOGLYPH, MIXED_SCRIPT
    detected_chars: List[str]
    codepoints: List[str]
    raw_text: str
    cleaned_text: str
    description: str
    risk_impact: float = 15.0


class UnicodeAnalysisReport(BaseModel):
    total_anomalies: int = 0
    findings: List[UnicodeAnomalyFinding] = Field(default_factory=list)
    has_rtlo: bool = False
    has_zero_width: bool = False
    has_unicode_tags: bool = False
    has_homoglyphs: bool = False


class UnicodeSecurityAnalyzer:
    """
    Comprehensive forensic analyzer for Unicode-based lexical evasion,
    homoglyph spoofing, and directional override manipulation.
    """

    # Directional overrides (RTLO / LTRO / BIDI embeddings)
    BIDI_OVERRIDE_CHARS = {
        "\u202e": "RIGHT-TO-LEFT OVERRIDE (RTLO)",
        "\u202d": "LEFT-TO-RIGHT OVERRIDE (LTRO)",
        "\u202b": "RIGHT-TO-LEFT EMBEDDING (RLE)",
        "\u202a": "LEFT-TO-RIGHT EMBEDDING (LRE)",
        "\u202c": "POP DIRECTIONAL FORMATTING (PDF)",
        "\u2066": "LEFT-TO-RIGHT ISOLATE (LRI)",
        "\u2067": "RIGHT-TO-LEFT ISOLATE (RLI)",
        "\u2068": "FIRST STRONG ISOLATE (FSI)",
        "\u2069": "POP DIRECTIONAL ISOLATE (PDI)"
    }

    # Zero-width non-printing characters
    ZERO_WIDTH_CHARS = {
        "\u200b": "ZERO WIDTH SPACE (ZWSP)",
        "\u200c": "ZERO WIDTH NON-JOINER (ZWNJ)",
        "\u200d": "ZERO WIDTH JOINER (ZWJ)",
        "\ufeff": "ZERO WIDTH NO-BREAK SPACE (BOM)",
        "\u200e": "LEFT-TO-RIGHT MARK (LRM)",
        "\u200f": "RIGHT-TO-LEFT MARK (RLM)",
        "\u180e": "MONGOLIAN VOWEL SEPARATOR",
        "\u202f": "NARROW NO-BREAK SPACE"
    }

    # Common Cyrillic/Greek homoglyphs confusables with ASCII Latin
    COMMON_HOMOGLYPH_MAP = {
        'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
        'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'К': 'K', 'М': 'M',
        'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X', 'Ѕ': 'S', 'І': 'I', 'Ј': 'J',
        'α': 'a', 'ο': 'o', 'ρ': 'p', 'υ': 'v', 'κ': 'k'
    }

    def analyze_text(self, text: str, location: str) -> List[UnicodeAnomalyFinding]:
        """
        Analyzes a single string target and tags all anomalies with exact location.
        """
        if not text:
            return []

        findings: List[UnicodeAnomalyFinding] = []

        # 1. Check RTLO / BIDI Overrides
        bidi_found = []
        bidi_cps = []
        for ch in text:
            if ch in self.BIDI_OVERRIDE_CHARS:
                bidi_found.append(ch)
                bidi_cps.append(f"U+{ord(ch):04X}")

        if bidi_found:
            findings.append(UnicodeAnomalyFinding(
                location=location,
                anomaly_type="RTLO",
                detected_chars=bidi_found,
                codepoints=bidi_cps,
                raw_text=text[:100],
                cleaned_text="".join(c for c in text if c not in self.BIDI_OVERRIDE_CHARS),
                description=f"Right-to-Left Override (RTLO) or BIDI control characters detected in {location}",
                risk_impact=35.0
            ))

        # 2. Check Zero-Width Characters
        zw_found = []
        zw_cps = []
        for ch in text:
            if ch in self.ZERO_WIDTH_CHARS:
                zw_found.append(ch)
                zw_cps.append(f"U+{ord(ch):04X}")

        if zw_found:
            findings.append(UnicodeAnomalyFinding(
                location=location,
                anomaly_type="ZERO_WIDTH",
                detected_chars=zw_found,
                codepoints=zw_cps,
                raw_text=text[:100],
                cleaned_text="".join(c for c in text if c not in self.ZERO_WIDTH_CHARS),
                description=f"Zero-width hidden non-printing characters detected in {location}",
                risk_impact=20.0
            ))

        # 3. Check Unicode Tag Characters (U+E0000 - U+E007F)
        tag_found = []
        tag_cps = []
        for ch in text:
            cp = ord(ch)
            if 0xE0000 <= cp <= 0xE007F:
                tag_found.append(ch)
                tag_cps.append(f"U+{cp:04X}")

        if tag_found:
            findings.append(UnicodeAnomalyFinding(
                location=location,
                anomaly_type="UNICODE_TAG",
                detected_chars=tag_found,
                codepoints=tag_cps,
                raw_text=text[:100],
                cleaned_text="".join(c for c in text if not (0xE0000 <= ord(c) <= 0xE007F)),
                description=f"Unicode Tag characters (steganographic evasion payload) detected in {location}",
                risk_impact=40.0
            ))

        # 4. Check Mixed-Script & Homoglyphs
        scripts = set()
        homoglyphs_found = []
        homoglyph_cps = []
        for ch in text:
            if ch.isalpha():
                script_name = unicodedata.name(ch, "").split()[0]
                scripts.add(script_name)
                if ch in self.COMMON_HOMOGLYPH_MAP:
                    homoglyphs_found.append(ch)
                    homoglyph_cps.append(f"U+{ord(ch):04X} ({ch}->{self.COMMON_HOMOGLYPH_MAP[ch]})")

        if len(scripts) > 1 and "LATIN" in scripts and (("CYRILLIC" in scripts) or ("GREEK" in scripts)):
            findings.append(UnicodeAnomalyFinding(
                location=location,
                anomaly_type="MIXED_SCRIPT",
                detected_chars=homoglyphs_found or list(scripts),
                codepoints=homoglyph_cps or [],
                raw_text=text[:100],
                cleaned_text="".join(self.COMMON_HOMOGLYPH_MAP.get(c, c) for c in text),
                description=f"Mixed-script homoglyphs ({', '.join(scripts)}) detected in {location}",
                risk_impact=25.0
            ))

        return findings

    def analyze_email_components(
        self,
        headers: Dict[str, str],
        body_plain: Optional[str] = None,
        body_html: Optional[str] = None,
        attachments: Optional[List[Dict[str, Any]]] = None
    ) -> UnicodeAnalysisReport:
        """
        Runs comprehensive Unicode analysis across all header fields, body sections,
        and attachment metadata.
        """
        all_findings: List[UnicodeAnomalyFinding] = []

        # Analyze Headers
        header_map = {
            "Subject": "HEADER: Subject",
            "From": "HEADER: From",
            "Reply-To": "HEADER: Reply-To",
            "To": "HEADER: To",
            "Cc": "HEADER: Cc"
        }

        for k, loc in header_map.items():
            val = headers.get(k) or headers.get(k.lower())
            if val:
                all_findings.extend(self.analyze_text(val, loc))

        # Analyze Body Sections
        if body_plain:
            all_findings.extend(self.analyze_text(body_plain, "BODY: text/plain"))

        if body_html:
            # Strip tags for raw text inspection
            raw_html_text = re.sub(r"<[^>]+>", " ", body_html)
            all_findings.extend(self.analyze_text(raw_html_text, "BODY: text/html"))

        # Analyze Attachments
        if attachments:
            for att in attachments:
                fn = att.get("filename") or att.get("name")
                if fn:
                    all_findings.extend(self.analyze_text(fn, f"FILENAME: {fn}"))

        has_rtlo = any(f.anomaly_type == "RTLO" for f in all_findings)
        has_zw = any(f.anomaly_type == "ZERO_WIDTH" for f in all_findings)
        has_tags = any(f.anomaly_type == "UNICODE_TAG" for f in all_findings)
        has_homo = any(f.anomaly_type in ["CONFUSABLE_HOMOGLYPH", "MIXED_SCRIPT"] for f in all_findings)

        return UnicodeAnalysisReport(
            total_anomalies=len(all_findings),
            findings=all_findings,
            has_rtlo=has_rtlo,
            has_zero_width=has_zw,
            has_unicode_tags=has_tags,
            has_homoglyphs=has_homo
        )
