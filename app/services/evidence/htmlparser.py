#!/usr/bin/env python3
"""
html_ml_parser.py
==================
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import re
import sys
from collections import Counter
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, parse_qs, unquote

from bs4 import BeautifulSoup

try:
    from langdetect import detect_langs, DetectorFactory, LangDetectException
    DetectorFactory.seed = 0  # deterministic results across runs
    _LANGDETECT_AVAILABLE = True
except ImportError:
    _LANGDETECT_AVAILABLE = False

try:
    import pandas as pd
    _PANDAS_AVAILABLE = True
except ImportError:
    _PANDAS_AVAILABLE = False


def deobfuscate_url(text: str) -> Optional[str]:
    """
    Reverse common manual URL-obfuscation tricks used to dodge naive
    string/regex scanners: hxxp(s), bracketed dots/colons, '(dot)', and
    zero-width/space-padded variants of '.'.

    Returns the normalized candidate URL, or None if `text` doesn't look
    like an obfuscated URL at all. Callers must keep both the original
    (`raw`) and this normalized form — per spec §8, collapsing to only the
    normalized form loses the evidence that obfuscation was attempted.
    """
    if not text:
        return None
    candidate = text.strip()
    if not re.search(r"h[x\*]{2}ps?[:\[]|(?:\[.\]|\(dot\)|\[:\])", candidate, re.IGNORECASE):
        return None

    candidate = re.sub(r"h[x\*]{2}p", "http", candidate, flags=re.IGNORECASE)
    candidate = re.sub(r"\[\.\]|\(dot\)|\[dot\]", ".", candidate, flags=re.IGNORECASE)
    candidate = re.sub(r"\[:\]", ":", candidate)
    candidate = re.sub(r"\s+", "", candidate)

    if not re.match(r"^https?://", candidate, re.IGNORECASE):
        return None
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None
    if not parsed.hostname:
        return None
    return candidate


def _registrable_domain(url_or_host: str) -> Optional[str]:
    """Best-effort registrable-domain extraction without a public-suffix
    list dependency: last two labels, e.g. 'mail.example.co.uk' -> 'co.uk'
    is a known limitation of this heuristic (no PSL), documented here
    rather than silently assumed correct."""
    try:
        host = urlparse(url_or_host).hostname or url_or_host
    except ValueError:
        host = url_or_host
    host = (host or "").lower().strip(".")
    if not host or _is_ip_literal(host):
        return host or None
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


@dataclass(slots=True)
class ImageAsset:
    src: str
    alt: str = ""
    width: Optional[str] = None
    height: Optional[str] = None
    is_tracking_pixel: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class URLRecord:
    url: str
    anchor_text: Optional[str] = None
    category: str = "general_link"
    redirect_target: Optional[str] = None
    features: dict = field(default_factory=dict)
    # --- forensic provenance (spec §8/§11) -----------------------------
    raw: Optional[str] = None            # exactly as it appeared in the source
    location: str = "html_anchor"        # html_anchor | html_text | iframe | form_action | object | embed | css
    tag: Optional[str] = None            # a, iframe, form, object, embed, style
    attribute: Optional[str] = None      # href, src, action, data, style
    is_obfuscated: bool = False          # raw used hxxp/[.]/[:]-style evasion
    link_mismatch: bool = False          # visible anchor text names a different destination than href
    visible_domain: Optional[str] = None
    actual_domain: Optional[str] = None

    def to_dict(self) -> dict:
        d = {
            "url": self.url,
            "raw": self.raw,
            "anchor_text": self.anchor_text,
            "category": self.category,
            "redirect_target": self.redirect_target,
            "location": self.location,
            "tag": self.tag,
            "attribute": self.attribute,
            "is_obfuscated": self.is_obfuscated,
            "link_mismatch": self.link_mismatch,
            "visible_domain": self.visible_domain,
            "actual_domain": self.actual_domain,
        }
        d.update(self.features)
        return d


@dataclass(slots=True)
class LanguageProfile:
    detected: str = "unknown"
    confidence: float = 0.0
    is_english: bool = False
    top_candidates: dict = field(default_factory=dict)
    cleaned_text: str = ""
    char_count: int = 0
    word_count: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class ParsedhtmlEmail:
    images: list[ImageAsset] = field(default_factory=list)
    url_records: list[URLRecord] = field(default_factory=list)
    language: LanguageProfile = field(default_factory=LanguageProfile)
    source: Optional[str] = None

    # ---- evidence fields --------------------------------------------
    # Kept separate from `language.cleaned_text`, which is whitespace-
    # collapsed for langdetect and not fit as an evidentiary record.
    full_text: str = ""             # complete visible text, structure preserved
    raw_html: Optional[str] = None  # untouched original source, for chain of evidence

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "language": self.language.to_dict(),
            "urls": [u.to_dict() for u in self.url_records],
            "images": [i.to_dict() for i in self.images],
            "full_text": self.full_text,
            "raw_html": self.raw_html,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_ml_row(self) -> dict:
        n_urls = len(self.url_records)
        n_tracker = sum(1 for u in self.url_records if u.category == "click_tracker")
        n_pixels = sum(1 for i in self.images if i.is_tracking_pixel)
        n_mismatch = sum(1 for u in self.url_records if u.link_mismatch)
        n_obfuscated = sum(1 for u in self.url_records if u.is_obfuscated)
        n_script_uri = sum(1 for u in self.url_records if u.features.get("has_javascript_scheme"))
        avg_entropy = (
            sum(u.features.get("domain_entropy", 0.0) for u in self.url_records) / n_urls
            if n_urls else 0.0
        )
        return {
            "source": self.source,
            "language": self.language.detected,
            "language_confidence": self.language.confidence,
            "is_english": self.language.is_english,
            "word_count": self.language.word_count,
            "char_count": self.language.char_count,
            "num_urls": n_urls,
            "num_click_trackers": n_tracker,
            "num_images": len(self.images),
            "num_tracking_pixels": n_pixels,
            "num_link_mismatches": n_mismatch,
            "num_obfuscated_urls": n_obfuscated,
            "num_javascript_uris": n_script_uri,
            "avg_url_domain_entropy": avg_entropy,
            "has_unsubscribe_link": any(u.category == "unsubscribe_or_prefs" for u in self.url_records),
        }

    def urls_to_dataframe(self):
        rows = [u.to_dict() for u in self.url_records]
        if _PANDAS_AVAILABLE:
            return pd.DataFrame(rows)
        return rows


class URLFeatureExtractor:
    _IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    _SPECIAL_CHAR_RE = re.compile(r"[^a-zA-Z0-9]")
    _DIGIT_RE = re.compile(r"\d")

    _SHORTENER_DOMAINS = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
        "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
    }

    _SUSPICIOUS_KEYWORDS = (
        "login", "verify", "secure", "account", "update", "confirm",
        "banking", "signin", "password", "unlock", "suspended", "billing",
    )

    _CATEGORY_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("tracking_pixel", ("logs.", "/collectorapi/", "/uba")),
        ("click_tracker", ("tr.",)),
        ("unsubscribe_or_prefs", ("unsubscribe", "communication")),
        ("feedback_report", ("feedback", "report")),
        ("legal_terms", ("terms", "condition")),
        ("security_advice", ("fakejobtrend", "security")),
        ("social_media", ("facebook", "twitter", "x.com", "instagram")),
    )

    @classmethod
    def classify(cls, url: str, parsed) -> str:
        redirect_target = cls.extract_redirect_target(parsed)
        candidates = [url]
        if redirect_target:
            candidates.append(redirect_target)

        for candidate in candidates:
            c_parsed = urlparse(candidate)
            host = (c_parsed.hostname or "").lower()
            path = (c_parsed.path or "").lower()
            haystack = host + path
            for category, needles in cls._CATEGORY_RULES:
                if category == "click_tracker":
                    continue
                if any(n in haystack for n in needles):
                    return category

        host = (parsed.hostname or "").lower()
        qkeys = {k.lower() for k in parse_qs(parsed.query)}
        if host.startswith("tr.") or "redirect" in qkeys:
            return "click_tracker"
        return "general_link"

    @classmethod
    def extract_redirect_target(cls, parsed) -> Optional[str]:
        qs = parse_qs(parsed.query)
        if "redirect" in qs:
            return unquote(qs["redirect"][0])
        return None

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        counts = Counter(s)
        length = len(s)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    @classmethod
    def _is_ip_host(cls, host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    @classmethod
    def extract(cls, url: str) -> dict:
        try:
            parsed = urlparse(url)
        except ValueError:
            parsed = urlparse("")

        host = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        registrable_parts = host.split(".") if host else []
        tld = registrable_parts[-1] if len(registrable_parts) > 1 else ""
        domain = ".".join(registrable_parts[-2:]) if len(registrable_parts) >= 2 else host
        subdomain_count = max(len(registrable_parts) - 2, 0)

        special_chars = len(cls._SPECIAL_CHAR_RE.findall(url))
        digits = len(cls._DIGIT_RE.findall(url))
        url_len = len(url) or 1

        category = cls.classify(url, parsed)
        if parsed.scheme.lower() == "javascript":
            category = "javascript_uri"
        elif parsed.scheme.lower() == "data":
            category = "data_uri"
        redirect_target = cls.extract_redirect_target(parsed)

        keyword_hits = sum(1 for kw in cls._SUSPICIOUS_KEYWORDS if kw in url.lower())

        return {
            "scheme": parsed.scheme,
            "domain": domain,
            "subdomain_count": subdomain_count,
            "tld": tld,
            "path": path,
            "path_depth": len([p for p in path.split("/") if p]),
            "query_param_count": len(parse_qs(query)),
            "url_length": url_len,
            "domain_length": len(domain),
            "has_ip_host": cls._is_ip_host(host),
            "has_at_symbol": "@" in url,
            "uses_https": parsed.scheme == "https",
            "num_digits": digits,
            "digit_ratio": round(digits / url_len, 4),
            "num_special_chars": special_chars,
            "special_char_ratio": round(special_chars / url_len, 4),
            "domain_entropy": round(cls._shannon_entropy(domain), 4),
            "has_redirect_param": redirect_target is not None,
            "is_shortened": domain in cls._SHORTENER_DOMAINS,
            "has_punycode": "xn--" in host,
            "has_percent_encoding": "%" in url,
            "has_javascript_scheme": parsed.scheme.lower() == "javascript",
            "has_data_scheme": parsed.scheme.lower() == "data",
            "suspicious_keyword_count": keyword_hits,
            "category": category,
            "redirect_target": redirect_target,
        }


class LanguageAnalyzer:
    _WHITESPACE_RE = re.compile(r"\s+")
    _WORD_RE = re.compile(r"\b\w+\b", re.UNICODE)
    _ENGLISH_HINTS = frozenset({
        "a", "an", "and", "are", "at", "before", "business", "click",
        "confirm", "for", "from", "hello", "invoice", "is", "of", "on",
        "please", "review", "secure", "the", "to", "update", "verify", "with",
        "you", "your",
    })
    _SCRIPT_LANGUAGES = (
        ("hi", 0x0900, 0x097F),
        ("bn", 0x0980, 0x09FF),
        ("ta", 0x0B80, 0x0BFF),
        ("te", 0x0C00, 0x0C7F),
        ("ar", 0x0600, 0x06FF),
        ("ru", 0x0400, 0x052F),
        ("zh", 0x4E00, 0x9FFF),
        ("ja", 0x3040, 0x30FF),
        ("ko", 0xAC00, 0xD7AF),
    )

    @classmethod
    def _fallback_detect(cls, cleaned: str, word_count: int):
        for language, start, end in cls._SCRIPT_LANGUAGES:
            script_chars = sum(start <= ord(char) <= end for char in cleaned)
            if script_chars:
                confidence = round(min(0.99, 0.55 + (script_chars / max(len(cleaned), 1))), 4)
                return language, confidence, {language: confidence}

        words = {word.lower() for word in cls._WORD_RE.findall(cleaned)}
        english_hits = len(words & cls._ENGLISH_HINTS)
        if word_count >= 3 and english_hits >= 2:
            confidence = round(min(0.9, 0.5 + (english_hits / max(word_count, 1))), 4)
            return "en", confidence, {"en": confidence}
        return "und", 0.0, {}

    @classmethod
    def analyze(cls, raw_text: str, top_k: int = 3) -> LanguageProfile:
        cleaned = cls._WHITESPACE_RE.sub(" ", raw_text).strip()
        word_count = len(cls._WORD_RE.findall(cleaned))

        profile = LanguageProfile(
            cleaned_text=cleaned,
            char_count=len(cleaned),
            word_count=word_count,
        )

        if not cleaned:
            profile.detected = "unknown (empty)"
            return profile

        if not _LANGDETECT_AVAILABLE:
            profile.detected, profile.confidence, profile.top_candidates = cls._fallback_detect(
                cleaned, word_count
            )
            profile.is_english = profile.detected == "en"
            return profile

        try:
            candidates = detect_langs(cleaned)
        except LangDetectException:
            profile.detected = "unknown (undetectable)"
            return profile

        top = candidates[0]
        profile.detected = top.lang
        profile.confidence = round(top.prob, 4)
        profile.is_english = top.lang == "en"
        profile.top_candidates = {
            c.lang: round(c.prob, 4) for c in candidates[:top_k]
        }
        return profile


class HTMLEmailParser:
    _STRIP_TAGS = ("style", "script", "meta", "link")

    def parse(self, html: str, source: Optional[str] = None) -> ParsedhtmlEmail:
        soup = BeautifulSoup(html, "html.parser")

        images = self._extract_images(soup)   # also removes <img> from tree
        image_srcs = {img.src for img in images}
        url_records = self._extract_urls(soup, exclude=image_srcs)

        self._strip_noise_tags(soup)          # remove style/script/meta/link
        full_text = self._extract_full_text(soup)       # evidence copy — structure preserved
        language = LanguageAnalyzer.analyze(full_text)  # analyze() makes its own collapsed copy internally

        return ParsedhtmlEmail(
            images=images,
            url_records=url_records,
            language=language,
            source=source,
            full_text=full_text,
            raw_html=html,
        )

    def parse_file(self, path) -> ParsedhtmlEmail:
        path = Path(path)
        html = path.read_text(encoding="utf-8", errors="replace")
        return self.parse(html, source=str(path))

    def parse_batch(self, paths):
        url_rows, email_rows = [], []
        for p in paths:
            doc = self.parse_file(p)
            email_rows.append(doc.to_ml_row())
            for u in doc.url_records:
                row = u.to_dict()
                row["source"] = str(p)
                url_rows.append(row)

        if _PANDAS_AVAILABLE:
            return pd.DataFrame(url_rows), pd.DataFrame(email_rows)
        return url_rows, email_rows

    def _extract_images(self, soup: BeautifulSoup) -> list[ImageAsset]:
        images = []
        for img in soup.find_all("img"):
            width, height = img.get("width"), img.get("height")
            is_pixel = (
                width in ("0", "0px", 0)
                or height in ("0", "0px", 0)
                or "collectorapi" in (img.get("src") or "")
                or "/uba" in (img.get("src") or "")
            )
            images.append(ImageAsset(
                src=img.get("src", ""),
                alt=img.get("alt", ""),
                width=width,
                height=height,
                is_tracking_pixel=is_pixel,
            ))
        for img in soup.find_all("img"):
            img.decompose()
        return images

    def _extract_urls(self, soup: BeautifulSoup, exclude=None) -> list[URLRecord]:
        records: list[URLRecord] = []
        seen: set[str] = set(exclude or ())

        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href in seen:
                continue
            seen.add(href)
            records.append(self._build_url_record(
                href, a.get_text(strip=True), tag="a", attribute="href", location="html_anchor"
            ))

        # Other elements that can carry a navigable/loadable URL. The spec
        # (§8) explicitly calls these out — a parser that only looks at
        # <a href> misses iframes, forms posting credentials elsewhere,
        # and embedded objects.
        attr_sources = (
            ("iframe", "src", "iframe"),
            ("form", "action", "form_action"),
            ("object", "data", "object"),
            ("embed", "src", "embed"),
            ("script", "src", "script"),
            ("link", "href", "link"),
        )
        for tag_name, attr_name, location in attr_sources:
            for tag in soup.find_all(tag_name, **{attr_name: True}):
                value = tag[attr_name]
                if not value or value in seen:
                    continue
                seen.add(value)
                records.append(self._build_url_record(
                    value, None, tag=tag_name, attribute=attr_name, location=location
                ))

        # url(...) inside inline style="" attributes and <style> blocks.
        for tag in soup.find_all(style=True):
            for css_url in re.findall(r"url\(\s*['\"]?([^'\")]+)['\"]?\s*\)", tag["style"]):
                if css_url in seen:
                    continue
                seen.add(css_url)
                records.append(self._build_url_record(
                    css_url, None, tag=tag.name, attribute="style", location="css"
                ))
        for style_tag in soup.find_all("style"):
            for css_url in re.findall(r"url\(\s*['\"]?([^'\")]+)['\"]?\s*\)", style_tag.get_text()):
                if css_url in seen:
                    continue
                seen.add(css_url)
                records.append(self._build_url_record(
                    css_url, None, tag="style", attribute="css", location="css"
                ))

        normalized_html = str(soup).replace("&amp;", "&")
        for match in re.findall(r'https?://[^\s"\'<>]+', normalized_html):
            match = match.rstrip('"\'')
            if match in seen or match == "http://www.w3.org/1999/xhtml":
                continue
            seen.add(match)
            records.append(self._build_url_record(match, None, tag=None, attribute=None, location="html_text"))

        # Obfuscated URLs (hxxp://, example[.]com, foo(dot)com) written out
        # as plain visible text rather than a real href. These never match
        # the https?:// regex above by design, so they need a separate pass.
        visible_text = soup.get_text(separator=" ", strip=False)
        for token in re.findall(r'\S*(?:h[x\*]{2}ps?[:\[]|\[\.\]|\(dot\)|\[dot\]|\[:\])\S*', visible_text, re.IGNORECASE):
            if token in seen:
                continue
            normalized = deobfuscate_url(token)
            if not normalized:
                continue
            seen.add(token)
            records.append(self._build_url_record(
                normalized, None, tag=None, attribute=None, location="html_text",
                raw_override=token, is_obfuscated=True
            ))

        return records

    @staticmethod
    def _build_url_record(
        url: str,
        anchor_text: Optional[str],
        tag: Optional[str] = None,
        attribute: Optional[str] = None,
        location: str = "html_anchor",
        raw_override: Optional[str] = None,
        is_obfuscated: bool = False,
    ) -> URLRecord:
        feats = URLFeatureExtractor.extract(url)
        record = URLRecord(
            url=url,
            raw=raw_override if raw_override is not None else url,
            anchor_text=anchor_text,
            category=feats.pop("category"),
            redirect_target=feats.pop("redirect_target"),
            features=feats,
            location=location,
            tag=tag,
            attribute=attribute,
            is_obfuscated=is_obfuscated,
        )
        HTMLEmailParser._detect_link_mismatch(record)
        return record

    @staticmethod
    def _detect_link_mismatch(record: URLRecord) -> None:
        """
        Flags the classic phishing construct: visible anchor text that
        itself looks like a URL/hostname naming one destination, while the
        real href points somewhere else entirely (spec §9's canonical
        example — text says google.com, href goes to evil-example.com).

        This only ever sets a fact (`link_mismatch`, `visible_domain`,
        `actual_domain`) — it does not label the email suspicious. That
        judgment belongs to the decision engine, not the parser.
        """
        text = (record.anchor_text or "").strip()
        if not text:
            return
        # Anchor text must itself look like a URL or bare hostname to be
        # comparable at all — "Click here" or "Unsubscribe" is not a claim
        # about a destination, so there is nothing to mismatch against.
        candidate = text if re.match(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://', text) else f"//{text}"
        try:
            visible_host = urlparse(candidate).hostname
        except ValueError:
            visible_host = None
        if not visible_host or "." not in visible_host:
            return

        actual_host = urlparse(record.url).hostname
        if not actual_host:
            return

        visible_domain = _registrable_domain(visible_host)
        actual_domain = _registrable_domain(actual_host)
        record.visible_domain = visible_domain
        record.actual_domain = actual_domain
        if visible_domain and actual_domain and visible_domain != actual_domain:
            record.link_mismatch = True

    def _strip_noise_tags(self, soup: BeautifulSoup) -> None:
        """Remove tags whose contents are never real visible text/evidence."""
        for tag_name in self._STRIP_TAGS:
            for tag in soup.find_all(tag_name):
                tag.decompose()

    def _extract_full_text(self, soup: BeautifulSoup) -> str:
        """
        Complete visible text for evidentiary purposes.

        Unlike `language.cleaned_text` (which collapses everything to single
        spaces purely so langdetect gets clean input), this preserves block
        structure as newlines — so headings, paragraphs, and list items don't
        get run together — and otherwise leaves the text untouched. Only
        excessive blank-line runs (3+) are collapsed to keep it readable.
        """
        text = soup.get_text(separator="\n", strip=True)
        return re.sub(r"\n{3,}", "\n\n", text)

    def _extract_language(self, soup: BeautifulSoup) -> LanguageProfile:
        """Standalone helper kept for direct/external use; `parse()` no
        longer calls this itself since it derives language from the
        already-extracted `full_text` to avoid walking the tree twice."""
        self._strip_noise_tags(soup)
        visible_text = soup.get_text(separator=" ", strip=True)
        return LanguageAnalyzer.analyze(visible_text)

