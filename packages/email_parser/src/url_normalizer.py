"""
URLNormalizer: Centralized, multi-stage URL and URI normalization pipeline.
Decodes HTML entities, iterative percent-encoding, Unicode NFKC,
and normalizes schemes and hostnames before security pattern matching.
"""

from __future__ import annotations

import html
import re
import unicodedata
import urllib.parse
from typing import List, Optional, Tuple
from pydantic import BaseModel, Field


class NormalizedUrl(BaseModel):
    """Structured representation of a normalized URL or URI."""
    original_url: str
    normalized_url: str
    scheme: str
    host: str = ""
    port: Optional[int] = None
    path: str = ""
    query: str = ""
    fragment: str = ""
    is_network_url: bool = False
    is_local_file_url: bool = False
    is_unc_path: bool = False
    is_moniker_uri: bool = False
    is_data_uri: bool = False
    is_script_uri: bool = False
    decoding_stages: List[str] = Field(default_factory=list)

    @property
    def canonical_scheme(self) -> str:
        return self.scheme

    @property
    def canonical_hostname(self) -> str:
        return self.host

    @property
    def canonical_url(self) -> str:
        return self.normalized_url

    @property
    def is_redirect_wrapper(self) -> bool:
        q_lower = self.query.lower()
        return "url=http" in q_lower or "redirect=http" in q_lower or "dest=http" in q_lower or "target=http" in q_lower

    @property
    def extracted_redirect_target(self) -> Optional[str]:
        if self.is_redirect_wrapper:
            for param in self.query.split("&"):
                if "=" in param:
                    k, v = param.split("=", 1)
                    if k.lower() in ["url", "redirect", "dest", "target"] and v.startswith("http"):
                        return urllib.parse.unquote(v)
        return None


class URLNormalizer:
    """
    Centralized URL and URI normalization pipeline.
    Ensures obfuscated, multi-encoded, or entity-wrapped URLs
    are converted to their canonical form prior to rule evaluation.
    """

    NETWORK_SCHEMES = {"http", "https", "ftp", "ftps", "ws", "wss"}
    MONIKER_SCHEMES = {"search-ms", "ms-appinstaller", "ms-word", "ms-excel", "ms-powerpoint"}
    SCRIPT_SCHEMES = {"javascript", "vbscript", "about"}

    @classmethod
    def normalize(cls, raw_url: str) -> NormalizedUrl:
        if not raw_url:
            return NormalizedUrl(
                original_url="",
                normalized_url="",
                scheme=""
            )

        stages = []
        current = raw_url.strip()

        # 1. HTML Entity & Comment Decoding (e.g. &#x66;&#x69;&#x6c;&#x65;: or <!--comment-->)
        current = re.sub(r"<!--.*?-->", "", current)
        decoded_html = html.unescape(current)
        if decoded_html != current:
            stages.append("html_entities")
            current = decoded_html

        # 2. Unicode Normalization (NFKC to resolve compatibility characters)
        norm_unicode = unicodedata.normalize("NFKC", current)
        if norm_unicode != current:
            stages.append("unicode_nfkc")
            current = norm_unicode

        # 3. Iterative Percent-Decoding (up to 5 rounds to defeat nested encoding like %2566)
        rounds = 0
        while rounds < 5:
            unquoted = urllib.parse.unquote(current)
            if unquoted == current:
                break
            current = unquoted
            rounds += 1
        if rounds > 0:
            stages.append(f"percent_decoding_{rounds}_rounds")

        # 4. Strip control characters and whitespace
        clean_url = "".join(ch for ch in current if ord(ch) >= 32 or ch in "\t\r\n").strip()

        # 5. Handle UNC / SMB paths directly (e.g., \\server\share or //server/share)
        is_unc = False
        if clean_url.startswith("\\\\") or clean_url.startswith("//"):
            is_unc = True
            scheme = "file"
            norm_path = clean_url.replace("/", "\\")
            host = norm_path.lstrip("\\").split("\\")[0]
            return NormalizedUrl(
                original_url=raw_url,
                normalized_url=f"file://{host}/" + "/".join(norm_path.lstrip("\\").split("\\")[1:]),
                scheme="file",
                host=host.lower(),
                path=norm_path,
                is_local_file_url=False,
                is_unc_path=True,
                decoding_stages=stages
            )

        # 6. Parse scheme and components
        # Extract scheme if present (e.g., "file:", "search-ms:", "http:")
        scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):(.*)", clean_url, re.DOTALL)
        if scheme_match:
            scheme = scheme_match.group(1).lower()
            rest = scheme_match.group(2)
        else:
            scheme = ""
            rest = clean_url

        # Check special categories
        is_data = scheme == "data"
        is_script = scheme in cls.SCRIPT_SCHEMES
        is_moniker = scheme in cls.MONIKER_SCHEMES
        is_local_file = False

        host = ""
        port = None
        path = ""
        query = ""
        fragment = ""

        if is_data or is_script:
            path = rest
            canonical = f"{scheme}:{rest}"
        elif scheme == "file":
            # Normalize file scheme: file:///c:/path or file://server/share
            stripped = rest.lstrip("/")
            if stripped.startswith("\\"):
                # file:///\\server\share\... (Outlook MonikerLink form) is a UNC path to a remote host
                unc_parts = stripped.lstrip("\\").replace("/", "\\").split("\\")
                host = unc_parts[0].lower()
                path = "/" + "/".join(unc_parts[1:])
                is_unc = bool(host) and host not in ("localhost", "127.0.0.1")
            elif rest.startswith("///") or (len(stripped) >= 2 and stripped[1] == ":"):
                is_local_file = True
                host = "localhost"
                path = "/" + stripped
            elif rest.startswith("//"):
                parts = stripped.split("/", 1)
                host = parts[0].lower()
                path = "/" + (parts[1] if len(parts) > 1 else "")
                is_unc = host not in ("localhost", "127.0.0.1", "")
            else:
                is_local_file = True
                path = "/" + stripped
            canonical = f"file://{host}{path}"
        elif scheme in cls.MONIKER_SCHEMES:
            canonical = f"{scheme}:{rest}"
            # May contain embedded UNC paths (e.g. crumb=location:\\10.0.0.1\share)
            if "\\\\" in rest or "//" in rest:
                is_unc = True
        else:
            # Standard network URL parsing
            try:
                # If no scheme, default to http for parsing
                parse_target = clean_url if scheme else f"http://{clean_url}"
                parsed = urllib.parse.urlparse(parse_target)
                if not scheme:
                    scheme = parsed.scheme.lower()
                host = (parsed.hostname or "").lower()
                port = parsed.port
                path = parsed.path
                query = parsed.query
                fragment = parsed.fragment

                # IDN / Punycode normalization
                try:
                    host = host.encode("idna").decode("ascii")
                except Exception:
                    pass

                canonical = urllib.parse.urlunparse((
                    scheme,
                    f"{host}:{port}" if port else host,
                    path or "/",
                    parsed.params,
                    query,
                    fragment
                ))
            except Exception:
                canonical = clean_url

        return NormalizedUrl(
            original_url=raw_url,
            normalized_url=canonical,
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
            is_network_url=scheme in cls.NETWORK_SCHEMES,
            is_local_file_url=is_local_file,
            is_unc_path=is_unc,
            is_moniker_uri=is_moniker,
            is_data_uri=is_data,
            is_script_uri=is_script,
            decoding_stages=stages
        )
