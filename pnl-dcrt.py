#!/usr/bin/env python3
"""
Advanced URL / Payload / API Analyzer

Capabilities:
- URL/query/fragment inspection
- Recursive URL-decode, HTML entities, Base64, Base64URL, hex
- gzip/zlib/raw-deflate/bz2/lzma decompression
- JSON and JWT structural decoding (JWT signatures are NOT verified)
- Embedded URL/API discovery
- HTML + inline JavaScript + external JS inspection
- Recursive JS import/module discovery
- JavaScript comment mining (endpoints hidden in comments)
- Embedded page-state extraction (__NEXT_DATA__, window.__X__)
- Secret / API-key pattern scanning in source
- Source-map discovery and basic source extraction
- API call pattern detection: fetch, axios, XHR, $.ajax, XMLHttpRequest
- Request method/path/query/body/header inference from source
- Template-literal and string-concatenation endpoint reconstruction
- Firebase Realtime Database URL + SDK pattern analysis
- Firebase Firestore / Storage / Functions reference detection
- Supabase and common GraphQL detection
- Generic REST endpoint discovery
- robots.txt / sitemap discovery, technology fingerprinting, security-header audit
- API path-tree deep dive with ID-segment normalization
- Well-known/API-doc path discovery, OPTIONS method + CORS reflection checks
- Firebase RTDB full path enumeration via read-only shallow listings
- Firebase REST .json path attachment (base + dynamic path -> full endpoint)
- Literal variable substitution (${S}/${b} resolved when assigned in source)
- Optional same-origin crawl to a chosen depth
- Optional active probing of discovered endpoints (explicit --probe only)
- Optional Playwright runtime mode to observe browser network requests
- JSON report output

Safety boundary:
Static analysis never contacts anything except the supplied page and its
own assets/robots.txt. --probe performs READ-ONLY GET/OPTIONS requests
against endpoints already discovered from source, plus a single GraphQL
introspection POST when --probe is given. The tool does not brute-force,
bypass authentication, exploit security controls, or guess credentials.
Runtime mode only records network traffic generated while loading the
supplied page.

Dependencies:
  Required: requests
  Optional runtime mode: playwright

Termux:
  pip install requests
  # Optional runtime mode:
  pip install playwright
  playwright install chromium
"""

import argparse
import base64
import binascii
import bz2
import gzip
import hashlib
import html
import json
import lzma
import os
import re
import sys
import textwrap
import time
import zlib
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import (
    parse_qsl,
    quote,
    unquote,
    unquote_plus,
    urljoin,
    urlparse,
    urlunparse,
)

try:
    import requests
except ImportError:
    print("Missing dependency: requests")
    print("Install with: pip install requests")
    sys.exit(1)


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_TIMEOUT = 15
DEFAULT_MAX_DEPTH = 18
DEFAULT_MAX_NODES = 15000
DEFAULT_MAX_TEXT = 12_000_000
DEFAULT_MAX_PAGE = 8_000_000
DEFAULT_MAX_JS = 15_000_000
DEFAULT_MAX_SCRIPTS = 100
DEFAULT_MAX_IMPORTS = 150
DEFAULT_MAX_SOURCEMAP_SOURCES = 100
DEFAULT_MAX_RUNTIME_REQUESTS = 1000
DEFAULT_RUNTIME_SECONDS = 20
DEFAULT_PRINTABLE_RATIO = 0.80
DEFAULT_MAX_PROBE = 40
DEFAULT_MAX_PAGES = 10
DEFAULT_PROBE_TIMEOUT = 8

USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 12; Mobile) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Mobile Safari/537.36"
)

STATIC_ASSET_EXTENSIONS = re.compile(
    r"\.(?:png|jpg|jpeg|gif|svg|webp|ico|bmp|avif|css|woff|woff2|ttf|otf|eot)"
    r"(?:\?|#|$)",
    re.I,
)

URL_RE = re.compile(r"https?://[^\s'\"<>`\\|]+", re.I)

BASE64_RE = re.compile(r"^[A-Za-z0-9+/=_-]{12,}$")
HEX_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}){4,}$")
JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")

SCRIPT_SRC_RE = re.compile(
    r"<script\b[^>]*?\bsrc\s*=\s*(['\"])(.*?)\1",
    re.I | re.S,
)
SCRIPT_INLINE_RE = re.compile(
    r"<script\b([^>]*)>(.*?)</script>",
    re.I | re.S,
)
IMPORT_RE = re.compile(
    r"(?:import|export)\s+(?:[^;]*?from\s*)?['\"]([^'\"]+)['\"]",
    re.I,
)
DYNAMIC_IMPORT_RE = re.compile(
    r"\bimport\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",
    re.I,
)

SOURCE_MAP_RE = re.compile(
    r"(?:[#@]\s*sourceMappingURL\s*=\s*([^\s]+)|sourceMappingURL\s*[:=]\s*['\"]([^'\"]+))",
    re.I,
)

# General absolute and protocol-relative URLs
PROTOCOL_RELATIVE_RE = re.compile(r"(?<![\w/])//[^\s'\"<>`|]+")

# Common endpoint strings in JavaScript.
PATH_STRING_RE = re.compile(
    r"(['\"`])((?:/api/|/v\d+(?:/|$)|/graphql(?:/|$)|/rest/|/rpc/|/auth/|/users(?:/|$)|/login(?:/|$)|/token(?:/|$)|/data(?:/|$)|/query(?:/|$)|/search(?:/|$)|/download(?:/|$)|/upload(?:/|$)|/public/|/private/)[^'\"`\n]{0,1000})\1",
    re.I,
)

FETCH_RE = re.compile(
    r"\bfetch\s*\(\s*([^,\)]{1,400})(?:,\s*(\{.*?\}))?\s*\)",
    re.I | re.S,
)

AXIOS_RE = re.compile(
    r"\baxios\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*([^,\)]{1,500})(?:,\s*(\{.*?\}))?\s*\)",
    re.I | re.S,
)

XHR_OPEN_RE = re.compile(
    r"\.open\s*\(\s*(['\"])(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\1\s*,\s*([^,\)]{1,1000})",
    re.I | re.S,
)

AJAX_RE = re.compile(
    r"\$\.ajax\s*\(\s*(\{.*?\})\s*\)",
    re.I | re.S,
)

REQUEST_METHOD_RE = re.compile(
    r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b",
    re.I,
)

HEADER_RE = re.compile(
    r"(?:['\"])(authorization|x-api-key|api-key|content-type|accept|origin|referer)(?:['\"])\s*[:=]\s*([^,}\n]+)",
    re.I,
)

QUERY_KEY_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_.-]{0,80})=")

JSON_KEY_RE = re.compile(
    r"[\'\"]([A-Za-z_][A-Za-z0-9_.-]{0,100})[\'\"]\s*:\s*"
)

CONFIG_FIELD_NAMES = {
    "url", "baseurl", "base_url", "endpoint", "apiurl", "api_url",
    "databaseurl", "database_url", "projectid", "project_id",
    "apikey", "api_key", "key", "token", "access_token",
    "authdomain", "storagebucket", "messagingsenderid", "appid",
    "measurementid", "clientid", "client_id", "secret",
}

KEY_NAME_RE = re.compile(
    r"(?:\b(?:param|params|query|body|data|payload|headers|options)\b[^\n]{0,120})",
    re.I,
)

# Firebase domains
FIREBASE_RTDB_RE = re.compile(
    r"https?://[^/\s'\"`|]+\.(?:firebaseio\.com|firebasedatabase\.app)(?:/[^\s'\"`|]*)?",
    re.I,
)
FIREBASE_HOST_RE = re.compile(
    r"(?:[A-Za-z0-9-]+\.)?(?:firebaseio\.com|firebasedatabase\.app)",
    re.I,
)
FIREBASE_REST_RE = re.compile(
    r"https?://[^/\s'\"`|]+\.(?:firebaseio\.com|firebasedatabase\.app)(?:/[^\s'\"`|]*)?(?:\.json)?(?:\?[^\s'\"`|]*)?",
    re.I,
)
FIREBASE_DB_REF_RE = re.compile(
    r"(?:ref\s*\(|databaseURL|firebaseConfig|initializeApp|getDatabase|child\s*\(|refFromURL)\s*[\s\S]{0,400}",
    re.I,
)
FIRESTORE_RE = re.compile(
    r"(?:firestore|cloud\.googleapis\.com/v1/projects/[^\s'\"`]+/databases/|googleapis\.com/identitytoolkit)",
    re.I,
)
FIREBASE_FUNCTIONS_RE = re.compile(
    r"(?:cloudfunctions\.net|firebasefunctions|httpsCallable|onCall|functions\.httpsCallable)",
    re.I,
)
FIREBASE_STORAGE_RE = re.compile(
    r"(?:firebasestorage\.googleapis\.com|storage\.googleapis\.com|gs://)",
    re.I,
)

SUPABASE_RE = re.compile(r"https?://[a-z0-9-]+\.supabase\.co(?:/[^\s'\"`]*)?", re.I)
GRAPHQL_ENDPOINT_RE = re.compile(r"https?://[^\s'\"`]+/graphql(?:/[^\s'\"`]*)?", re.I)

# Common API-ish host/path clues
API_PATH_RE = re.compile(
    r"(?:/api(?:/|$)|/rest(?:/|$)|/rpc(?:/|$)|/graphql(?:/|$)|/v\d+(?:/|$)|/auth(?:/|$)|/oauth(?:/|$)|/token(?:/|$))",
    re.I,
)

# JavaScript string literals; intentionally conservative.
STRING_LITERAL_RE = re.compile(
    r"(['\"])(.{1,2000}?)\1",
    re.S,
)

# Basic template literal pieces.
TEMPLATE_RE = re.compile(r"`([^`]{1,5000})`", re.S)

# JS object method/body clues.
METHOD_FIELD_RE = re.compile(
    r"\bmethod\s*:\s*(['\"])(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\1",
    re.I,
)

BODY_FIELD_RE = re.compile(
    r"\b(body|data)\s*:\s*([^,}\n]{1,2000})",
    re.I | re.S,
)

# Browser network resource-like filters.
NETWORK_SCHEMES = ("http://", "https://", "ws://", "wss://")

LINK_RE = re.compile(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", re.I)

JS_BLOCK_COMMENT_RE = re.compile(r"/\*([\s\S]*?)\*/")
JS_LINE_COMMENT_RE = re.compile(r"(?<![:/])//[^\n]*")

EMBEDDED_STATE_RE = re.compile(
    r"<script[^>]*id=['\"]__NEXT_DATA__['\"][^>]*>([\s\S]*?)</script>", re.I
)
WINDOW_STATE_RE = re.compile(
    r"window\.(__[A-Za-z0-9_]*__)\s*=\s*(\{[\s\S]{0,500000}?\})\s*[;<]", re.I
)

META_GENERATOR_RE = re.compile(
    r"<meta[^>]+name=['\"]generator['\"][^>]+content=['\"]([^'\"]+)", re.I
)

SECRET_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("google_or_firebase_api_key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt_token", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("stripe_key", re.compile(r"(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{16,}")),
    (
        "generic_secret_assignment",
        re.compile(
            r"(?i)(?:api[_-]?key|apikey|secret|token|password)\s*[:=]\s*['\"]([^'\"]{8,})['\"]"
        ),
    ),
]

SECURITY_HEADERS = (
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
    "access-control-allow-origin",
)

TECH_MARKERS: List[Tuple[str, List[str]]] = [
    ("Next.js", ["__next", "/_next/", "__NEXT_DATA__"]),
    ("Nuxt", ["__NUXT__", "_nuxt/"]),
    ("React", ["data-reactroot", "react-dom", "__REACT"]),
    ("Vue", ["__vue__", "data-v-", "vue.runtime"]),
    ("Angular", ["ng-version", "ng-app", "angular.io"]),
    ("Svelte", ["svelte"]),
    ("jQuery", ["jquery"]),
    ("WordPress", ["wp-content", "wp-includes", "wordpress"]),
    ("Firebase", ["firebaseio", "firebase/app"]),
    ("Supabase", ["supabase"]),
    ("Vercel", ["x-vercel", "vercel"]),
    ("Cloudflare", ["cf-ray", "cloudflare"]),
]

UUID_SEG_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
PUSHID_SEG_RE = re.compile(r"^-[A-Za-z0-9_-]{19}$")


def normalize_path(path: str) -> Tuple[str, List[str]]:
    """Collapse ID-like segments so /users/123 and /users/456 group together."""
    params: List[str] = []
    out: List[str] = []
    for seg in (path or "/").split("/"):
        if not seg:
            out.append("")
            continue
        if seg.isdigit():
            out.append("{num}")
            params.append(seg)
        elif UUID_SEG_RE.match(seg):
            out.append("{uuid}")
            params.append(seg)
        elif PUSHID_SEG_RE.match(seg):
            out.append("{pushid}")
            params.append(seg)
        elif len(seg) >= 20 and re.fullmatch(r"[0-9a-fA-F]+", seg):
            out.append("{hash}")
            params.append(seg)
        elif (
            len(seg) >= 16
            and re.fullmatch(r"[A-Za-z0-9_-]+", seg)
            and re.search(r"\d", seg)
            and re.search(r"[A-Za-z]", seg)
        ):
            out.append("{token}")
            params.append(seg)
        else:
            out.append(seg)
    pattern = "/".join(out) or "/"
    return pattern, params


WELLKNOWN_PATHS = [
    "/api", "/api/v1", "/api/v2", "/v1", "/v2", "/v3",
    "/rest", "/rest/v1", "/rpc", "/graphql", "/graphiql", "/playground",
    "/swagger.json", "/swagger.yaml", "/swagger.yml", "/openapi.json",
    "/api-docs", "/api/docs", "/docs", "/redoc", "/redoc.html",
    "/health", "/healthz", "/status", "/version", "/metrics",
    "/.well-known/openid-configuration", "/.well-known/security.txt",
    "/.well-known/assetlinks.json", "/sitemap.xml", "/.git/HEAD",
]

NOISE_HOST_RE = re.compile(r"(?:^|\.)(?:w3\.org|schema\.org|react\.dev)$", re.I)
PLACEHOLDER_HOST_RE = re.compile(r"your-project|(?:^|\.)example\.(?:com|org|net)$", re.I)
FIREBASE_JSON_TMPL_RE = re.compile(r"`([^`\n]{1,400}\.json(?:\?[^`\n]{0,200})?)`")
BARE_IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$")
LEADING_PLACEHOLDER_RE = re.compile(r"^\s*(?:\$\{[^}]*\}|\{[^}]*\})\s*/")
DYNAMIC_PLACEHOLDER_RE = re.compile(r"\$\{|\{[A-Za-z_$]")
VAR_ASSIGN_RE = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(['\"`])((?:(?!\2)[^\n]){1,300})\2")
# ============================================================
# DATA CLASSES
# ============================================================

@dataclass
class Endpoint:
    url: str
    api_type: str
    method: Optional[str] = None
    path: str = ""
    query: Dict[str, List[str]] = field(default_factory=dict)
    inferred_query_parameters: List[str] = field(default_factory=list)
    body_keys: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    source: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    confidence: str = "medium"
    runtime: bool = False

    def as_dict(self):
        return {
            "url": self.url,
            "api_type": self.api_type,
            "method": self.method,
            "path": self.path,
            "path_pattern": normalize_path(self.path)[0],
            "query": self.query,
            "inferred_query_parameters": sorted(set(self.inferred_query_parameters)),
            "body_keys": sorted(set(self.body_keys)),
            "headers": self.headers,
            "source": sorted(set(self.source)),
            "evidence": sorted(set(self.evidence)),
            "confidence": self.confidence,
            "runtime": self.runtime,
        }


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def trim_value(value: Any, limit: int = 3000) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "…"
    return value


def _short(value: Any, limit: int = 110) -> str:
    """Console-only truncation; JSON report always keeps full values."""
    s = str(value)
    return s if len(s) <= limit else s[:limit] + "…"


def safe_text(data: bytes, max_len: int = DEFAULT_MAX_TEXT, ratio: float = DEFAULT_PRINTABLE_RATIO) -> Optional[str]:
    if not isinstance(data, (bytes, bytearray)):
        return None
    if len(data) > max_len:
        return None
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        text = bytes(data).decode("utf-8", errors="replace")
    if not text:
        return None
    printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    if printable / max(len(text), 1) < ratio:
        return None
    return text


def normalize_b64(value: str) -> str:
    value = re.sub(r"\s+", "", value.strip())
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    value = value.replace("-", "+").replace("_", "/")
    pad = len(value) % 4
    if pad:
        value += "=" * (4 - pad)
    return value


def decode_b64(value: str) -> Optional[Any]:
    normalized = normalize_b64(value)
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = fn(normalized, validate=True) if fn is base64.b64decode else fn(normalized)
            text = safe_text(raw)
            return text if text is not None else raw
        except Exception:
            continue
    return None


def decode_hex(value: str) -> Optional[Any]:
    try:
        raw = bytes.fromhex(value)
        text = safe_text(raw)
        return text if text is not None else raw
    except Exception:
        return None


def decompress_bytes(raw: bytes, max_output: int) -> List[Tuple[str, bytes]]:
    out = []
    funcs = []
    try:
        funcs.append(("gzip", gzip.decompress(raw)))
    except Exception:
        pass
    try:
        funcs.append(("zlib", zlib.decompress(raw)))
    except Exception:
        pass
    try:
        obj = zlib.decompressobj(-zlib.MAX_WBITS)
        funcs.append(("raw-deflate", obj.decompress(raw) + obj.flush()))
    except Exception:
        pass
    try:
        funcs.append(("bz2", bz2.decompress(raw)))
    except Exception:
        pass
    try:
        funcs.append(("lzma", lzma.decompress(raw)))
    except Exception:
        pass
    for name, data in funcs:
        if len(data) <= max_output:
            out.append((name, data))
    return out


def maybe_json(value: str) -> Optional[Any]:
    value = value.strip()
    if not value or value[0] not in "[{\"":
        return None
    try:
        return json.loads(value)
    except Exception:
        return None


def canonical(value: Any) -> str:
    if isinstance(value, bytes):
        return "bytes:" + hashlib.sha256(value).hexdigest()
    if isinstance(value, str):
        return "str:" + value
    try:
        return "json:" + json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    except Exception:
        return repr(value)


def clean_url(url: str) -> str:
    url = html.unescape(url.strip())
    url = url.rstrip(".,;:)]}>\'\"`")
    return url


def extract_urls(text: str) -> List[str]:
    found = set()
    for m in URL_RE.finditer(text):
        found.add(clean_url(m.group(0)))
    for m in PROTOCOL_RELATIVE_RE.finditer(text):
        raw = m.group(0)
        if len(raw) > 2:
            found.add(clean_url("https:" + raw))
    return sorted(found)


def parse_query(url: str) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = defaultdict(list)
    try:
        pairs = parse_qsl(urlparse(url).query, keep_blank_values=True)
        for k, v in pairs:
            if v not in result[k]:
                result[k].append(v)
    except Exception:
        pass
    return dict(result)


def endpoint_type(url: str) -> str:
    low = url.lower()
    host = urlparse(url).netloc.lower()
    if "firebaseio.com" in host or "firebasedatabase.app" in host:
        return "Firebase Realtime Database"
    if "firebasestorage.googleapis.com" in low or "storage.googleapis.com" in low or low.startswith("gs://"):
        return "Firebase Storage / GCS"
    if "cloudfunctions.net" in host or "httpscallable" in low:
        return "Firebase Functions"
    if "supabase.co" in host:
        return "Supabase"
    if "/graphql" in low or low.endswith("graphql"):
        return "GraphQL"
    if API_PATH_RE.search(low):
        return "REST API"
    return "HTTP API"


def confidence_score(evidence: List[str], runtime: bool = False) -> str:
    score = 0
    joined = " ".join(evidence).lower()
    if runtime:
        score += 6
    if "fetch" in joined or "axios" in joined or "xhr" in joined or "ajax" in joined:
        score += 3
    if ".json" in joined or "firebase" in joined:
        score += 2
    if "api/" in joined or "graphql" in joined:
        score += 2
    if "query parameter" in joined or "body key" in joined:
        score += 1
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def redact_secretish(value: str) -> str:
    """Avoid displaying obvious secret-bearing header values."""
    value = value.strip()
    if len(value) > 200:
        return f"[REDACTED length={len(value)}]"
    if re.search(r"(?:bearer|token|secret|api[_-]?key|authorization)", value, re.I):
        return "[REDACTED]"
    return value


def reconstruct_expression(expr: str) -> str:
    """
    Best-effort endpoint reconstruction for concatenations and simple templates.
    It intentionally leaves dynamic expressions as placeholders.
    """
    expr = expr.strip()
    if not expr:
        return expr

    # Strip balanced surrounding parentheses.
    for _ in range(3):
        if expr.startswith("(") and expr.endswith(")"):
            expr = expr[1:-1].strip()
        else:
            break

    # Simple quoted literal.
    if len(expr) >= 2 and expr[0] == expr[-1] and expr[0] in "'\"`":
        inner = expr[1:-1]
        inner = re.sub(r"\$\{([^}]+)\}", lambda m: "${" + m.group(1).strip() + "}", inner)
        return inner

    # String concatenation.
    parts = re.split(r"\s*\+\s*", expr)
    if len(parts) > 1:
        out = []
        for part in parts:
            p = part.strip()
            if len(p) >= 2 and p[0] == p[-1] and p[0] in "'\"`":
                out.append(p[1:-1])
            elif re.fullmatch(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*", p):
                out.append("{" + p + "}")
            else:
                out.append("{" + p[:200] + "}")
        return "".join(out)

    return expr[:1500]


def _substitute_vars(s: str, varmap: Dict[str, str]) -> str:
    """Replace ${VAR} / {VAR} placeholders with known literal values."""
    if not s or not varmap:
        return s
    for name, val in varmap.items():
        if name not in s:
            continue
        s = s.replace("${" + name + "}", val)
        s = re.sub(r"\$\{\s*" + re.escape(name) + r"\s*\}", val, s)
        s = s.replace("{" + name + "}", val)
    return s


def _short_mid(value: Any, head: int = 65, tail: int = 35) -> str:
    """Truncate the middle, keeping both the head and the distinctive tail."""
    s = str(value)
    if len(s) <= head + tail + 1:
        return s
    return s[:head] + "…" + s[-tail:]


# ============================================================
# ANALYZER
# ============================================================

class AdvancedAnalyzer:
    def __init__(self, timeout: int, max_depth: int, max_nodes: int):
        self.timeout = timeout
        self.max_depth = max_depth
        self.max_nodes = max_nodes

        self.seen_values: Set[str] = set()
        self.nodes = 0

        self.discovered_urls: Set[str] = set()
        self.endpoints: Dict[str, Endpoint] = {}
        self.firebase: Dict[str, Dict[str, Any]] = {}
        self.files: Dict[str, Dict[str, Any]] = {}
        self.inline_sources: List[Dict[str, Any]] = []
        self.source_maps: Dict[str, Dict[str, Any]] = {}
        self.evidence: List[Dict[str, Any]] = []
        self.parameters: Set[str] = set()
        self.body_keys: Set[str] = set()
        self.methods: Set[str] = set()
        self.headers: Dict[str, Dict[str, Any]] = {}
        self.config_fields: Set[str] = set()
        self.api_configs: List[Dict[str, Any]] = []
        self.runtime_requests: List[Dict[str, Any]] = []
        self.runtime_enabled = False
        self.firebase_bases_global: Set[str] = set()
        self.secrets: List[Dict[str, Any]] = []
        self.embedded_states: List[Dict[str, Any]] = []
        self._secret_seen: Set[str] = set()
        self._secret_counts: Dict[str, int] = defaultdict(int)

    # --------------------------------------------------------
    # ENDPOINT REGISTRATION
    # --------------------------------------------------------

    def register_endpoint(
        self,
        url: str,
        source: str,
        method: Optional[str] = None,
        evidence: Optional[List[str]] = None,
        body_keys: Optional[List[str]] = None,
        headers: Optional[Dict[str, str]] = None,
        inferred_query: Optional[List[str]] = None,
        runtime: bool = False,
    ):
        if not isinstance(url, str):
            return
        url = clean_url(url)
        if not url:
            return
        if url.startswith("//"):
            url = "https:" + url
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ("http", "https"):
            return
        host = parsed.netloc.lower()
        if NOISE_HOST_RE.search(host) or PLACEHOLDER_HOST_RE.search(host):
            return
        if STATIC_ASSET_EXTENSIONS.search(url) and not API_PATH_RE.search(parsed.path):
            return

        key = url
        if key not in self.endpoints:
            self.endpoints[key] = Endpoint(
                url=url,
                api_type=endpoint_type(url),
                method=None,
                path=parsed.path or "/",
                query=parse_query(url),
            )

        ep = self.endpoints[key]
        if method:
            method = method.upper()
            ep.method = ep.method or method
            self.methods.add(method)
        if source:
            ep.source.append(source)
        if evidence:
            ep.evidence.extend(evidence)
        if body_keys:
            ep.body_keys.extend(body_keys)
            self.body_keys.update(body_keys)
        if inferred_query:
            ep.inferred_query_parameters.extend(inferred_query)
            self.parameters.update(inferred_query)
        if headers:
            for hk, hv in headers.items():
                ep.headers[hk.lower()] = hv
        ep.runtime = ep.runtime or runtime
        ep.confidence = confidence_score(ep.evidence, ep.runtime)

        self.discovered_urls.add(url)
        self.analyze_firebase_url(url, source)
    # --------------------------------------------------------
    # FIREBASE
    # --------------------------------------------------------

    def analyze_firebase_url(self, url: str, source: str = ""):
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        is_rtdb = "firebaseio.com" in host or "firebasedatabase.app" in host
        if not is_rtdb:
            return

        base = f"{parsed.scheme}://{parsed.netloc}"
        self.firebase_bases_global.add(base)
        item = self.firebase.setdefault(
            base,
            {
                "base_url": base,
                "paths": set(),
                "observed_query_parameters": set(),
                "sources": set(),
                "sdk_evidence": [],
            },
        )
        item["paths"].add(parsed.path or "/")
        for key in parse_query(url):
            item["observed_query_parameters"].add(key)
        if source:
            item["sources"].add(source)

    def analyze_firebase_text(self, text: str, source: str):
        for m in FIREBASE_RTDB_RE.finditer(text):
            url = clean_url(m.group(0))
            self.register_endpoint(
                url,
                source=source,
                evidence=["Firebase Realtime Database URL literal"],
            )

        for m in FIREBASE_REST_RE.finditer(text):
            url = clean_url(m.group(0))
            # A Firebase base URL alone does not prove the HTTP method.
            # A `.json` REST path is a concrete endpoint shape, but method
            # is still left unknown unless source/runtime evidence provides it.
            method = "GET" if re.search(r"\.json(?:\?|$)", url, re.I) else None
            self.register_endpoint(
                url,
                source=source,
                method=method,
                evidence=[
                    "Firebase REST endpoint URL" if method else
                    "Firebase Realtime Database URL"
                ],
            )

        if FIREBASE_DB_REF_RE.search(text):
            self.evidence.append({
                "source": source,
                "type": "firebase_rtdb_sdk_reference",
                "details": "Realtime Database SDK reference/configuration pattern detected",
            })

        if FIRESTORE_RE.search(text):
            self.evidence.append({
                "source": source,
                "type": "firebase_firestore_reference",
                "details": "Firestore-related reference detected",
            })

        if FIREBASE_FUNCTIONS_RE.search(text):
            self.evidence.append({
                "source": source,
                "type": "firebase_functions_reference",
                "details": "Firebase Functions/callable reference detected",
            })

        if FIREBASE_STORAGE_RE.search(text):
            self.evidence.append({
                "source": source,
                "type": "firebase_storage_reference",
                "details": "Firebase Storage/GCS reference detected",
            })

    def firebase_bases_in_text(self, text: str) -> List[str]:
        bases = []
        for m in FIREBASE_RTDB_RE.finditer(text):
            try:
                for piece in m.group(0).split("|"):
                    piece = piece.strip()
                    if not piece:
                        continue
                    p = urlparse(clean_url(piece))
                    base = f"{p.scheme}://{p.netloc}".rstrip("/")
                    if base.startswith(("http://", "https://")) and base not in bases:
                        bases.append(base)
            except Exception:
                continue
        return bases

    def _attach_firebase_json(
        self,
        built: str,
        method: Optional[str],
        source: str,
        fb_bases: List[str],
        headers: Optional[Dict[str, str]] = None,
        body_keys: Optional[List[str]] = None,
        via: str = "fetch() call",
        varmap: Optional[Dict[str, str]] = None,
    ) -> bool:
        """
        Attach a dynamic `.json` path expression to every discovered Firebase
        base, e.g. `${url}/${S}/${b}.json?auth=...` becomes
        `https://<base>/${S}/${b}.json?auth=...`. Known variable literals
        are substituted first. Returns True when attached.
        """
        e = (built or "").strip()
        for _ in range(3):
            if e.startswith("(") and e.endswith(")"):
                e = e[1:-1].strip()
            else:
                break
        if len(e) >= 2 and e[0] == e[-1] and e[0] in "'\"`":
            e = e[1:-1]
        if ".json" not in e.lower():
            return False
        if e.startswith(("http://", "https://", "//")):
            return False
        if varmap:
            e = _substitute_vars(e, varmap)
        # A leading base-variable placeholder proves Firebase shape even if
        # everything else resolved to literals.
        had_leading_base = bool(LEADING_PLACEHOLDER_RE.match(e))
        # Drop ONE leading base-variable placeholder: ${url}/... -> ...
        # (only one: the rest of the segments are the real REST path).
        e = LEADING_PLACEHOLDER_RE.sub("", e, count=1)
        # Only dynamic paths belong to a Firebase base; static local
        # .json files stay on the page host.
        if not DYNAMIC_PLACEHOLDER_RE.search(e) and not had_leading_base:
            return False
        path = e if e.startswith("/") else "/" + e
        if not path:
            return False
        attached = False
        for base in fb_bases:
            full = base.rstrip("/") + path
            if not full.startswith(("http://", "https://")):
                continue
            self.register_endpoint(
                full,
                source=source,
                method=method,
                evidence=[via, "Firebase REST .json path attached to discovered base"],
                body_keys=body_keys,
                inferred_query=self.extract_query_parameters(full),
                headers=headers or {},
            )
            attached = True
        return attached

    def _sweep_firebase_templates(self, text: str, source: str, fb_bases: List[str], varmap: Optional[Dict[str, str]] = None):
        seen: Set[str] = set()
        for m in FIREBASE_JSON_TMPL_RE.finditer(text):
            inner = m.group(1)
            if inner.startswith(("http://", "https://")):
                continue
            if inner in seen:
                continue
            seen.add(inner)
            self._attach_firebase_json(
                inner, None, f"{source}:template", fb_bases, via="template literal",
                varmap=varmap,
            )

    # --------------------------------------------------------
    # API PARAMETER/BODY ANALYSIS
    # --------------------------------------------------------

    def extract_body_keys(self, fragment: str) -> List[str]:
        keys = set()
        for m in JSON_KEY_RE.finditer(fragment):
            keys.add(m.group(1))
        return sorted(keys)

    def extract_query_parameters(self, text: str) -> List[str]:
        keys = set(m.group(1) for m in QUERY_KEY_RE.finditer(text))
        return sorted(keys)

    def extract_headers(self, text: str) -> Dict[str, str]:
        found = {}
        for m in HEADER_RE.finditer(text):
            name = m.group(1).lower()
            value = m.group(2).strip()
            found[name] = redact_secretish(value)
            self.headers[name] = {"present": True, "value_redacted": name in {"authorization", "x-api-key", "api-key"}}
        return found

    # --------------------------------------------------------
    # CONFIG / PAYLOAD PARAMETER ANALYSIS
    # --------------------------------------------------------

    def extract_config_fields(self, text: str, source: str):
        """
        Identify application configuration fields from object-like source.
        These are NOT automatically HTTP query parameters.
        """
        found = []
        for m in JSON_KEY_RE.finditer(text):
            key = m.group(1)
            normalized = re.sub(r"[^a-z0-9_]", "", key.lower())
            if normalized in CONFIG_FIELD_NAMES:
                self.config_fields.add(key)
                found.append(key)

        # Capture a compact window around likely config objects.
        if found:
            unique = sorted(set(found))
            self.api_configs.append({
                "source": source,
                "fields": unique,
                "field_count": len(unique),
            })

        return sorted(set(found))

    def extract_var_literals(self, text: str) -> Dict[str, str]:
        """Collect `const/let/var NAME = "literal"` assignments for substitution."""
        varmap: Dict[str, str] = {}
        for m in VAR_ASSIGN_RE.finditer(text):
            if len(varmap) >= 300:
                break
            name, val = m.group(1), m.group(3)
            if name in varmap or "\n" in val:
                continue
            varmap[name] = val
        return varmap

    # --------------------------------------------------------
    # TEXT ANALYSIS
    # --------------------------------------------------------

    def analyze_text(
        self,
        text: str,
        source: str,
        base_url: Optional[str] = None,
        depth: int = 0,
    ):
        if not isinstance(text, str):
            return
        if depth > self.max_depth:
            return
        if len(text) > DEFAULT_MAX_JS:
            text = text[:DEFAULT_MAX_JS]

        self.extract_config_fields(text, source)
        self.scan_secrets(text, source)

        # URLs
        for url in extract_urls(text):
            absolute = urljoin(base_url, url) if base_url else url
            self.register_endpoint(
                absolute,
                source=source,
                evidence=["URL literal/reference"],
            )

        # API technology markers
        for m in SUPABASE_RE.finditer(text):
            self.register_endpoint(
                clean_url(m.group(0)),
                source=source,
                evidence=["Supabase URL"],
            )
        for m in GRAPHQL_ENDPOINT_RE.finditer(text):
            self.register_endpoint(
                clean_url(m.group(0)),
                source=source,
                method="POST",
                evidence=["GraphQL endpoint pattern"],
            )

        self.analyze_firebase_text(text, source)

        # Firebase bases known from ANY source so far (payloads, pages, JS),
        # so dynamic `.json` paths attach even when the base was decoded
        # from a different text than the fetch() call.
        fb_bases = sorted(self.firebase_bases_global)
        if not fb_bases and ".json" in text.lower():
            fb_bases = self.firebase_bases_in_text(text)

        # Literal variable values, for resolving templates like `${S}/${b}`.
        varmap: Dict[str, str] = {}
        if re.search(r"\b(?:const|let|var)\s+[A-Za-z_$]", text):
            varmap = self.extract_var_literals(text)

        # Query parameters anywhere in source.
        query_params = self.extract_query_parameters(text)
        self.parameters.update(query_params)

        # Explicit headers.
        headers = self.extract_headers(text)

        # HTTP verbs.
        for m in REQUEST_METHOD_RE.finditer(text):
            self.methods.add(m.group(1).upper())

        # fetch(...)
        for m in FETCH_RE.finditer(text):
            expr = m.group(1).strip()
            if BARE_IDENTIFIER_RE.match(expr):
                continue
            options = m.group(2) or ""
            method = None
            mm = METHOD_FIELD_RE.search(options)
            if mm:
                method = mm.group(2).upper()
            body_fragment = ""
            bm = BODY_FIELD_RE.search(options)
            if bm:
                body_fragment = bm.group(2)
            built = reconstruct_expression(expr)
            if varmap:
                built = _substitute_vars(built, varmap)
            if fb_bases and self._attach_firebase_json(
                built,
                method or ("POST" if body_fragment else None),
                f"{source}:fetch",
                fb_bases,
                headers,
                body_keys=self.extract_body_keys(body_fragment),
                via="fetch() call",
                varmap=varmap,
            ):
                continue
            url_candidate = self._make_absolute(built, base_url)
            body_keys = self.extract_body_keys(body_fragment)
            inferred = self.extract_query_parameters(url_candidate)
            self.register_endpoint(
                url_candidate,
                source=f"{source}:fetch",
                method=method or ("POST" if body_fragment else "GET"),
                evidence=["fetch() call"],
                body_keys=body_keys,
                headers=headers,
                inferred_query=inferred,
            )

        # axios.*
        for m in AXIOS_RE.finditer(text):
            method = m.group(1).upper()
            raw_ax = m.group(2).strip()
            if BARE_IDENTIFIER_RE.match(raw_ax):
                continue
            expr = reconstruct_expression(raw_ax)
            if varmap:
                expr = _substitute_vars(expr, varmap)
            options_ax = m.group(3) or ""
            if fb_bases and self._attach_firebase_json(
                expr,
                method,
                f"{source}:axios",
                fb_bases,
                headers,
                body_keys=self.extract_body_keys(options_ax),
                via="axios method call",
                varmap=varmap,
            ):
                continue
            url_candidate = self._make_absolute(expr, base_url)
            options = m.group(3) or ""
            body_keys = self.extract_body_keys(options)
            inferred = self.extract_query_parameters(url_candidate)
            self.register_endpoint(
                url_candidate,
                source=f"{source}:axios",
                method=method,
                evidence=["axios method call"],
                body_keys=body_keys,
                headers=headers,
                inferred_query=inferred,
            )

        # XMLHttpRequest.open(...)
        for m in XHR_OPEN_RE.finditer(text):
            method = m.group(2).upper()
            raw_xhr = m.group(3).strip()
            if BARE_IDENTIFIER_RE.match(raw_xhr):
                continue
            expr = reconstruct_expression(raw_xhr)
            if varmap:
                expr = _substitute_vars(expr, varmap)
            if fb_bases and self._attach_firebase_json(
                expr, method, f"{source}:xhr", fb_bases, headers,
                via="XMLHttpRequest.open()",
                varmap=varmap,
            ):
                continue
            url_candidate = self._make_absolute(expr, base_url)
            self.register_endpoint(
                url_candidate,
                source=f"{source}:xhr",
                method=method,
                evidence=["XMLHttpRequest.open()"],
                headers=headers,
                inferred_query=self.extract_query_parameters(url_candidate),
            )

        # $.ajax({...})
        for m in AJAX_RE.finditer(text):
            block = m.group(1)
            mm = re.search(r"\btype\s*:\s*['\"](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['\"]", block, re.I)
            um = re.search(r"\burl\s*:\s*([^,}\n]+)", block, re.I)
            method = mm.group(1).upper() if mm else None
            if um:
                raw_ajax = um.group(1).strip()
                if BARE_IDENTIFIER_RE.match(raw_ajax):
                    continue
                expr = reconstruct_expression(raw_ajax)
                if varmap:
                    expr = _substitute_vars(expr, varmap)
                ajax_body = self.extract_body_keys(block)
                if fb_bases and self._attach_firebase_json(
                    expr, method or "GET", f"{source}:jquery-ajax", fb_bases,
                    headers, body_keys=ajax_body, via="$.ajax() call",
                    varmap=varmap,
                ):
                    continue
                url_candidate = self._make_absolute(expr, base_url)
                body_keys = ajax_body
                self.register_endpoint(
                    url_candidate,
                    source=f"{source}:jquery-ajax",
                    method=method or "GET",
                    evidence=["$.ajax() call"],
                    body_keys=body_keys,
                    headers=headers,
                    inferred_query=self.extract_query_parameters(url_candidate),
                )

        # Standalone Firebase .json templates (assigned to vars, etc.).
        if fb_bases:
            self._sweep_firebase_templates(text, source, fb_bases, varmap)

        # Obvious path-like strings.
        for m in PATH_STRING_RE.finditer(text):
            path = m.group(2)
            if base_url:
                absolute = urljoin(base_url, path)
            else:
                absolute = path
            if absolute.startswith(("http://", "https://")):
                self.register_endpoint(
                    absolute,
                    source=f"{source}:path-literal",
                    evidence=["API-like path literal"],
                    inferred_query=self.extract_query_parameters(absolute),
                )

        # String-literal URLs, including concatenated fragments.
        self._analyze_string_literals(text, source, base_url)

        # JSON-looking body/query keys around common request constructs.
        if "firebase" in text.lower():
            self.evidence.append({
                "source": source,
                "type": "firebase_general",
                "details": "Firebase-related code/text detected",
            })

        if "graphql" in text.lower() or re.search(r"\b(?:query|mutation)\s*\{", text, re.I):
            self.evidence.append({
                "source": source,
                "type": "graphql_general",
                "details": "GraphQL-related code/text detected",
            })

        self._analyze_comments(text, source, base_url, depth)
        if "<script" in text and ("__NEXT_DATA__" in text or "window.__" in text):
            self._analyze_embedded_state(text, source, depth)

    def scan_secrets(self, text: str, source: str):
        if not isinstance(text, str) or not text:
            return
        if len(text) > DEFAULT_MAX_JS:
            text = text[:DEFAULT_MAX_JS]
        for name, pattern in SECRET_PATTERNS:
            for m in pattern.finditer(text):
                value = m.group(0)
                if m.lastindex:
                    value = m.group(1) or value
                digest = hashlib.sha1((name + value).encode("utf-8", "ignore")).hexdigest()
                if digest in self._secret_seen:
                    continue
                bucket = f"{source}|{name}"
                if self._secret_counts[bucket] >= 5:
                    continue
                self._secret_seen.add(digest)
                self._secret_counts[bucket] += 1
                self.secrets.append({
                    "type": name,
                    "source": source,
                    "preview": (value[:6] + "…") if len(value) > 6 else "***",
                    "length": len(value),
                })

    def _analyze_comments(self, text: str, source: str, base_url: Optional[str], depth: int):
        candidates: List[str] = []
        candidates.extend(m.group(1) for m in JS_BLOCK_COMMENT_RE.finditer(text))
        candidates.extend(m.group(0) for m in JS_LINE_COMMENT_RE.finditer(text))
        seen: Set[str] = set()
        for comment in candidates[:200]:
            c = comment.strip()
            if len(c) < 8:
                continue
            low = c.lower()
            if not (
                URL_RE.search(c)
                or API_PATH_RE.search(c)
                or "http" in low
                or "/api" in low
                or "token" in low
                or "key" in low
                or "secret" in low
            ):
                continue
            h = hashlib.sha1(c.encode("utf-8", "ignore")).hexdigest()[:16]
            if h in seen:
                continue
            seen.add(h)
            self.analyze_text(c, f"{source}:comment", base_url=base_url, depth=depth + 1)

    def _analyze_embedded_state(self, text: str, source: str, depth: int):
        for m in EMBEDDED_STATE_RE.finditer(text):
            obj = maybe_json(m.group(1))
            if obj is not None:
                self.embedded_states.append({
                    "source": source,
                    "type": "__NEXT_DATA__",
                    "top_level_keys": sorted(obj.keys())[:50] if isinstance(obj, dict) else None,
                })
                self.walk(obj, f"{source}:__NEXT_DATA__", depth + 1)
        for m in WINDOW_STATE_RE.finditer(text):
            obj = maybe_json(m.group(2))
            if obj is not None:
                self.embedded_states.append({
                    "source": source,
                    "type": m.group(1),
                    "top_level_keys": sorted(obj.keys())[:50] if isinstance(obj, dict) else None,
                })
                self.walk(obj, f"{source}:{m.group(1)}", depth + 1)

    def _make_absolute(self, value: str, base_url: Optional[str]) -> str:
        value = value.strip()
        if value.startswith("http://") or value.startswith("https://"):
            return value
        if value.startswith("//"):
            return "https:" + value
        if base_url and value.startswith(("/", "./", "../")):
            return urljoin(base_url, value)
        if base_url and not value.startswith(("{", "[")):
            # For relative endpoint strings such as "api/users"
            # urljoin handles both root and relative forms.
            return urljoin(base_url, value)
        return value

    def _analyze_string_literals(self, text: str, source: str, base_url: Optional[str]):
        for m in STRING_LITERAL_RE.finditer(text):
            value = m.group(2).strip()
            low = value.lower()
            if value.startswith(("http://", "https://", "//")):
                self.register_endpoint(
                    self._make_absolute(value, base_url),
                    source=f"{source}:string-literal",
                    evidence=["URL string literal"],
                    inferred_query=self.extract_query_parameters(value),
                )
            elif API_PATH_RE.search(value) or FIREBASE_HOST_RE.search(value):
                abs_url = self._make_absolute(value, base_url)
                if abs_url.startswith(("http://", "https://")):
                    self.register_endpoint(
                        abs_url,
                        source=f"{source}:string-literal",
                        evidence=["API-like string literal"],
                        inferred_query=self.extract_query_parameters(value),
                    )
            elif "firebaseio.com" in low or "firebasedatabase.app" in low:
                for u in extract_urls(value):
                    self.register_endpoint(
                        u,
                        source=f"{source}:firebase-string",
                        evidence=["Firebase URL string"],
                    )
    # --------------------------------------------------------
    # RECURSIVE PAYLOAD DECODING
    # --------------------------------------------------------

    def walk(self, value: Any, path: str = "root", depth: int = 0) -> Dict[str, Any]:
        if self.nodes >= self.max_nodes:
            return {"path": path, "limit": "max_nodes"}
        self.nodes += 1
        if depth > self.max_depth:
            return {"path": path, "limit": "max_depth"}

        cid = canonical(value)
        if cid in self.seen_values:
            return {"path": path, "duplicate": True}
        self.seen_values.add(cid)

        node: Dict[str, Any] = {"path": path, "original": trim_value(value)}

        if isinstance(value, dict):
            node["type"] = "object"
            children = []
            for key, child in value.items():
                children.append(self.walk(child, f"{path}.{key}", depth + 1))
            node["children"] = children
            return node

        if isinstance(value, list):
            node["type"] = "array"
            children = []
            for i, child in enumerate(value):
                children.append(self.walk(child, f"{path}[{i}]", depth + 1))
            node["children"] = children
            return node

        if isinstance(value, (bytes, bytearray)):
            node["type"] = "bytes"
            compressed = []
            for method, raw in decompress_bytes(bytes(value), DEFAULT_MAX_TEXT):
                txt = safe_text(raw)
                entry = {"encoding": method, "value": trim_value(txt if txt is not None else raw.hex())}
                compressed.append(entry)
                if txt is not None:
                    self.analyze_text(txt, f"{path}:{method}")
                    node.setdefault("children", []).append(
                        self.walk(txt, f"{path}->{method}", depth + 1)
                    )
            if compressed:
                node["decompression"] = compressed
            return node

        if not isinstance(value, str):
            node["type"] = type(value).__name__
            return node

        if len(value) > DEFAULT_MAX_TEXT:
            node["type"] = "string"
            node["limit"] = "string_too_large"
            return node

        current = value.strip()
        node["type"] = "string"

        self.analyze_text(current, path)

        children = []

        # HTML entities
        decoded_html = html.unescape(current)
        if decoded_html != current:
            children.append(self.walk(decoded_html, f"{path}->html", depth + 1))

        # Percent/plus URL decoding
        decoded_url = unquote_plus(current)
        if decoded_url != current:
            children.append(self.walk(decoded_url, f"{path}->url-decode", depth + 1))

        # JSON
        obj = maybe_json(current)
        if obj is not None:
            children.append(self.walk(obj, f"{path}->json", depth + 1))

        # JWT structural decode
        if JWT_RE.fullmatch(current):
            parts = current.split(".")
            jwt_node: Dict[str, Any] = {"type": "jwt", "signature_verified": False}
            for label, part in (("header", parts[0]), ("payload", parts[1])):
                decoded = decode_b64(part)
                if decoded is not None:
                    jwt_node[label] = trim_value(decoded)
                    if isinstance(decoded, str):
                        maybe = maybe_json(decoded)
                        if maybe is not None:
                            jwt_node[label + "_json"] = maybe
            node["jwt"] = jwt_node

        # HEX
        if HEX_RE.fullmatch(current) and len(current) <= DEFAULT_MAX_TEXT:
            decoded = decode_hex(current)
            if decoded is not None:
                children.append(self.walk(decoded, f"{path}->hex", depth + 1))

        # Base64
        if BASE64_RE.fullmatch(current):
            decoded = decode_b64(current)
            if decoded is not None:
                display = decoded if isinstance(decoded, str) else decoded.hex()
                node.setdefault("decodings", []).append({"encoding": "base64", "value": trim_value(display)})
                children.append(self.walk(decoded, f"{path}->base64", depth + 1))

        if children:
            node["children"] = children
        return node

    # --------------------------------------------------------
    # API PATH TREE (DEEP DIVE)
    # --------------------------------------------------------

    def build_path_tree(self) -> Dict[str, Any]:
        tree: Dict[str, Any] = {}
        for ep in self.endpoints.values():
            host = urlparse(ep.url).netloc.lower() or "(no-host)"
            pattern, params = normalize_path(ep.path)
            host_node = tree.setdefault(host, {})
            node = host_node.setdefault(pattern, {
                "pattern": pattern,
                "count": 0,
                "methods": set(),
                "param_samples": defaultdict(set),
                "example_url": ep.url,
            })
            node["count"] += 1
            if ep.method:
                node["methods"].add(ep.method)
            for i, sample in enumerate(params):
                if len(node["param_samples"][f"seg{i}"]) < 10:
                    node["param_samples"][f"seg{i}"].add(sample[:80])
        serial: Dict[str, Any] = {}
        for host, patterns in tree.items():
            serial[host] = [
                {
                    "pattern": p,
                    "count": n["count"],
                    "methods": sorted(n["methods"]),
                    "param_samples": {k: sorted(v) for k, v in n["param_samples"].items()},
                    "example_url": n["example_url"],
                }
                for p, n in sorted(patterns.items(), key=lambda kv: -kv[1]["count"])
            ]
        return serial

    # --------------------------------------------------------
    # NORMALIZED REPORT
    # --------------------------------------------------------

    def report(self) -> Dict[str, Any]:
        firebase = {}
        for base, data in self.firebase.items():
            firebase[base] = {
                "base_url": base,
                "paths": sorted(data["paths"]),
                "observed_query_parameters": sorted(data["observed_query_parameters"]),
                "sources": sorted(data["sources"]),
                "firebase_rtdb_rest_endpoint_pattern": base.rstrip("/") + "/<PATH>.json",
                "rest_urls": [base.rstrip("/") + p for p in sorted(data["paths"])],
                "common_rest_query_parameters": [
                    "auth", "access_token", "shallow", "print",
                    "format", "orderBy", "equalTo", "startAt", "endAt",
                    "limitToFirst", "limitToLast",
                ],
            }

        return {
            "endpoints": [self.endpoints[k].as_dict() for k in sorted(self.endpoints)],
            "firebase": firebase,
            "api_parameters": sorted(self.parameters),
            "request_body_keys": sorted(self.body_keys),
            "configuration_fields": sorted(self.config_fields),
            "api_configuration_objects": self.api_configs,
            "http_methods": sorted(self.methods),
            "headers": self.headers,
            "files": self.files,
            "source_maps": self.source_maps,
            "evidence": self.evidence,
            "runtime_requests": self.runtime_requests,
            "secrets": self.secrets,
            "embedded_states": self.embedded_states,
            "path_tree": self.build_path_tree(),
        }


# ============================================================
# WEB INSPECTOR
# ============================================================

class WebInspector:
    def __init__(self, analyzer: AdvancedAnalyzer, max_page: int, max_js: int, max_scripts: int, max_imports: int, max_maps: int):
        self.analyzer = analyzer
        # Compatibility alias. Both names reference the same store.
        self.js_files = self.analyzer.files
        self.max_page = max_page
        self.max_js = max_js
        self.max_scripts = max_scripts
        self.max_imports = max_imports
        self.max_maps = max_maps
        self.visited: Set[str] = set()
        self.import_seen: Set[str] = set()
        self.map_seen: Set[str] = set()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })

    def fetch(self, url: str, max_bytes: int) -> Optional[Dict[str, Any]]:
        url = clean_url(url)
        if not url or url in self.visited:
            return None
        self.visited.add(url)
        try:
            r = self.session.get(url, timeout=self.analyzer.timeout, allow_redirects=True)
            content = r.content[:max_bytes]
            encoding = r.encoding or "utf-8"
            try:
                text = content.decode(encoding, errors="replace")
            except Exception:
                text = content.decode("utf-8", errors="replace")
            return {
                "url": url,
                "final_url": r.url,
                "status": r.status_code,
                "content_type": r.headers.get("content-type", ""),
                "content_length": len(content),
                "text": text,
                "headers": {k.lower(): v for k, v in r.headers.items()},
                "cookies": sorted({c.name for c in r.cookies}),
            }
        except requests.RequestException as exc:
            return {"url": url, "error": str(exc)}

    def discover_source_map(self, text: str, owner_url: str):
        matches = SOURCE_MAP_RE.findall(text)
        for a, b in matches:
            raw = a or b
            if not raw or raw.startswith("data:"):
                self._analyze_inline_source_map(raw, owner_url)
                continue
            map_url = urljoin(owner_url, raw)
            self._fetch_source_map(map_url, owner_url)

    def _analyze_inline_source_map(self, raw: str, owner_url: str):
        if not raw.startswith("data:"):
            return
        try:
            header, payload = raw.split(",", 1)
            if ";base64" in header:
                data = base64.b64decode(payload)
                text = data.decode("utf-8", errors="replace")
            else:
                text = unquote(payload)
            obj = json.loads(text)
            self._store_source_map(owner_url, owner_url, obj)
        except Exception:
            pass

    def _fetch_source_map(self, map_url: str, owner_url: str):
        if map_url in self.map_seen or len(self.map_seen) >= self.max_maps:
            return
        self.map_seen.add(map_url)
        data = self.fetch(map_url, self.max_page)
        if not data or "text" not in data:
            return
        try:
            obj = json.loads(data["text"])
        except Exception:
            return
        self._store_source_map(owner_url, map_url, obj)

    def _store_source_map(self, owner_url: str, map_url: str, obj: Dict[str, Any]):
        sources = obj.get("sources", []) or []
        names = obj.get("names", []) or []
        content = obj.get("sourcesContent", []) or []
        self.analyzer.source_maps[owner_url] = {
            "map_url": map_url,
            "file": obj.get("file"),
            "source_root": obj.get("sourceRoot"),
            "sources_count": len(sources),
            "sources": [str(x) for x in sources[: self.max_maps]],
            "embedded_sources": sum(1 for x in content if isinstance(x, str) and x),
            "names_count": len(names),
        }
        for idx, src in enumerate(sources[: self.max_maps]):
            resolved = urljoin(map_url, str(src))
            source_text = content[idx] if idx < len(content) else None
            record = {"source": str(src), "resolved": resolved}
            if isinstance(source_text, str) and source_text:
                record["embedded"] = True
                record["size"] = len(source_text)
                self.analyzer.analyze_text(source_text, f"sourcemap:{owner_url}:{src}", base_url=resolved)
            self.analyzer.evidence.append({
                "source": owner_url,
                "type": "source_map_source",
                "details": record,
            })

    def inspect_script(self, js_url: str) -> Optional[Dict[str, Any]]:
        if len(self.import_seen) >= self.max_imports:
            return None
        self.import_seen.add(js_url)
        data = self.fetch(js_url, self.max_js)
        if not data or "text" not in data:
            return data

        text = data["text"]
        self.js_files[js_url] = {
            "status": data.get("status"),
            "size": len(text),
            "content_type": data.get("content_type", ""),
        }
        self.analyzer.analyze_text(text, js_url, base_url=data.get("final_url") or js_url)
        self.discover_source_map(text, data.get("final_url") or js_url)

        child_modules = []
        imports = []
        imports.extend(IMPORT_RE.findall(text))
        imports.extend(DYNAMIC_IMPORT_RE.findall(text))
        for src in list(dict.fromkeys(imports))[: self.max_imports]:
            if src.startswith(("http://", "https://")):
                module_url = src
            elif src.startswith("//"):
                module_url = "https:" + src
            else:
                module_url = urljoin(data.get("final_url") or js_url, src)
            if module_url.startswith(("http://", "https://")):
                child_modules.append(module_url)

        for module_url in child_modules:
            if module_url not in self.import_seen and len(self.import_seen) < self.max_imports:
                self.inspect_script(module_url)

        return {
            "url": data.get("url"),
            "final_url": data.get("final_url"),
            "status": data.get("status"),
            "size": len(text),
            "imports": child_modules,
        }

    def inspect_page(self, url: str) -> Optional[Dict[str, Any]]:
        page = self.fetch(url, self.max_page)
        if not page:
            return None
        if "text" not in page:
            return page

        final_url = page.get("final_url") or url
        text = page["text"]
        self.analyzer.analyze_text(text, final_url, base_url=final_url)
        self.discover_source_map(text, final_url)

        scripts = []
        for m in SCRIPT_SRC_RE.finditer(text):
            scripts.append(urljoin(final_url, m.group(2)))

        inline_count = 0
        for attrs, body in SCRIPT_INLINE_RE.findall(text):
            if body.strip():
                inline_count += 1
                self.analyzer.inline_sources.append({
                    "page": final_url,
                    "index": inline_count,
                    "size": len(body),
                    "attrs": attrs.strip(),
                })
                self.analyzer.analyze_text(body, f"{final_url}#inline-script-{inline_count}", base_url=final_url)
                self.discover_source_map(body, final_url)

        scripts = list(dict.fromkeys(scripts))[: self.max_scripts]
        script_results = []
        for js_url in scripts:
            item = self.inspect_script(js_url)
            if item:
                script_results.append(item)

        # HTML itself may contain relative endpoint paths and config values.
        self.analyzer.evidence.append({
            "source": final_url,
            "type": "page_summary",
            "details": {
                "scripts_discovered": len(scripts),
                "inline_scripts": inline_count,
                "title": self._extract_title(text),
            },
        })

        return {
            "url": url,
            "final_url": final_url,
            "status": page.get("status"),
            "content_type": page.get("content_type"),
            "size": len(text),
            "scripts": script_results,
            "inline_script_count": inline_count,
            "security": self._security_headers(page.get("headers", {})),
            "technology": self._detect_technology(text, page.get("headers", {}), final_url),
            "cookies": page.get("cookies", []),
        }

    @staticmethod
    def _extract_title(text: str) -> Optional[str]:
        m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        if not m:
            return None
        return re.sub(r"\s+", " ", html.unescape(m.group(1))).strip()[:500]

    @staticmethod
    def _security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
        present = {h: headers[h] for h in SECURITY_HEADERS if h in headers}
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        return {"present": present, "missing": missing}

    @staticmethod
    def _detect_technology(text: str, headers: Dict[str, str], url: str) -> Dict[str, Any]:
        low = text.lower()
        signals = sorted({name for name, markers in TECH_MARKERS if any(m.lower() in low for m in markers)})
        generator = None
        m = META_GENERATOR_RE.search(text)
        if m:
            generator = m.group(1).strip()
        return {
            "signals": signals,
            "generator": generator,
            "server": headers.get("server"),
            "powered_by": headers.get("x-powered-by"),
            "via": headers.get("via"),
        }

    def fetch_robots(self, url: str) -> Dict[str, Any]:
        robots_url = urljoin(url, "/robots.txt")
        data = self.fetch(robots_url, self.max_page)
        result = {"url": robots_url, "status": None, "sitemaps": [], "error": None}
        if not data:
            result["error"] = "not fetched"
            return result
        result["status"] = data.get("status")
        result["error"] = data.get("error")
        if data.get("status") == 200 and "text" in data:
            result["sitemaps"] = [
                line.split(":", 1)[1].strip()
                for line in data["text"].splitlines()
                if line.lower().startswith("sitemap:")
            ]
            self.analyzer.analyze_text(data["text"], robots_url, base_url=robots_url)
        return result

    def crawl(self, start_url: str, depth: int, max_pages: int) -> Dict[str, Any]:
        queue = deque([(start_url, 0)])
        origin = urlparse(start_url).netloc.lower()
        queued = {start_url}
        pages = 0
        while queue and pages < max_pages:
            url, d = queue.popleft()
            page = self.fetch(url, self.max_page)
            if not page or "text" not in page or page.get("status") != 200:
                continue
            pages += 1
            final = page.get("final_url") or url
            self.analyzer.analyze_text(page["text"], final, base_url=final)
            if d >= depth:
                continue
            for m in LINK_RE.finditer(page["text"]):
                link = urljoin(final, m.group(1).strip())
                p = urlparse(link)
                if (
                    p.scheme in ("http", "https")
                    and p.netloc.lower() == origin
                    and link not in queued
                    and link not in self.visited
                    and not STATIC_ASSET_EXTENSIONS.search(link)
                ):
                    queued.add(link)
                    queue.append((link, d + 1))
        return {"pages_visited": pages, "max_depth": depth}
# ============================================================
# RUNTIME NETWORK INSPECTOR (OPTIONAL PLAYWRIGHT)
# ============================================================

class RuntimeInspector:
    def __init__(self, analyzer: AdvancedAnalyzer, timeout_seconds: int = DEFAULT_RUNTIME_SECONDS):
        self.analyzer = analyzer
        self.timeout_seconds = timeout_seconds

    def run(self, url: str) -> Dict[str, Any]:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return {
                "enabled": False,
                "error": "Playwright not installed",
                "install": "pip install playwright && playwright install chromium",
            }

        self.analyzer.runtime_enabled = True
        captured = []
        start = time.time()

        def on_request(req):
            if len(captured) >= DEFAULT_MAX_RUNTIME_REQUESTS:
                return
            req_url = req.url
            if not req_url.startswith(NETWORK_SCHEMES):
                return
            resource_type = getattr(req, "resource_type", "")
            method = req.method
            post_data = req.post_data or ""
            headers = {}
            try:
                hdrs = req.all_headers()
                for k, v in hdrs.items():
                    if k.lower() in {"authorization", "x-api-key", "api-key"}:
                        headers[k.lower()] = "[REDACTED]"
                    elif k.lower() in {"content-type", "accept"}:
                        headers[k.lower()] = v
            except Exception:
                pass

            q = parse_query(req_url)
            body_keys = []
            if post_data:
                obj = maybe_json(post_data)
                if isinstance(obj, dict):
                    body_keys = sorted(str(k) for k in obj.keys())
                body_keys.extend(self.analyzer.extract_body_keys(post_data))

            record = {
                "url": req_url,
                "method": method,
                "resource_type": resource_type,
                "query_parameters": sorted(q.keys()),
                "query": q,
                "body_keys": sorted(set(body_keys)),
                "headers": headers,
            }
            captured.append(record)

            self.analyzer.register_endpoint(
                req_url,
                source="runtime-network",
                method=method,
                evidence=[f"browser network request ({resource_type})"],
                body_keys=body_keys,
                inferred_query=sorted(q.keys()),
                headers=headers,
                runtime=True,
            )

        errors = []
        console_messages = []

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    user_agent=USER_AGENT,
                    ignore_https_errors=True,
                )
                page = context.new_page()
                page.on("request", on_request)
                page.on("pageerror", lambda exc: errors.append(str(exc)))
                page.on("console", lambda msg: console_messages.append(msg.text) if msg.type in {"error", "warning"} else None)

                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=self.analyzer.timeout * 1000)
                except Exception as exc:
                    errors.append(f"goto: {exc}")

                # Give client-side code a brief opportunity to issue requests.
                remaining = self.timeout_seconds
                if remaining > 0:
                    page.wait_for_timeout(min(remaining * 1000, 15000))

                try:
                    title = page.title()
                except Exception:
                    title = None

                try:
                    current_url = page.url
                except Exception:
                    current_url = url

                browser.close()

        except Exception as exc:
            return {
                "enabled": True,
                "error": str(exc),
                "requests": captured,
            }

        return {
            "enabled": True,
            "elapsed_seconds": round(time.time() - start, 2),
            "final_url": current_url,
            "title": title,
            "requests": captured,
            "page_errors": errors[:100],
            "console_warnings_errors": console_messages[:100],
        }


# ============================================================
# FIREBASE RTDB PATH ENUMERATOR
# ============================================================

class FirebaseEnumerator:
    """
    Recursively list every path inside a Firebase Realtime Database
    using read-only shallow=true listings. Public databases reveal
    their full key tree; private ones return 'Permission denied'
    and are reported as not public.
    """

    def __init__(self, timeout: int = DEFAULT_PROBE_TIMEOUT, max_depth: int = 4, max_nodes: int = 2000, delay: float = 0.05):
        self.timeout = timeout
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

    def _shallow(self, base: str, path: str):
        if path:
            quoted = "/".join(quote(seg, safe="") for seg in path.split("/"))
            url = base.rstrip("/") + "/" + quoted + ".json?shallow=true"
        else:
            url = base.rstrip("/") + "/.json?shallow=true"
        try:
            r = self.session.get(url, timeout=self.timeout)
            try:
                return r.status_code, r.json(), None
            except ValueError:
                return r.status_code, None, "non-json response"
        except requests.RequestException as exc:
            return None, None, str(exc)[:200]

    def enumerate_base(self, base: str) -> Dict[str, Any]:
        start = time.time()
        result: Dict[str, Any] = {
            "base_url": base,
            "public": False,
            "status": None,
            "error": None,
            "paths": ["/"],
            "leaf_count": 0,
            "branch_count": 0,
            "nodes_visited": 0,
            "truncated": False,
            "max_depth_reached": 0,
            "leaf_samples": {},
            "elapsed_seconds": 0.0,
        }
        status, data, err = self._shallow(base, "")
        result["status"] = status
        if err and status is None:
            result["error"] = err
            result["elapsed_seconds"] = round(time.time() - start, 2)
            return result
        if status in (401, 403) or (isinstance(data, dict) and data.get("error") == "Permission denied"):
            result["error"] = "permission denied (not public)"
            result["elapsed_seconds"] = round(time.time() - start, 2)
            return result
        if status != 200 or data is None:
            result["error"] = err or f"unexpected status {status}"
            result["elapsed_seconds"] = round(time.time() - start, 2)
            return result

        result["public"] = True
        if not isinstance(data, dict) or not data:
            result["leaf_count"] = 1
            result["elapsed_seconds"] = round(time.time() - start, 2)
            return result

        seen = {""}
        queue: deque = deque()

        def expand(path: str, node: Dict[str, Any], depth: int):
            items = list(node.items())[:20000]
            if len(node) > 20000:
                result["truncated"] = True
            for key, val in items:
                child = f"{path}/{key}" if path else f"/{key}"
                if child in seen or len(result["paths"]) >= 50000:
                    if len(result["paths"]) >= 50000:
                        result["truncated"] = True
                    continue
                seen.add(child)
                result["paths"].append(child)
                if val is True:
                    result["branch_count"] += 1
                    if depth + 1 <= self.max_depth and len(seen) < self.max_nodes:
                        queue.append((child, depth + 1))
                    else:
                        result["truncated"] = True
                else:
                    result["leaf_count"] += 1
                    if (
                        len(result["leaf_samples"]) < 200
                        and isinstance(val, (str, int, float))
                        and len(str(val)) < 200
                    ):
                        result["leaf_samples"][child] = val

        result["nodes_visited"] = 1
        expand("", data, 0)
        while queue and result["nodes_visited"] < self.max_nodes:
            path, depth = queue.popleft()
            result["max_depth_reached"] = max(result["max_depth_reached"], depth)
            status, data, _err = self._shallow(base, path.lstrip("/"))
            result["nodes_visited"] += 1
            if status != 200 or not isinstance(data, dict) or not data:
                result["leaf_count"] += 1
                continue
            expand(path, data, depth)
            if self.delay:
                time.sleep(self.delay)
        if queue:
            result["truncated"] = True
        result["path_count"] = len(result["paths"])
        result["elapsed_seconds"] = round(time.time() - start, 2)
        return result


# ============================================================
# ACTIVE PROBE INSPECTOR (EXPLICIT --probe MODE)
# ============================================================

class ProbeInspector:
    """
    Active checks against endpoints WE discovered from source analysis.
    Only runs when the user passes --probe. Requests are read-only
    (GET/OPTIONS) except a single GraphQL introspection POST.
    """

    def __init__(self, analyzer: AdvancedAnalyzer, timeout: int = DEFAULT_PROBE_TIMEOUT, max_endpoints: int = DEFAULT_MAX_PROBE, firebase_depth: int = 4, firebase_max_nodes: int = 2000):
        self.analyzer = analyzer
        self.timeout = timeout
        self.max_endpoints = max_endpoints
        self.firebase_depth = firebase_depth
        self.firebase_max_nodes = firebase_max_nodes
        self.origin: Optional[str] = None
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

    def run(self, base_url: Optional[str] = None) -> Dict[str, Any]:
        out = {"endpoints": [], "firebase": [], "graphql": [], "wellknown": {}, "firebase_enum": []}
        if base_url:
            try:
                self.origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
                self.session.headers["Origin"] = self.origin
            except Exception:
                pass

        probed = 0
        for url in sorted(self.analyzer.discovered_urls):
            if probed >= self.max_endpoints:
                break
            if "{" in url or not url.startswith(("http://", "https://")):
                continue
            if STATIC_ASSET_EXTENSIONS.search(url) and not API_PATH_RE.search(urlparse(url).path):
                continue
            out["endpoints"].append(self._probe_url(url))
            probed += 1

        out["firebase"] = self._probe_firebase()
        out["graphql"] = self._probe_graphql()

        origins = []
        if self.origin:
            origins.append(self.origin)
        for ep in self.analyzer.endpoints.values():
            try:
                o = f"{urlparse(ep.url).scheme}://{urlparse(ep.url).netloc}"
                if o not in origins and o.startswith(("http://", "https://")):
                    origins.append(o)
                if len(origins) >= 3:
                    break
            except Exception:
                continue
        out["wellknown"] = self._probe_wellknown(origins)

        fbenum = FirebaseEnumerator(
            timeout=self.timeout,
            max_depth=self.firebase_depth,
            max_nodes=self.firebase_max_nodes,
        )
        out["firebase_enum"] = [fbenum.enumerate_base(b) for b in sorted(self.analyzer.firebase)[:10]]
        return out

    def _probe_url(self, url: str) -> Dict[str, Any]:
        record: Dict[str, Any] = {"url": url, "status": None, "error": None}
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True, stream=True)
            try:
                chunk = next(r.iter_content(65536), b"")
            except Exception:
                chunk = b""
            record.update({
                "status": r.status_code,
                "final_url": r.url,
                "content_type": r.headers.get("content-type", ""),
                "sampled_bytes": len(chunk),
                "access_control_allow_origin": r.headers.get("access-control-allow-origin"),
                "content_json": "json" in r.headers.get("content-type", "").lower(),
            })
            try:
                o = self.session.options(url, timeout=self.timeout, allow_redirects=True)
                record["allow"] = o.headers.get("allow")
                oacao = o.headers.get("access-control-allow-origin")
                record["acao_options"] = oacao
                record["cors_reflects_origin"] = bool(
                    oacao and (oacao == "*" or (self.origin and self.origin in oacao))
                )
            except requests.RequestException:
                pass
            r.close()
        except requests.RequestException as exc:
            record["error"] = str(exc)[:200]
        return record

    def _probe_wellknown(self, origins: List[str]) -> Dict[str, Any]:
        hits = []
        scanned = 0
        for origin in origins[:3]:
            for path in WELLKNOWN_PATHS:
                url = origin.rstrip("/") + path
                scanned += 1
                try:
                    r = self.session.get(url, timeout=self.timeout, allow_redirects=True, stream=True)
                    try:
                        chunk = next(r.iter_content(32768), b"")
                    except Exception:
                        chunk = b""
                    if r.status_code < 400:
                        hits.append({
                            "url": r.url,
                            "path": path,
                            "origin": origin,
                            "status": r.status_code,
                            "content_type": r.headers.get("content-type", ""),
                            "sampled_bytes": len(chunk),
                        })
                    r.close()
                except requests.RequestException:
                    continue
        return {"scanned": scanned, "origins": origins[:3], "hits": hits}

    def _probe_firebase(self) -> List[Dict[str, Any]]:
        results = []
        for base in sorted(self.analyzer.firebase)[:10]:
            probe_url = base.rstrip("/") + "/.json?shallow=true"
            record = {"url": probe_url, "status": None, "public": False, "error": None}
            try:
                r = self.session.get(probe_url, timeout=self.timeout)
                record["status"] = r.status_code
                try:
                    r.json()
                    record["json_response"] = True
                    record["public"] = r.status_code == 200
                except ValueError:
                    record["json_response"] = False
            except requests.RequestException as exc:
                record["error"] = str(exc)[:200]
            results.append(record)
        return results

    def _probe_graphql(self) -> List[Dict[str, Any]]:
        results = []
        graphql_urls = sorted({
            ep.url for ep in self.analyzer.endpoints.values()
            if "graphql" in ep.url.lower() and ep.url.startswith(("http://", "https://"))
        })
        query = {
            "query": (
                "{__schema{queryType{name}mutationType{name}"
                "subscriptionType{name}types{name kind}}}"
            )
        }
        for url in graphql_urls[:3]:
            record = {"url": url, "status": None, "introspectable": False, "error": None}
            try:
                r = self.session.post(url, json=query, timeout=self.timeout)
                record["status"] = r.status_code
                try:
                    body = r.json()
                    schema = body.get("data", {}).get("__schema")
                    if schema:
                        record["introspectable"] = True
                        record["query_type"] = (schema.get("queryType") or {}).get("name")
                        record["mutation_type"] = (schema.get("mutationType") or {}).get("name")
                        record["type_count"] = len(schema.get("types", []) or [])
                except ValueError:
                    pass
            except requests.RequestException as exc:
                record["error"] = str(exc)[:200]
            results.append(record)
        return results


# ============================================================
# PRETTY OUTPUT
# ============================================================

def print_report(report: Dict[str, Any]):
    print("\n" + "=" * 82)
    print(" ADVANCED API / PAYLOAD ANALYSIS")
    print("=" * 82)

    endpoints = report["api_analysis"]["endpoints"]
    print(f"\nEndpoints discovered : {len(endpoints)}")
    print(f"Firebase databases   : {len(report['api_analysis']['firebase'])}")
    print(f"JS/source files       : {len(report['api_analysis']['files'])}")
    print(f"Source maps           : {len(report['api_analysis']['source_maps'])}")
    print(f"API parameters        : {len(report['api_analysis']['api_parameters'])}")
    print(f"Secrets found         : {len(report['api_analysis'].get('secrets', []))}")
    fbenum_top = report.get("firebase_enum") or []
    if fbenum_top:
        print(f"Firebase paths        : {sum(len(f.get('paths', [])) for f in fbenum_top)}")
    print(f"Runtime requests      : {len(report['api_analysis']['runtime_requests'])}")

    if endpoints:
        print("\n" + "-" * 82)
        print(" DISCOVERED API ENDPOINTS")
        print("-" * 82)
        for i, ep in enumerate(endpoints, 1):
            print(f"\n[{i}] {ep['api_type']}  | confidence={ep['confidence']}")
            print(f"    URL     : {_short(ep['url'], 130)}")
            print(f"    Method  : {ep['method'] or 'not explicit'}")
            print(f"    Path    : {_short(ep['path'], 100)}")
            if ep["query"]:
                print("    Query:")
                for k, values in ep["query"].items():
                    if "{" in k or "}" in k or "$" in k:
                        print(f"      - {_short(k, 80)}  [dynamic query part]")
                    else:
                        print(f"      - {_short(k, 60)} = {', '.join(_short(v, 60) for v in values[:3])}")
            if ep["inferred_query_parameters"]:
                print("    Inferred query parameters:")
                for k in ep["inferred_query_parameters"]:
                    print(f"      - {k}")
            if ep["body_keys"]:
                print("    Request body keys:")
                for k in ep["body_keys"]:
                    print(f"      - {k}")
            if ep["headers"]:
                print("    Relevant headers:")
                for k, v in ep["headers"].items():
                    print(f"      - {k}: {_short(v, 80)}")
            if ep["source"]:
                print("    Source:")
                for s in ep["source"][:5]:
                    print(f"      - {_short_mid(s)}")
            if ep["evidence"]:
                print("    Evidence:")
                for e in ep["evidence"][:5]:
                    print(f"      - {_short(e, 140)}")

    tree = report["api_analysis"].get("path_tree", {})
    if tree:
        print("\n" + "-" * 82)
        print(" API PATH TREE (NORMALIZED, DEEP DIVE)")
        print("-" * 82)
        tgroups: Dict[tuple, List[str]] = defaultdict(list)
        tpatterns: Dict[tuple, List[Dict[str, Any]]] = {}
        for host, patterns in tree.items():
            key = tuple((n["pattern"], n["count"], tuple(n["methods"])) for n in patterns)
            tgroups[key].append(host)
            tpatterns[key] = patterns
        for key, hosts in tgroups.items():
            shown = ", ".join(hosts[:10]) + ("..." if len(hosts) > 10 else "")
            print(f"\nHosts ({len(hosts)}): {shown}")
            for n in tpatterns[key][:60]:
                methods = ",".join(n["methods"]) or "-"
                if len(methods) > 12:
                    methods = f"{len(n['methods'])} methods"
                print(f"  x{n['count']:>3} [{methods:<12}] {_short(n['pattern'], 90)}")

    firebase = report["api_analysis"]["firebase"]
    if firebase:
        print("\n" + "-" * 82)
        print(" FIREBASE ANALYSIS (BASE -> ALL ATTACHED PATHS)")
        print("-" * 82)
        groups: Dict[tuple, List[str]] = defaultdict(list)
        for base, item in firebase.items():
            groups[tuple(item["paths"])].append(base)
        for paths, bases in groups.items():
            print(f"\n{len(bases)} database(s) x {len(paths)} attached path(s):")
            for b in bases[:40]:
                print(f"  DB  : {b}")
            if len(bases) > 40:
                print(f"  ... +{len(bases) - 40} more")
            qunion = sorted({q for b in bases for q in firebase[b]["observed_query_parameters"]})
            if qunion:
                dyn = [q + " [dynamic]" if ("{" in q or "$" in q) else q for q in qunion]
                print("  Query : " + ", ".join(dyn))
            print("  Paths (full REST URL, first DB shown):")
            for p in paths[:80]:
                print(f"    - {_short(bases[0].rstrip('/') + p, 135)}")
            if len(paths) > 80:
                print(f"    ... +{len(paths) - 80} more (see JSON report)")

    fbenum = report.get("firebase_enum") or []
    if fbenum:
        print("\n" + "-" * 82)
        print(" FIREBASE RTDB PATH ENUMERATION (ALL PATHS)")
        print("-" * 82)
        for fb in fbenum:
            print(f"\nBase: {fb['base_url']}  public={fb['public']}  paths={len(fb.get('paths', []))}  "
                  f"leaves={fb.get('leaf_count')} branches={fb.get('branch_count')}  truncated={fb.get('truncated')}")
            if fb.get("error"):
                print(f"  error: {fb['error']}")
            for p in fb.get("paths", [])[:150]:
                print(f"  {p}")
            extra = len(fb.get("paths", [])) - 150
            if extra > 0:
                print(f"  ... +{extra} more (see JSON report)")
            if fb.get("leaf_samples"):
                print("  sample values:")
                for k, v in list(fb["leaf_samples"].items())[:10]:
                    print(f"    {k} = {str(v)[:80]}")

    params = report["api_analysis"]["api_parameters"]
    if params:
        print("\n" + "-" * 82)
        print(" ALL DISCOVERED API PARAMETERS")
        print("-" * 82)
        print("  " + "\n  ".join(params))

    bodies = report["api_analysis"]["request_body_keys"]
    if bodies:
        print("\n" + "-" * 82)
        print(" REQUEST BODY KEYS")
        print("-" * 82)
        print("  " + "\n  ".join(bodies))

    config_fields = report["api_analysis"].get("configuration_fields", [])
    if config_fields:
        print("\n" + "-" * 82)
        print(" APPLICATION / API CONFIGURATION FIELDS")
        print("-" * 82)
        print("  " + "\n  ".join(config_fields))
        print("  Note: these are configuration/object fields, not necessarily HTTP query parameters.")

    methods = report["api_analysis"]["http_methods"]
    if methods:
        print("\n" + "-" * 82)
        print(" HTTP METHODS")
        print("-" * 82)
        print("  " + "  ".join(methods))

    runtime = report["api_analysis"].get("runtime_requests", [])
    if runtime:
        print("\n" + "-" * 82)
        print(" RUNTIME NETWORK REQUESTS")
        print("-" * 82)
        for i, item in enumerate(runtime, 1):
            print(f"\n[{i}] {item['method']} {item['url']}")
            print(f"    type : {item.get('resource_type', '')}")
            if item.get("query_parameters"):
                print("    query: " + ", ".join(item["query_parameters"]))
            if item.get("body_keys"):
                print("    body : " + ", ".join(item["body_keys"]))

    page = report.get("page_analysis") or {}
    tech = page.get("technology")
    if tech and (tech.get("signals") or tech.get("generator") or tech.get("server")):
        print("\n" + "-" * 82)
        print(" TECHNOLOGY FINGERPRINT")
        print("-" * 82)
        if tech.get("signals"):
            print("  Signals   : " + ", ".join(tech["signals"]))
        if tech.get("generator"):
            print(f"  Generator : {tech['generator']}")
        if tech.get("server"):
            print(f"  Server    : {tech['server']}")
        if tech.get("powered_by"):
            print(f"  Powered-By: {tech['powered_by']}")

    security = page.get("security")
    if security:
        print("\n" + "-" * 82)
        print(" SECURITY HEADERS")
        print("-" * 82)
        for h, v in security.get("present", {}).items():
            print(f"  [+] {h}: {v[:90]}")
        for h in security.get("missing", []):
            print(f"  [-] missing: {h}")

    secrets = report["api_analysis"].get("secrets", [])
    if secrets:
        print("\n" + "-" * 82)
        print(f" POTENTIAL SECRETS / KEYS IN SOURCE ({len(secrets)})")
        print("-" * 82)
        for s in secrets[:40]:
            print(f"  {s['type']:<28} len={s['length']:<4} preview={s['preview']}  src={s['source'][:60]}")

    embedded = report["api_analysis"].get("embedded_states", [])
    if embedded:
        print("\n" + "-" * 82)
        print(" EMBEDDED PAGE STATE")
        print("-" * 82)
        for e in embedded[:20]:
            keys = ", ".join(e.get("top_level_keys") or [])
            print(f"  {e['type']} @ {e['source'][:60]}  keys: {keys[:120]}")

    probe = report.get("probe")
    if probe:
        print("\n" + "-" * 82)
        print(" ACTIVE PROBE RESULTS")
        print("-" * 82)
        for p in probe.get("endpoints", []):
            if p.get("error"):
                print(f"  ERR  {p['url']}  {p['error'][:60]}")
            else:
                extra = ""
                if p.get("cors_reflects_origin"):
                    extra += " CORS-REFLECT"
                if p.get("allow"):
                    extra += f" allow={p['allow']}"
                print(f"  {p['status']}  {p['content_type'][:40]:<40} {p['url'][:70]}{extra}")
        for f in probe.get("firebase", []):
            print(f"  firebase status={f['status']} public_json={f.get('public')} {f['url']}")
        for g in probe.get("graphql", []):
            print(f"  graphql introspectable={g['introspectable']} status={g['status']} {g['url']}")
        wk = probe.get("wellknown") or {}
        hits = wk.get("hits", []) if isinstance(wk, dict) else []
        if hits:
            print(f"  well-known/doc paths ({len(hits)} hits / {wk.get('scanned', '?')} scanned):")
            for h in hits:
                print(f"    {h['status']} {h['content_type'][:30]:<30} {h['url'][:75]}")

    robots = report.get("robots")
    if robots and robots.get("status") == 200:
        print("\n" + "-" * 82)
        print(" ROBOTS / SITEMAPS")
        print("-" * 82)
        for s in robots.get("sitemaps", []):
            print(f"  sitemap: {s}")

    crawl = report.get("crawl")
    if crawl:
        print(f"\n Crawl: {crawl['pages_visited']} page(s) visited at depth {crawl['max_depth']}")


# ============================================================
# INPUT HELPERS
# ============================================================

def build_parser():
    p = argparse.ArgumentParser(
        description="Advanced recursive payload + API analyzer"
    )
    p.add_argument("url", nargs="?", help="Target URL")
    p.add_argument("--output", "-o", default="api_analysis.json", help="JSON report path")
    p.add_argument("--no-page", action="store_true", help="Do not fetch/inspect the supplied page")
    p.add_argument("--runtime", action="store_true", help="Use optional Playwright browser runtime network inspection")
    p.add_argument("--runtime-seconds", type=int, default=DEFAULT_RUNTIME_SECONDS)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    p.add_argument("--max-nodes", type=int, default=DEFAULT_MAX_NODES)
    p.add_argument("--max-scripts", type=int, default=DEFAULT_MAX_SCRIPTS)
    p.add_argument("--max-imports", type=int, default=DEFAULT_MAX_IMPORTS)
    p.add_argument("--max-sourcemaps", type=int, default=DEFAULT_MAX_SOURCEMAP_SOURCES)
    p.add_argument("--probe", action="store_true", help="Actively probe discovered endpoints (read-only GET/OPTIONS, plus one GraphQL introspection POST)")
    p.add_argument("--max-probe", type=int, default=DEFAULT_MAX_PROBE, help="Max endpoints to probe")
    p.add_argument("--crawl", type=int, default=0, metavar="DEPTH", help="Crawl same-origin links to given depth (0=off)")
    p.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES, help="Max pages to fetch during crawl")
    p.add_argument("--no-robots", action="store_true", help="Skip robots.txt analysis")
    p.add_argument("--firebase-enum", action="store_true", help="Enumerate all Firebase RTDB paths via shallow listings (standalone, read-only)")
    p.add_argument("--firebase-depth", type=int, default=4, help="Max depth for Firebase path enumeration")
    p.add_argument("--max-firebase-nodes", type=int, default=2000, help="Max Firebase nodes to enumerate")
    p.add_argument("--quiet", action="store_true")
    return p


def get_target(args) -> str:
    if args.url:
        return args.url.strip()
    return input("Enter URL: ").strip()


# ============================================================
# MAIN
# ============================================================

def main():
    args = build_parser().parse_args()
    target = get_target(args)

    if not re.match(r"^https?://", target, re.I):
        print("Error: target must start with http:// or https://")
        sys.exit(1)

    analyzer = AdvancedAnalyzer(
        timeout=args.timeout,
        max_depth=args.max_depth,
        max_nodes=args.max_nodes,
    )

    parsed = urlparse(target)
    print("=" * 82)
    print(" ADVANCED URL -> PAYLOAD -> API ANALYZER")
    print("=" * 82)
    print(f"Host: {parsed.netloc}")
    print(f"Path: {parsed.path or '/'}")
    print(f"Query parameters: {len(parse_qsl(parsed.query, keep_blank_values=True))}")

    # --------------------------------------------------------
    # Decode every query parameter and fragment.
    # --------------------------------------------------------
    print("\n[1/5] Decoding URL payloads...")
    payload_report = {
        "input": target,
        "scheme": parsed.scheme,
        "host": parsed.netloc,
        "path": parsed.path or "/",
        "query_parameters": [],
        "fragment": None,
    }

    for index, (name, value) in enumerate(parse_qsl(parsed.query, keep_blank_values=True)):
        payload_report["query_parameters"].append({
            "name": name,
            "raw_value": value,
            "decoded_tree": analyzer.walk(value, f"query[{index}].{name}"),
        })

    if parsed.fragment:
        payload_report["fragment"] = analyzer.walk(
            unquote_plus(parsed.fragment),
            "fragment",
        )

    # --------------------------------------------------------
    # Inspect page and client-side assets.
    # --------------------------------------------------------
    page_report = None
    inspector = None
    robots_report = None
    crawl_report = None
    if not args.no_page:
        print("[2/5] Inspecting HTML, JavaScript, modules and source maps...")
        inspector = WebInspector(
            analyzer,
            max_page=DEFAULT_MAX_PAGE,
            max_js=DEFAULT_MAX_JS,
            max_scripts=args.max_scripts,
            max_imports=args.max_imports,
            max_maps=args.max_sourcemaps,
        )
        page_report = inspector.inspect_page(target)
        if page_report and page_report.get("status") is not None:
            print(f"Page status: {page_report.get('status')}")
        elif page_report and page_report.get("error"):
            print(f"Page error: {page_report['error']}")

        if not args.no_robots:
            robots_report = inspector.fetch_robots(target)

        if args.crawl and args.crawl > 0:
            print(f"[2b/5] Crawling same-origin links (depth={args.crawl})...")
            crawl_report = inspector.crawl(target, args.crawl, args.max_pages)

    # --------------------------------------------------------
    # Optional runtime network inspection.
    # --------------------------------------------------------
    runtime_report = None
    if args.runtime:
        print("[3/5] Observing browser runtime network requests...")
        runtime = RuntimeInspector(analyzer, timeout_seconds=args.runtime_seconds)
        runtime_report = runtime.run(target)
        if runtime_report.get("error"):
            print(f"Runtime warning: {runtime_report['error']}")
    else:
        print("[3/5] Runtime mode disabled (static analysis only).")

    # Store runtime requests also in top-level analyzer state.
    if runtime_report:
        analyzer.runtime_requests = runtime_report.get("requests", [])
        for req in analyzer.runtime_requests:
            analyzer.register_endpoint(
                req["url"],
                source="runtime-network",
                method=req.get("method"),
                evidence=["captured browser network request"],
                body_keys=req.get("body_keys", []),
                inferred_query=req.get("query_parameters", []),
                headers=req.get("headers", {}),
                runtime=True,
            )

    # --------------------------------------------------------
    # Optional active probing of discovered endpoints.
    # --------------------------------------------------------
    probe_report = None
    firebase_enum_report = None
    if args.probe:
        print("[4/5] Actively probing discovered endpoints (read-only)...")
        prober = ProbeInspector(
            analyzer,
            timeout=DEFAULT_PROBE_TIMEOUT,
            max_endpoints=args.max_probe,
            firebase_depth=args.firebase_depth,
            firebase_max_nodes=args.max_firebase_nodes,
        )
        probe_report = prober.run(target)
    elif args.firebase_enum:
        print("[4/5] Enumerating Firebase paths (read-only shallow listings)...")
        if "firebaseio.com" in target or "firebasedatabase.app" in target:
            analyzer.register_endpoint(target, source="target", evidence=["explicit Firebase target"])
        fbenum = FirebaseEnumerator(
            timeout=DEFAULT_PROBE_TIMEOUT,
            max_depth=args.firebase_depth,
            max_nodes=args.max_firebase_nodes,
        )
        firebase_enum_report = [fbenum.enumerate_base(b) for b in sorted(analyzer.firebase)[:10]]
        if not firebase_enum_report:
            print("No Firebase databases discovered to enumerate.")
    else:
        print("[4/5] Probe mode disabled (use --probe to activate read-only checks).")

    print("[5/5] Building report...")
    fbenum_data = probe_report["firebase_enum"] if probe_report else firebase_enum_report
    api_report = analyzer.report()
    report = {
        "tool": "advanced_api_analyzer",
        "version": "4.2",
        "input": target,
        "payload_analysis": payload_report,
        "page_analysis": page_report,
        "robots": robots_report,
        "crawl": crawl_report,
        "runtime_analysis": runtime_report,
        "probe": probe_report,
        "firebase_enum": fbenum_data,
        "api_analysis": api_report,
        "statistics": {
            "decoder_nodes": analyzer.nodes,
            "discovered_urls": len(analyzer.discovered_urls),
            "discovered_endpoints": len(analyzer.endpoints),
            "firebase_databases": len(analyzer.firebase),
            "files": len(analyzer.files),
            "source_maps": len(analyzer.source_maps),
            "api_parameters": len(analyzer.parameters),
            "body_keys": len(analyzer.body_keys),
            "configuration_fields": len(analyzer.config_fields),
            "secrets": len(analyzer.secrets),
            "embedded_states": len(analyzer.embedded_states),
            "crawl_pages": crawl_report["pages_visited"] if crawl_report else 0,
            "probe_endpoints": len(probe_report["endpoints"]) if probe_report else 0,
            "firebase_paths": sum(len(f.get("paths", [])) for f in (fbenum_data or [])),
            "wellknown_hits": len((probe_report.get("wellknown", {}) or {}).get("hits", [])) if probe_report else 0,
            "runtime_requests": len(analyzer.runtime_requests),
        },
        "notes": [
            "Static endpoint reconstruction is best-effort when JavaScript builds URLs dynamically.",
            "Runtime mode observes requests produced by page execution and is more authoritative for actual network behavior.",
            "JWT signatures are not verified.",
            "Probe mode issues read-only requests to already-discovered endpoints; it performs no brute-force, auth bypass or credential guessing.",
            "Secret matches are pattern-based and may include false positives; values are truncated in output.",
            "Firebase enumeration uses read-only shallow listings and only reveals paths of publicly-readable databases.",
            "Dynamic Firebase REST paths (e.g. `${base}/${path}.json`) are attached to every discovered base; placeholders are preserved.",
            "Known `let/const/var` literals are substituted into templates; unknown variables stay as placeholders.",
            "Firebase REST endpoint patterns are reported from observed/inferred configuration; they are not automatically executed.",
        ],
    }

    try:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        print(f"\nFull report saved to: {args.output}")
    except OSError as exc:
        print(f"Could not save report: {exc}")
        sys.exit(1)

    if not args.quiet:
        print_report(report)


if __name__ == "__main__":
    main()
