"""
Threat Intelligence Module  Analyser Container

Provides in-memory IP reputation lookups against downloaded blocklist feeds.
Feeds are populated by threatintel/update-feeds.sh (run as a cron job or
via `docker exec analyser /app/threatintel/update-feeds.sh`).

Integration points:
  - AlertAnalyzer.analyze_alert() calls enrich_alert_with_threatintel()
    to prepend threat intel context to the LLM prompt.
  - api.py exposes /threatintel (web UI) and /api/threatintel/* (JSON API).
"""

import ipaddress
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Feeds directory — override via THREATINTEL_FEEDS_DIR env var.
# Default: /app/threatintel/feeds  (matches Dockerfile COPY and update-feeds.sh)
DEFAULT_FEEDS_DIR = Path(
    os.environ.get("THREATINTEL_FEEDS_DIR", "/app/threatintel/feeds")
)

# Per-feed metadata: display_name, severity, description
FEED_METADATA: dict[str, tuple[str, str, str]] = {
    "feodotracker":   ("Feodo Tracker",    "CRITICAL", "Banking trojans / active botnet C2 servers"),
    "sslbl":          ("SSL Blacklist",     "CRITICAL", "Malware C2 IPs identified via SSL certificates"),
    "et_compromised": ("Emerging Threats",  "HIGH",     "Compromised hosts"),
    "blocklist_ssh":  ("Blocklist.de SSH",  "MEDIUM",   "SSH bruteforce attackers"),
    "blocklist_all":  ("Blocklist.de All",  "MEDIUM",   "All attack categories"),
    "ci_army":        ("CINSscore CI Army", "HIGH",     "Composite threat intelligence score"),
    "tor_exit_nodes": ("Tor Exit Nodes",    "INFO",     "Tor anonymization network exit nodes"),
}

# Feeds that are confirmed C2 infrastructure — highest confidence
C2_FEEDS: frozenset[str] = frozenset({"feodotracker", "sslbl"})

# Severity ordering for comparisons
_SEVERITY_RANK: dict[str, int] = {
    "CLEAN": 0, "INFO": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4
}

# Compiled IPv4 extractor — used for scanning alert text
_IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ThreatMatch:
    """A single positive hit for an IP in one feed."""
    feed: str
    display_name: str
    severity: str
    description: str
    feed_updated: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "feed": self.feed,
            "display_name": self.display_name,
            "severity": self.severity,
            "description": self.description,
            "feed_updated": self.feed_updated.isoformat() if self.feed_updated else None,
        }


@dataclass
class ThreatIntelResult:
    """Full lookup result for a single IP address."""
    ip: str
    is_malicious: bool = False
    matches: list[ThreatMatch] = field(default_factory=list)
    is_c2: bool = False
    is_tor: bool = False
    in_spamhaus_cidr: Optional[str] = None
    highest_severity: str = "CLEAN"
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "is_malicious": self.is_malicious,
            "is_c2": self.is_c2,
            "is_tor": self.is_tor,
            "highest_severity": self.highest_severity,
            "spamhaus_cidr": self.in_spamhaus_cidr,
            "matches": [m.to_dict() for m in self.matches],
            "summary": self.summary,
        }


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

class ThreatIntelDB:
    """
    In-memory threat intel database built from flat feed files.

    Thread-safety: reads are safe after load(); reload() should only be called
    from a single thread (the API reload endpoint holds no lock, so if you run
    multiple gunicorn workers you may want to use a file-based signal instead).
    """

    def __init__(self, feeds_dir: Optional[Path] = None):
        self.feeds_dir = Path(feeds_dir) if feeds_dir else DEFAULT_FEEDS_DIR
        self._ip_sets: dict[str, set[str]] = {}
        self._spamhaus_cidrs: list[ipaddress.IPv4Network] = []
        self._load_times: dict[str, datetime] = {}
        self._loaded = False

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load_plain_feed(self, stem: str) -> set[str]:
        """Load a plain-IP (one per line) feed file into a set."""
        path = self.feeds_dir / f"{stem}.txt"
        if not path.exists():
            return set()

        ips: set[str] = set()
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
                try:
                    ipaddress.IPv4Address(line)
                    ips.add(line)
                except ValueError:
                    pass

        self._load_times[stem] = datetime.fromtimestamp(path.stat().st_mtime)
        return ips

    def _load_spamhaus(self) -> None:
        """Load Spamhaus DROP CIDR list (not plain IPs)."""
        path = self.feeds_dir / "spamhaus_drop.txt"
        if not path.exists():
            return

        cidrs: list[ipaddress.IPv4Network] = []
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith(";") or line.startswith("#"):
                    continue
                cidr_part = line.split(";")[0].strip()
                try:
                    cidrs.append(ipaddress.IPv4Network(cidr_part, strict=False))
                except ValueError:
                    pass

        self._spamhaus_cidrs = cidrs
        self._load_times["spamhaus_drop"] = datetime.fromtimestamp(path.stat().st_mtime)

    def load(self) -> None:
        """Load all feeds into memory. Safe to call multiple times."""
        if not self.feeds_dir.exists():
            logger.warning(
                "Threat intel feeds directory not found: %s — "
                "run /app/threatintel/update-feeds.sh to download feeds",
                self.feeds_dir,
            )
            self._loaded = True
            return

        for stem in FEED_METADATA:
            self._ip_sets[stem] = self._load_plain_feed(stem)

        self._load_spamhaus()
        self._loaded = True

        total = sum(len(s) for s in self._ip_sets.values())
        logger.info(
            "ThreatIntelDB: loaded %d IPs across %d feeds + %d Spamhaus CIDRs (from %s)",
            total,
            sum(1 for s in self._ip_sets.values() if s),
            len(self._spamhaus_cidrs),
            self.feeds_dir,
        )

    def reload(self) -> None:
        """Reload all feeds from disk (picks up updates without restart)."""
        logger.info("ThreatIntelDB: reloading feeds from %s", self.feeds_dir)
        self._ip_sets.clear()
        self._spamhaus_cidrs.clear()
        self._load_times.clear()
        self._loaded = False
        self.load()

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load()

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def lookup(self, ip: str) -> ThreatIntelResult:
        """
        Look up a single IPv4 address against all feeds.

        Returns a ThreatIntelResult. Private/loopback addresses are returned
        as CLEAN immediately — they will never appear in public feeds.
        """
        self._ensure_loaded()

        result = ThreatIntelResult(ip=ip)

        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            result.summary = f"{ip} is not a valid IPv4 address"
            return result

        if addr.is_private or addr.is_loopback or addr.is_link_local:
            result.summary = f"{ip} is a private/internal address — not checked against public feeds"
            return result

        highest = "CLEAN"

        # Check plain-IP feeds
        for stem, ip_set in self._ip_sets.items():
            if ip not in ip_set:
                continue
            meta = FEED_METADATA.get(stem, (stem, "MEDIUM", "Unknown feed"))
            match = ThreatMatch(
                feed=stem,
                display_name=meta[0],
                severity=meta[1],
                description=meta[2],
                feed_updated=self._load_times.get(stem),
            )
            result.matches.append(match)
            result.is_malicious = True
            if stem in C2_FEEDS:
                result.is_c2 = True
            if stem == "tor_exit_nodes":
                result.is_tor = True
            if _SEVERITY_RANK.get(meta[1], 0) > _SEVERITY_RANK.get(highest, 0):
                highest = meta[1]

        # Check Spamhaus CIDRs
        for cidr in self._spamhaus_cidrs:
            if addr in cidr:
                result.in_spamhaus_cidr = str(cidr)
                result.is_malicious = True
                if _SEVERITY_RANK["HIGH"] > _SEVERITY_RANK.get(highest, 0):
                    highest = "HIGH"
                break

        result.highest_severity = highest if result.is_malicious else "CLEAN"
        result.summary = self._build_summary(result)
        return result

    def lookup_many(self, ips: list[str]) -> dict[str, ThreatIntelResult]:
        """Bulk lookup. Returns {ip: ThreatIntelResult}."""
        return {ip: self.lookup(ip) for ip in ips}

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        """Return feed statistics — used by the health and stats endpoints."""
        self._ensure_loaded()
        feeds_info = {}
        for stem, ip_set in self._ip_sets.items():
            updated = self._load_times.get(stem)
            feeds_info[stem] = {
                "count": len(ip_set),
                "updated": updated.isoformat() if updated else None,
            }
        if self._spamhaus_cidrs:
            updated = self._load_times.get("spamhaus_drop")
            feeds_info["spamhaus_drop"] = {
                "count": len(self._spamhaus_cidrs),
                "updated": updated.isoformat() if updated else None,
                "note": "CIDR blocks, not plain IPs",
            }
        return {
            "feeds_dir": str(self.feeds_dir),
            "feeds_loaded": feeds_info,
            "total_ips": sum(len(s) for s in self._ip_sets.values()),
            "spamhaus_cidrs": len(self._spamhaus_cidrs),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_summary(result: ThreatIntelResult) -> str:
        if not result.is_malicious:
            return f"{result.ip}: not found in any threat intel feed"

        feed_names = ", ".join(m.display_name for m in result.matches)
        if result.in_spamhaus_cidr:
            feed_names += f", Spamhaus DROP (CIDR {result.in_spamhaus_cidr})"

        parts = [f"{result.ip} is listed in {len(result.matches) + (1 if result.in_spamhaus_cidr else 0)} feed(s): {feed_names}."]
        if result.is_c2:
            parts.append("CONFIRMED C2 SERVER — high-confidence indicator of compromise.")
        if result.is_tor:
            parts.append("Known Tor exit node.")
        parts.append(f"Highest severity: {result.highest_severity}.")
        return " ".join(parts)


# ---------------------------------------------------------------------------
# Module-level singleton — one DB per process, shared across all requests
# ---------------------------------------------------------------------------
_db: Optional[ThreatIntelDB] = None


def get_db(feeds_dir: Optional[Path] = None) -> ThreatIntelDB:
    """Return (or lazily create) the module-level ThreatIntelDB singleton."""
    global _db
    if _db is None:
        _db = ThreatIntelDB(feeds_dir)
    return _db


# ---------------------------------------------------------------------------
# Public helpers used by analyzer.py
# ---------------------------------------------------------------------------

def extract_ips_from_alert(alert: dict) -> list[str]:
    """
    Extract all unique IPv4 addresses from a Falco alert dict.

    Scans both the raw `output` string and every string value in
    `output_fields` so structured and unstructured alerts are both covered.
    """
    seen: set[str] = set()
    result: list[str] = []

    def _collect(text: str) -> None:
        for ip in _IPV4_RE.findall(text):
            if ip not in seen:
                seen.add(ip)
                result.append(ip)

    _collect(alert.get("output", ""))
    for val in (alert.get("output_fields") or {}).values():
        if isinstance(val, str):
            _collect(val)

    return result


def enrich_alert_with_threatintel(alert: dict) -> dict:
    """
    Run threat intel lookups for every IP found in a Falco alert.

    Returns a dict with a single key ``"threat_intel"`` whose value is
    a structured result dict ready to be merged into the analyzer result
    and, if threats are found, appended to the LLM prompt.

    Return shape::

        {
            "threat_intel": {
                "checked_ips": [...],
                "malicious_ips": [...],
                "has_threats": bool,
                "has_c2": bool,
                "highest_severity": "CRITICAL|HIGH|MEDIUM|INFO|CLEAN",
                "results": {"1.2.3.4": {...ThreatIntelResult.to_dict()...}},
                "context_for_llm": "Threat Intelligence:\\n  • ...",
            }
        }
    """
    db = get_db()
    ips = extract_ips_from_alert(alert)

    if not ips:
        return {
            "threat_intel": {
                "checked_ips": [],
                "malicious_ips": [],
                "has_threats": False,
                "has_c2": False,
                "highest_severity": "CLEAN",
                "results": {},
                "context_for_llm": "Threat Intelligence: no IP addresses found in this alert.",
            }
        }

    results = db.lookup_many(ips)
    malicious = [ip for ip, r in results.items() if r.is_malicious]
    has_c2 = any(r.is_c2 for r in results.values())

    highest = max(
        (r.highest_severity for r in results.values()),
        key=lambda s: _SEVERITY_RANK.get(s, 0),
        default="CLEAN",
    )

    lines = [f"Threat Intelligence ({len(ips)} IP(s) checked):"]
    for ip, r in results.items():
        lines.append(f"  • {r.summary}")
    if has_c2:
        lines.append("  ⚠ One or more IPs are confirmed C2 servers — treat this alert as HIGH priority.")

    return {
        "threat_intel": {
            "checked_ips": ips,
            "malicious_ips": malicious,
            "has_threats": bool(malicious),
            "has_c2": has_c2,
            "highest_severity": highest,
            "results": {ip: r.to_dict() for ip, r in results.items()},
            "context_for_llm": "\n".join(lines),
        }
    }
