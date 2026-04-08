"""
Obfuscator - Privacy-preserving data redaction for Falco security alerts

Replaces sensitive information with consistent tokens while preserving
the structure and relationships needed for security analysis.
Alerts are stored in Loki and forwarded by Falcosidekick.
"""

import re
import math
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Set
from enum import Enum


class ObfuscationLevel(Enum):
    MINIMAL = "minimal"      # Only secrets/credentials
    STANDARD = "standard"    # IPs, hostnames, users, paths (recommended)
    PARANOID = "paranoid"    # Everything except alert type


@dataclass
class ObfuscationMap:
    """Tracks obfuscated values for consistent replacement and potential de-obfuscation."""
    ips: Dict[str, str] = field(default_factory=dict)
    hostnames: Dict[str, str] = field(default_factory=dict)
    users: Dict[str, str] = field(default_factory=dict)
    containers: Dict[str, str] = field(default_factory=dict)
    paths: Dict[str, str] = field(default_factory=dict)
    emails: Dict[str, str] = field(default_factory=dict)
    k8s: Dict[str, str] = field(default_factory=dict)
    secrets: Set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "ips": self.ips,
            "hostnames": self.hostnames,
            "users": self.users,
            "containers": self.containers,
            "paths": self.paths,
            "emails": self.emails,
            "k8s": self.k8s,
            "secrets_count": len(self.secrets)
        }


class Obfuscator:
    """Obfuscates sensitive data in Falco security alerts while preserving analytical value."""

    # RFC 1918 private IP ranges + common container networks
    PRIVATE_IP_RANGES = [
        (0x0A000000, 0x0AFFFFFF),  # 10.0.0.0/8
        (0xAC100000, 0xAC1FFFFF),  # 172.16.0.0/12
        (0xC0A80000, 0xC0A8FFFF),  # 192.168.0.0/16
        (0x7F000000, 0x7FFFFFFF),  # 127.0.0.0/8 (loopback)
        (0xC6120000, 0xC612FFFF),  # 198.18.0.0/15 (container default)
    ]

    PATTERNS = {
        # Network identifiers
        'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',

        # FIX #1: Anchor container ID so it doesn't match arbitrary hex
        # Only replace when followed by whitespace, closing paren, or end-of-line,
        # and within an explicit container= / id= context or as a bare 64-char SHA.
        'container_id': r'\b[a-f0-9]{12,64}\b(?=\s|\)|$)',

        # Cloud provider credentials — FIX #5: add context anchors
        'aws_access_key': r'\b(A3T[A-Z0-9]|AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16}\b',
        # FIX #5: was too broad; require key= / secret= / ACCESS_KEY prefix context
        'aws_secret_key': r'(?i)(aws_secret_access_key|aws_secret|secret_key)[=:\s]+["\']?([A-Za-z0-9+/]{40})["\']?',
        'aws_session_token': r'\b(FwoGZXIvYXdzE|IQoJb3JpZ2lu)[A-Za-z0-9/+=]+\b',
        'gcp_service_account': r'\b[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com\b',
        'google_api_key': r'\bAIza[0-9A-Za-z\-_]{35}\b',
        'azure_storage_key': r'\b[A-Za-z0-9+/]{86}==\b',

        # Version control tokens
        'github_pat': r'\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b',
        'github_fine_grained': r'\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b',
        'gitlab_pat': r'\bglpat-[A-Za-z0-9\-_]{20,}\b',

        # Communication platforms
        'slack_bot_token': r'\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}\b',
        'slack_webhook': r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}',
        'discord_bot_token': r'\b(MTA|MTE|MTI|OT|Nj|Nz|OD)[A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b',

        # Payment & services
        'stripe_secret_key': r'\b(sk|rk)_(test|live)_[A-Za-z0-9]{24,}\b',
        'twilio_api_key': r'\bSK[a-f0-9]{32}\b',

        # Database connection strings
        'postgres_uri': r'postgres(ql)?://[^:]+:[^@]+@[^/]+/\w+',
        'mysql_uri': r'mysql://[^:]+:[^@]+@[^/]+/\w+',
        'mongodb_uri': r'mongodb(\+srv)?://[^:]+:[^@]+@[^/]+',
        'redis_uri': r'redis://[^:]+:[^@]+@[^/]+',

        # Authentication tokens
        'jwt': r'\beyJ[A-Za-z0-9-_]*\.eyJ[A-Za-z0-9-_]*\.[A-Za-z0-9-_.+/]*\b',
        'basic_auth': r'\bBasic\s+[A-Za-z0-9+/]+=*\b',
        'bearer_token': r'\bBearer\s+[A-Za-z0-9\-_\.]+\b',

        # Cryptographic material
        'private_key': r'-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----',
        'ssh_private_key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
        'password_field': r'(password|passwd|pwd|secret_key|auth_key|private_key|encryption_key)[=:]\s*["\']?[^\s"\']{8,}["\']?',

        # FIX #6: Kubernetes context patterns
        'k8s_pod': r'(pod=)([a-z0-9][a-z0-9\-]{1,253})',
        'k8s_ns': r'(namespace=|k8s\.ns\.name=)([a-z0-9][a-z0-9\-]{1,253})',
    }

    SECRET_LABELS = {
        'aws_access_key': 'AWS-KEY',
        'aws_secret_key': 'AWS-SECRET',
        'aws_session_token': 'AWS-SESSION',
        'gcp_service_account': 'GCP-SERVICE-ACCOUNT',
        'google_api_key': 'GOOGLE-API',
        'azure_storage_key': 'AZURE-STORAGE',
        'github_pat': 'GITHUB-TOKEN',
        'github_fine_grained': 'GITHUB-TOKEN',
        'gitlab_pat': 'GITLAB-TOKEN',
        'slack_bot_token': 'SLACK-BOT',
        'slack_webhook': 'SLACK-WEBHOOK',
        'discord_bot_token': 'DISCORD-BOT',
        'stripe_secret_key': 'STRIPE-SECRET',
        'twilio_api_key': 'TWILIO-KEY',
        'postgres_uri': 'DB-POSTGRES',
        'mysql_uri': 'DB-MYSQL',
        'mongodb_uri': 'DB-MONGODB',
        'redis_uri': 'DB-REDIS',
        'jwt': 'JWT',
        'private_key': 'PRIVATE-KEY',
        'ssh_private_key': 'SSH-PRIVATE-KEY',
        'password_field': 'PASSWORD',
        'basic_auth': 'BASIC-AUTH',
        'bearer_token': 'BEARER-TOKEN',
    }

    # System users that are safe to show (common in Falco alerts)
    SYSTEM_USERS = {
        'root', 'nobody', 'daemon', 'www-data', 'nginx', 'postgres',
        'mysql', 'redis', 'falco', 'prometheus', 'node-exporter'
    }

    # Sensitive paths to always flag (Falco-relevant)
    SENSITIVE_PATHS = {
        '/etc/shadow', '/etc/passwd', '/etc/sudoers', '/etc/ssh/',
        '/.ssh/', '/id_rsa', '/id_ed25519', '/.aws/credentials',
        '/.kube/config', '/secrets/', '/vault/', '/.env',
        '/proc/', '/sys/', '/var/run/secrets/'
    }

    def __init__(self, level: ObfuscationLevel = ObfuscationLevel.STANDARD):
        self.level = level
        self.map = ObfuscationMap()
        self._counters = {
            'ip_internal': 0,
            'ip_external': 0,
            'host': 0,
            'user': 0,
            'container': 0,
            'path': 0,
            'email': 0,
            'k8s_pod': 0,
            'k8s_ns': 0,
        }

    def _is_private_ip(self, ip: str) -> bool:
        try:
            parts = [int(p) for p in ip.split('.')]
            ip_int = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
            return any(start <= ip_int <= end for start, end in self.PRIVATE_IP_RANGES)
        except (ValueError, IndexError):
            return False

    def _get_token(self, category: str, original: str, mapping: Dict[str, str]) -> str:
        if original in mapping:
            return mapping[original]
        self._counters[category] += 1
        token = f"[{category.upper().replace('_', '-')}-{self._counters[category]}]"
        mapping[original] = token
        return token

    def _obfuscate_ips(self, text: str) -> str:
        def replace_ip(match):
            ip = match.group(0)
            category = 'ip_internal' if self._is_private_ip(ip) else 'ip_external'
            return self._get_token(category, ip, self.map.ips)

        text = re.sub(self.PATTERNS['ipv4'], replace_ip, text)
        text = re.sub(self.PATTERNS['ipv6'],
                      lambda m: self._get_token('ip_external', m.group(0), self.map.ips), text)
        return text

    def _obfuscate_secrets(self, text: str) -> str:
        secret_patterns = [
            'aws_access_key', 'aws_session_token', 'gcp_service_account',
            'google_api_key', 'azure_storage_key',
            'github_pat', 'github_fine_grained', 'gitlab_pat',
            'slack_bot_token', 'slack_webhook', 'discord_bot_token',
            'stripe_secret_key', 'twilio_api_key',
            'postgres_uri', 'mysql_uri', 'mongodb_uri', 'redis_uri',
            'jwt', 'basic_auth', 'bearer_token',
            'private_key', 'ssh_private_key', 'password_field',
            # aws_secret_key intentionally after other AWS patterns (context-anchored now)
            'aws_secret_key',
        ]

        for pattern_name in secret_patterns:
            if pattern_name not in self.PATTERNS:
                continue
            pattern = self.PATTERNS[pattern_name]
            label = self.SECRET_LABELS.get(pattern_name, 'SECRET')

            def make_replacer(lbl):
                def replacer(match):
                    self.map.secrets.add(match.group(0)[:20] + '...')
                    return f'[REDACTED-{lbl}]'
                return replacer

            try:
                text = re.sub(pattern, make_replacer(label), text, flags=re.IGNORECASE)
            except re.error:
                pass

        return text

    def _obfuscate_high_entropy(self, text: str) -> str:
        """Detect and redact high-entropy strings that might be secrets (paranoid mode only)."""

        def entropy(s: str) -> float:
            if not s:
                return 0
            prob = [float(s.count(c)) / len(s) for c in set(s)]
            return -sum(p * math.log2(p) for p in prob)

        def replace_high_entropy(match):
            s = match.group(0)
            # FIX #7: raise threshold + require mixed charset to reduce false positives.
            if (
                len(s) >= 20
                and entropy(s) > 4.8
                and re.search(r'[A-Z]', s)
                and re.search(r'[0-9]', s)
            ):
                self.map.secrets.add(s[:10] + '...')
                return '[REDACTED-HIGH-ENTROPY]'
            return s

        text = re.sub(r'\b[A-Za-z0-9+/=_-]{20,}\b', replace_high_entropy, text)
        return text

    def _obfuscate_emails(self, text: str) -> str:
        def replace_email(match):
            return self._get_token('email', match.group(0), self.map.emails)
        return re.sub(self.PATTERNS['email'], replace_email, text)

    def _obfuscate_containers(self, text: str) -> str:
        """Replace container IDs with tokens (FIX #1: anchored regex)."""
        def replace_container(match):
            cid = match.group(0)
            if len(cid) >= 12 and all(c in '0123456789abcdef' for c in cid.lower()):
                return self._get_token('container', cid, self.map.containers)
            return cid
        return re.sub(self.PATTERNS['container_id'], replace_container, text)

    def _obfuscate_users(self, text: str) -> str:
        """Replace usernames with tokens, preserving system users.
        FIX #4: expanded to cover auid, euid, login, container_user patterns.
        """
        def replace_user(match):
            user = match.group(2)
            if user.lower() in self.SYSTEM_USERS:
                return match.group(0)
            token = self._get_token('user', user, self.map.users)
            return f"{match.group(1)}{token}"

        patterns = [
            r'(user=)(\w+)',
            r'(uid=)(\d+)',
            r'(auid=)(\d+)',      # FIX #4: audit UID
            r'(euid=)(\d+)',      # FIX #4: effective UID
            r'(login=)(\w+)',     # FIX #4: login field
            r'(container_user=)(\w+)',  # FIX #4: container user
            r'(User )(\w+)',
            r'(by user )(\w+)',
        ]
        for pattern in patterns:
            text = re.sub(pattern, replace_user, text, flags=re.IGNORECASE)
        return text

    def _obfuscate_k8s(self, text: str) -> str:
        """FIX #6: Obfuscate Kubernetes pod and namespace names."""
        def replace_k8s_pod(match):
            token = self._get_token('k8s_pod', match.group(2), self.map.k8s)
            return f"{match.group(1)}{token}"

        def replace_k8s_ns(match):
            token = self._get_token('k8s_ns', match.group(2), self.map.k8s)
            return f"{match.group(1)}{token}"

        text = re.sub(self.PATTERNS['k8s_pod'], replace_k8s_pod, text, flags=re.IGNORECASE)
        text = re.sub(self.PATTERNS['k8s_ns'], replace_k8s_ns, text, flags=re.IGNORECASE)
        return text

    def _obfuscate_paths(self, text: str) -> str:
        """Obfuscate file paths while preserving structure and sensitive indicators.
        FIX #3: /home/<user> subdirectory is now replaced with [USER-HOME].
        """
        def replace_path(match):
            path = match.group(0)

            for sensitive in self.SENSITIVE_PATHS:
                if sensitive in path:
                    return path

            parts = path.split('/')
            obfuscated_parts = []
            for idx, part in enumerate(parts):
                if not part:
                    obfuscated_parts.append('')
                elif part in ('home', 'var', 'tmp', 'etc', 'usr', 'opt', 'root',
                               'proc', 'sys', 'dev', 'bin', 'sbin', 'lib', 'lib64'):
                    obfuscated_parts.append(part)
                    # FIX #3: mask the username immediately under /home/
                    if part == 'home' and idx == 1:
                        obfuscated_parts.append('[USER-HOME]')
                        # skip the real username (next part handled by continue below)
                        parts[idx + 1] = None  # sentinel
                elif part is None:
                    continue  # was masked above
                elif '.' in part:
                    name, ext = part.rsplit('.', 1)
                    if len(name) > 3:
                        obfuscated_parts.append(f'[FILE].{ext}')
                    else:
                        obfuscated_parts.append(part)
                else:
                    obfuscated_parts.append(part)

            return '/'.join(obfuscated_parts)

        text = re.sub(r'/[\w./-]+', replace_path, text)
        return text

    def _obfuscate_hostnames(self, text: str) -> str:
        """Replace hostnames with tokens.
        FIX #2: use prefix-anchored pattern to avoid matching k8s service FQDNs.
        """
        def replace_hostname(match):
            # match.group(1) = prefix (host=), match.group(2) = hostname value
            hostname = match.group(2)
            if hostname.lower() in ('localhost', 'localhost.localdomain'):
                return match.group(0)
            token = self._get_token('host', hostname, self.map.hostnames)
            return f"{match.group(1)}{token}"

        # FIX #2: only replace when preceded by explicit host context labels
        text = re.sub(
            r'(host=|hostname=|HOSTNAME=)([a-zA-Z0-9][a-zA-Z0-9.\-]*)',
            replace_hostname,
            text
        )
        return text

    def obfuscate(self, text: str) -> str:
        """
        Obfuscate sensitive data in Falco alert text based on configured level.

        Levels:
        - minimal: Only secrets/credentials
        - standard: IPs, emails, containers, users, k8s context
        - paranoid: Everything including paths, hostnames, high-entropy strings
        """
        if not text:
            return text

        # Always obfuscate secrets regardless of level
        result = self._obfuscate_secrets(text)

        if self.level == ObfuscationLevel.MINIMAL:
            return result

        # Standard level
        result = self._obfuscate_ips(result)
        result = self._obfuscate_emails(result)
        result = self._obfuscate_containers(result)
        result = self._obfuscate_users(result)
        result = self._obfuscate_k8s(result)  # FIX #6

        if self.level == ObfuscationLevel.PARANOID:
            result = self._obfuscate_paths(result)
            result = self._obfuscate_hostnames(result)
            result = self._obfuscate_high_entropy(result)

        return result

    def get_mapping(self) -> dict:
        return self.map.to_dict()


def obfuscate_alert(alert: dict, level: str = "standard") -> tuple[dict, dict]:
    """
    Convenience function to obfuscate a Falco alert dictionary.

    Args:
        alert: Falco alert dictionary with 'output', 'output_fields', etc.
        level: Obfuscation level (minimal, standard, paranoid)

    Returns:
        Tuple of (obfuscated_alert, obfuscation_mapping)
    """
    obfuscator = Obfuscator(ObfuscationLevel(level))

    obfuscated = alert.copy()

    if 'output' in obfuscated:
        obfuscated['output'] = obfuscator.obfuscate(obfuscated['output'])

    if 'output_fields' in obfuscated:
        fields = obfuscated['output_fields'].copy()
        for key, value in fields.items():
            if isinstance(value, str):
                fields[key] = obfuscator.obfuscate(value)
        obfuscated['output_fields'] = fields

    return obfuscated, obfuscator.get_mapping()


# ---------------------------------------------------------------------------
# Quick smoke-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    test_alert = """
    Read sensitive file untrusted: user=jsmith command=cat /etc/shadow 
    container=a1b2c3d4e5f6 (nginx:latest) connection from 192.168.1.100 
    to external IP 52.94.233.12:443 password=secret123 
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE email=admin@company.com
    host=prod-web-01.acme.com pid=12345 uid=1001 auid=1001 euid=0
    pod=nginx-deployment-7d5b9c namespace=production login=jsmith
    /home/jsmith/.ssh/id_rsa
    """

    print("=== MINIMAL (only secrets) ===")
    obfuscator = Obfuscator(ObfuscationLevel.MINIMAL)
    print(obfuscator.obfuscate(test_alert))

    print("\n=== STANDARD (IPs, users, containers, k8s) ===")
    obfuscator = Obfuscator(ObfuscationLevel.STANDARD)
    print(obfuscator.obfuscate(test_alert))

    print("\n=== PARANOID (maximum privacy) ===")
    obfuscator = Obfuscator(ObfuscationLevel.PARANOID)
    print(obfuscator.obfuscate(test_alert))
    print("\nMapping:", obfuscator.get_mapping())
