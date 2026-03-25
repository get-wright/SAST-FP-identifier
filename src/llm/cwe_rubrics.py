"""Per-CWE micro-rubrics for dynamic LLM guidance.

Each rubric provides CWE-specific patterns the LLM should look for during triage.
Rubrics are selected dynamically based on Semgrep finding metadata.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class CWERubric:
    """Triage guidance for one CWE category."""
    cwe_id: int
    name: str
    high_risk: list[str] = field(default_factory=list)    # patterns -> likely TP
    safe_patterns: list[str] = field(default_factory=list) # patterns -> likely FP
    not_sanitizers: list[str] = field(default_factory=list) # look safe but aren't


# Registry keyed by CWE ID
_RUBRICS: dict[int, CWERubric] = {}

# Also index by vulnerability_class string (from Semgrep metadata)
_CLASS_TO_CWE: dict[str, int] = {}


def _register(rubric: CWERubric, vuln_classes: list[str] | None = None) -> None:
    _RUBRICS[rubric.cwe_id] = rubric
    if vuln_classes:
        for vc in vuln_classes:
            _CLASS_TO_CWE[vc.lower()] = rubric.cwe_id


# --- SQL Injection (CWE-89) ---
_register(CWERubric(
    cwe_id=89,
    name="SQL Injection",
    high_risk=[
        "String concatenation or f-strings/template literals building SQL queries with user input",
        "Raw SQL execution (cursor.execute, createNativeQuery, sequelize.query) with interpolated values",
        "Dynamic table/column names from user input without allowlist",
    ],
    safe_patterns=[
        "Parameterized queries / prepared statements (?, $1, :param placeholders)",
        "ORM query builders (Django ORM, SQLAlchemy, Sequelize, Prisma, ActiveRecord)",
        "Allowlist validation of table/column names against known constants",
        "Static SQL strings with no dynamic components",
    ],
    not_sanitizers=[
        "String escaping/quoting (mysql_real_escape_string, addslashes) — bypassable",
        "Type casting alone (int(), str()) without parameterized queries",
        "Blacklist filtering of SQL keywords",
        "Length limits on input",
    ],
), vuln_classes=["SQL Injection"])

# --- XSS (CWE-79) ---
_register(CWERubric(
    cwe_id=79,
    name="Cross-Site Scripting (XSS)",
    high_risk=[
        "innerHTML/outerHTML assignment with user-controlled data",
        "document.write() with dynamic content",
        "Jinja2/Mako template with |safe or {% autoescape false %}",
        "React dangerouslySetInnerHTML with unsanitized input",
        "v-html (Vue) or {@html} (Svelte) with user data",
    ],
    safe_patterns=[
        "textContent/innerText assignment (no HTML parsing)",
        "Template auto-escaping active (Django, Jinja2 default, React JSX, Vue templates, Svelte default)",
        "DOMPurify.sanitize() or bleach.clean() before insertion",
        "encodeURIComponent() for URL parameters",
        "Static HTML string constants (no dynamic values)",
        "Content-Security-Policy with strict nonce/hash",
    ],
    not_sanitizers=[
        "Custom regex-based HTML stripping — often bypassable",
        "Encoding only < and > but not quotes or attributes",
        "Server-side sanitization alone without CSP (stored XSS can bypass)",
    ],
), vuln_classes=["Cross-Site-Scripting", "XSS"])

# --- Command Injection (CWE-78) ---
_register(CWERubric(
    cwe_id=78,
    name="OS Command Injection",
    high_risk=[
        "os.system(), subprocess.call(shell=True) with user input",
        "exec(), eval(), child_process.exec() with interpolated strings",
        "GitHub Actions ${{ }} interpolation in run: steps with user-controlled context (PR title, branch name, commit message)",
        "Backtick command substitution with dynamic values",
    ],
    safe_patterns=[
        "subprocess with array arguments (no shell=True)",
        "shlex.quote() / escapeshellarg() wrapping all dynamic values",
        "Allowlist validation of command arguments",
        "GitHub Actions: using environment variables instead of direct ${{ }} interpolation",
    ],
    not_sanitizers=[
        "Blacklist filtering of shell metacharacters (;, |, &) — incomplete",
        "Path validation alone without argument escaping",
        "Git branch name restrictions — do NOT prevent shell metacharacters like backticks or $()",
    ],
), vuln_classes=["Command Injection"])

# --- Path Traversal (CWE-22) ---
_register(CWERubric(
    cwe_id=22,
    name="Path Traversal",
    high_risk=[
        "File path built from user input with string concatenation (os.path.join, path.resolve with user segment)",
        "open(user_input), fs.readFile(user_input) without path validation",
        "Archive extraction (zip, tar) without checking entry paths for ../",
    ],
    safe_patterns=[
        "os.path.realpath() + startswith() check against allowed base directory",
        "Path.resolve() compared against known root",
        "Allowlist of permitted filenames/paths",
        "chroot or container-level filesystem isolation",
    ],
    not_sanitizers=[
        "Stripping ../ once — can be bypassed with ....// or URL encoding",
        "Checking for .. without resolving symlinks first",
        "Basename extraction alone (may still allow absolute paths)",
    ],
), vuln_classes=["Path Traversal"])

# --- CSRF (CWE-352) ---
_register(CWERubric(
    cwe_id=352,
    name="Cross-Site Request Forgery",
    high_risk=[
        "HTML form with method=POST and no CSRF token",
        "State-changing API endpoint without CSRF validation or SameSite cookie",
        "Custom AJAX without CSRF header/token when cookies are used for auth",
    ],
    safe_patterns=[
        "Framework CSRF middleware active (Django CsrfViewMiddleware, Rails protect_from_forgery, Laravel VerifyCsrfToken)",
        "SameSite=Strict or SameSite=Lax cookies with no cross-origin state changes",
        "Bearer token / API key auth (not cookie-based — CSRF not applicable)",
        "GET/HEAD/OPTIONS requests (safe methods — CSRF not relevant)",
    ],
    not_sanitizers=[
        "Referer/Origin header checking alone — can be spoofed or absent",
        "CORS configuration — does not prevent CSRF from same-origin contexts",
    ],
), vuln_classes=["Cross-Site Request Forgery (CSRF)", "CSRF"])

# --- SSRF (CWE-918) ---
_register(CWERubric(
    cwe_id=918,
    name="Server-Side Request Forgery",
    high_risk=[
        "HTTP client (requests, fetch, urllib, HttpClient) with user-controlled URL",
        "URL parameter used directly in server-side request without validation",
        "Internal service discovery via user-supplied hostnames",
    ],
    safe_patterns=[
        "URL parsed and domain validated against allowlist before request",
        "IP address resolution checked against private/internal ranges (10.x, 172.16.x, 192.168.x, 127.x, ::1)",
        "Proxy/gateway that strips internal routing headers",
    ],
    not_sanitizers=[
        "Blocklist of internal IPs — bypassable via DNS rebinding or alternative encodings",
        "URL regex validation — often bypassed with @, #, or unicode",
    ],
), vuln_classes=["Server-Side Request Forgery (SSRF)", "SSRF"])

# --- Insecure Hashing (CWE-328) ---
_register(CWERubric(
    cwe_id=328,
    name="Use of Weak Hash",
    high_risk=[
        "MD5/SHA1 for password hashing or storage",
        "MD5/SHA1 for digital signatures, certificates, or HMAC keys",
        "Unsalted hash for any authentication purpose",
    ],
    safe_patterns=[
        "MD5/SHA1 for non-security purposes: cache keys, ETags, checksums, deduplication, content addressing",
        "bcrypt, scrypt, argon2, PBKDF2 for password hashing",
        "SHA-256+ for cryptographic purposes",
    ],
    not_sanitizers=[],
), vuln_classes=["Use of a Broken or Risky Cryptographic Algorithm", "Insecure Hashing"])

# --- Hard-coded Secrets (CWE-798) ---
_register(CWERubric(
    cwe_id=798,
    name="Hard-coded Credentials",
    high_risk=[
        "Private API keys, tokens, or passwords in source code",
        "Database connection strings with embedded credentials",
        "Cloud provider access keys (AWS, GCP, Azure) in committed files",
    ],
    safe_patterns=[
        "Public API keys (e.g., public Stripe publishable key, public RSS feed URL parameters)",
        "Placeholder/example values in .example files or documentation",
        "Environment variable references (os.environ, process.env) — not hardcoded",
        "Test/mock credentials in test fixtures",
    ],
    not_sanitizers=[],
), vuln_classes=["Hard-coded Secrets", "Secret Detection"])

# --- Insecure Transport (CWE-319) ---
_register(CWERubric(
    cwe_id=319,
    name="Cleartext Transmission",
    high_risk=[
        "HTTP URLs used for actual network requests transmitting sensitive data (passwords, tokens, PII)",
        "Disabled TLS verification (verify=False, rejectUnauthorized=false) in production",
    ],
    safe_patterns=[
        "HTTP URLs in string comparisons, URL normalization, or scheme detection logic",
        "HTTP URLs for localhost/development-only connections",
        "HTTP URLs in comments, documentation, or error messages",
        "HTTPS redirect logic that references http:// as the source scheme",
    ],
    not_sanitizers=[],
), vuln_classes=["Insecure Transport"])

# --- Deserialization (CWE-502) ---
_register(CWERubric(
    cwe_id=502,
    name="Insecure Deserialization",
    high_risk=[
        "pickle.loads(), yaml.load() (without SafeLoader), unserialize() with user input",
        "Java ObjectInputStream on untrusted data",
        "JSON.parse() is generally SAFE — only flag pickle/yaml/marshal equivalents",
    ],
    safe_patterns=[
        "JSON.parse(), json.loads() — no code execution risk",
        "yaml.safe_load() or yaml.load(Loader=SafeLoader)",
        "Protobuf, MessagePack, or schema-validated deserialization",
        "Signed/encrypted serialized data with integrity verification before deserialization",
    ],
    not_sanitizers=[
        "Type checking after deserialization — too late, gadget chains execute during deserialize",
    ],
), vuln_classes=["Insecure Deserialization", "Deserialization of Untrusted Data"])

# --- ReDoS (CWE-1333) ---
_register(CWERubric(
    cwe_id=1333,
    name="Regular Expression Denial of Service",
    high_risk=[
        "User-controlled input used directly as regex pattern (new RegExp(userInput))",
        "Regex with nested quantifiers on user input (e.g., (a+)+ or (a|a)*)",
    ],
    safe_patterns=[
        "Regex pattern from developer-controlled source (config file, hardcoded constant, translation keys)",
        "Input properly escaped before regex construction (escapeRegExp, replace special chars)",
        "Script/CLI tool not exposed to untrusted input",
        "RE2 or other linear-time regex engine",
    ],
    not_sanitizers=[
        "Length limits alone — short strings can still trigger exponential backtracking",
    ],
), vuln_classes=["Denial-of-Service (DoS)", "ReDoS"])

# --- Prototype Pollution (CWE-1321) ---
_register(CWERubric(
    cwe_id=1321,
    name="Prototype Pollution",
    high_risk=[
        "Deep merge/extend of user-controlled objects without __proto__ filtering",
        "Object.assign(target, userInput) where userInput could contain __proto__",
        "Recursive property copy from untrusted JSON without key sanitization",
    ],
    safe_patterns=[
        "Object.assign with spread syntax ({ ...defaults, ...parsed }) — spread ignores __proto__",
        "JSON.parse() output — __proto__ becomes regular property, not prototype link",
        "Map/Set instead of plain objects for dynamic keys",
        "Object.create(null) as target (no prototype chain)",
        "localStorage data — user can only pollute their own session (self-XSS scope)",
    ],
    not_sanitizers=[],
), vuln_classes=["Prototype Pollution"])

# --- Dockerfile Misconfiguration (CWE-250) ---
_register(CWERubric(
    cwe_id=250,
    name="Execution with Unnecessary Privileges",
    high_risk=[
        "Dockerfile without USER directive — container runs as root",
        "Privileged container (--privileged flag)",
        "Unnecessary capabilities (CAP_SYS_ADMIN, CAP_NET_RAW)",
    ],
    safe_patterns=[
        "USER directive setting non-root user before CMD/ENTRYPOINT",
        "Distroless or scratch base images (minimal attack surface)",
        "Read-only root filesystem (--read-only)",
    ],
    not_sanitizers=[],
), vuln_classes=["Dockerfile Misconfiguration"])

# --- Generic fallback ---
_GENERIC_RUBRIC = CWERubric(
    cwe_id=0,
    name="Generic",
    high_risk=["User-controlled data reaches a security-sensitive sink without sanitization"],
    safe_patterns=["Input validated/sanitized before reaching sink", "Framework-provided protection active", "Data source is trusted (hardcoded, internal config, developer-controlled)"],
    not_sanitizers=[],
)


def get_rubric(cwe_id: int) -> CWERubric:
    """Look up rubric by CWE ID. Returns generic fallback if not found."""
    return _RUBRICS.get(cwe_id, _GENERIC_RUBRIC)


def get_rubric_by_class(vulnerability_class: str) -> CWERubric | None:
    """Look up rubric by Semgrep vulnerability_class string."""
    cwe_id = _CLASS_TO_CWE.get(vulnerability_class.lower())
    if cwe_id:
        return _RUBRICS[cwe_id]
    return None


def get_rubrics_for_findings(findings: list[dict]) -> list[CWERubric]:
    """Select unique rubrics relevant to a set of findings.

    Looks up by CWE ID first, then by vulnerability_class, then falls back to generic.
    Returns deduplicated list of rubrics.
    """
    seen_ids: set[int] = set()
    rubrics: list[CWERubric] = []

    for f in findings:
        rubric = None
        # Try CWE IDs from metadata
        for cwe_str in f.get("cwe", []):
            # Parse "CWE-89: Improper Neutralization..." -> 89
            cwe_id = _parse_cwe_id(cwe_str)
            if cwe_id and cwe_id in _RUBRICS:
                rubric = _RUBRICS[cwe_id]
                break

        # Try vulnerability_class
        if not rubric:
            vc = f.get("vulnerability_class")
            if vc:
                rubric = get_rubric_by_class(vc)

        if rubric and rubric.cwe_id not in seen_ids:
            seen_ids.add(rubric.cwe_id)
            rubrics.append(rubric)

    # If no specific rubric matched, include generic
    if not rubrics:
        rubrics.append(_GENERIC_RUBRIC)

    return rubrics


def format_rubrics_for_prompt(rubrics: list[CWERubric]) -> str:
    """Format rubrics as text for inclusion in LLM prompt."""
    if not rubrics:
        return ""

    parts = []
    for r in rubrics:
        lines = [f"[{r.name} (CWE-{r.cwe_id})]" if r.cwe_id else f"[{r.name}]"]
        if r.high_risk:
            lines.append("  High risk (likely TRUE POSITIVE):")
            for p in r.high_risk:
                lines.append(f"    - {p}")
        if r.safe_patterns:
            lines.append("  Safe patterns (likely FALSE POSITIVE):")
            for p in r.safe_patterns:
                lines.append(f"    - {p}")
        if r.not_sanitizers:
            lines.append("  NOT sanitizers (look safe but aren't):")
            for p in r.not_sanitizers:
                lines.append(f"    - {p}")
        parts.append("\n".join(lines))

    return "\n\n".join(parts)


def _parse_cwe_id(cwe_str: str) -> int | None:
    """Extract numeric CWE ID from strings like 'CWE-89: ...' or 'CWE-89'."""
    m = re.match(r"CWE-(\d+)", cwe_str)
    return int(m.group(1)) if m else None
