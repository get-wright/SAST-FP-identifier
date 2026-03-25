"""Detect known sanitizers and check conditional placement."""

from __future__ import annotations

from typing import Optional

from src.models.analysis import SanitizerInfo

_SANITIZER_DB: dict[str, list[str]] = {
    "CWE-79": [
        "html.escape", "markupsafe.escape", "bleach.clean", "sanitize",
        "escapehtml", "htmlspecialchars", "encodeURIComponent",
        "dompurify.sanitize", "textcontent", "innertext",
        "cgi.escape", "xss_clean", "strip_tags",
    ],
    "CWE-89": [
        "parameterize", "prepare", "placeholder", "sanitize_sql",
        "quote_identifier", "escape_string", "mysql_real_escape_string",
    ],
    "CWE-78": [
        "shlex.quote", "escapeshellarg", "escapeshellcmd", "shellescape",
    ],
    "CWE-22": [
        "os.path.basename", "os.path.normpath", "path.resolve",
        "realpath", "securejoin", "filepath.clean",
    ],
}

_SANITIZER_LOOKUP: dict[str, list[str]] = {}
for _cwe, _names in _SANITIZER_DB.items():
    for _name in _names:
        _key = _name.lower()
        if _key not in _SANITIZER_LOOKUP:
            _SANITIZER_LOOKUP[_key] = []
        _SANITIZER_LOOKUP[_key].append(_cwe)
        # Also index the bare suffix so "escape" matches "html.escape"
        if "." in _key:
            _suffix = _key.rsplit(".", 1)[-1]
            if _suffix not in _SANITIZER_LOOKUP:
                _SANITIZER_LOOKUP[_suffix] = []
            if _cwe not in _SANITIZER_LOOKUP[_suffix]:
                _SANITIZER_LOOKUP[_suffix].append(_cwe)


def check_known_sanitizer(callee_name: str) -> Optional[SanitizerInfo]:
    key = callee_name.lower()
    if key in _SANITIZER_LOOKUP:
        return SanitizerInfo(name=callee_name, line=0, cwe_categories=_SANITIZER_LOOKUP[key],
                             conditional=False, verified=False)
    if "." in key:
        suffix = key.rsplit(".", 1)[-1]
        if suffix in _SANITIZER_LOOKUP:
            return SanitizerInfo(name=callee_name, line=0, cwe_categories=_SANITIZER_LOOKUP[suffix],
                                 conditional=False, verified=False)
    return None


def is_conditional_ancestor(node, conditional_types: tuple[str, ...]) -> bool:
    current = node.parent
    while current is not None:
        if current.type in conditional_types:
            return True
        if current.type in (
            "function_definition", "function_declaration", "method_definition",
            "method_declaration", "arrow_function", "constructor_declaration",
        ):
            break
        current = current.parent
    return False
