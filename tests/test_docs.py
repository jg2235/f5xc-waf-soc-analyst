#!/usr/bin/env python3
"""
Regression guard for API-naming defects in skill documentation.

Every defect this suite covers was found the hard way against a live tenant, and
two of them FAILED SILENTLY -- a wrong filter key returns zero hits instead of an
error, which reads as "this signature never fired" rather than as a bug. That is
why these are enforced in CI rather than left to review.

Run:  python3 tests/test_docs.py     (or: python3 -m pytest tests/ -q)
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"

# Lines that TALK ABOUT a bad name (to warn readers) are legitimate. A line is
# exempt if it carries one of these markers.
WARN_MARKERS = (
    "rejected", "REJECTED", "not valid", "NOT valid", "does not exist",
    "returns null", "reads null", "silently", "Rejected by the enum",
    "do not use", "invalid", "trap", "NOT aggregatable", "not aggregatable",
    "mistakes", "DIFFERENT enum", "Do not carry",
)

# Agg-field names the event enum rejects (HTTP 400). Verified 2026-08-18.
BAD_AGG_FIELDS = [
    "CALCULATED_ACTION", "REQ_PATH", "RSP_CODE", "USER_AGENT",
    "APP_FIREWALL_NAME", "API_ENDPOINT", "TIMESTAMP",
]
# Access logs use a DIFFERENT enum where some of these are valid, so files
# discussing access logs are exempt for those two names.
ACCESS_LOG_OK = {"REQ_PATH", "RSP_CODE"}

failures: list[str] = []


def fail(msg: str) -> None:
    failures.append(msg)


def md_files():
    yield from SKILLS.rglob("*.md")


def exempt_lines(text: str) -> set[int]:
    """1-indexed lines inside a warning block.

    A block starts at a line carrying a WARN_MARKER and runs to the next blank
    line, so a marker sentence covers the field list that follows it. Without
    this, the docs that *warn* about a bad name trip the very check they exist
    to enforce.
    """
    out, active = set(), False
    for n, line in enumerate(text.splitlines(), 1):
        if any(m in line for m in WARN_MARKERS):
            active = True
        elif not line.strip():
            active = False
        if active:
            out.add(n)
    return out


def test_no_bad_agg_fields():
    """Documented aggregation fields must exist in the event enum."""
    for f in md_files():
        text = f.read_text()
        ex = exempt_lines(text)
        for n, line in enumerate(text.splitlines(), 1):
            if n in ex:
                continue
            for bad in BAD_AGG_FIELDS:
                if re.search(rf"\b{bad}\b", line):
                    if bad in ACCESS_LOG_OK and ("access_log" in line or "Access log" in line):
                        continue
                    fail(f"{f.relative_to(ROOT)}:{n}: invalid agg field '{bad}' "
                         f"(request path is URI; client is BROWSER_TYPE)")


def test_signature_filter_key():
    """The event filter key is signatures.id; signature_id= returns 0 silently."""
    for f in list(md_files()) + list(SKILLS.rglob("*.py")):
        # xc-waf-config documents waf_exclusion_rules[].signature_id, a CONFIG
        # object field -- correct and unrelated to the query key.
        if "xc-waf-config" in str(f):
            continue
        text = f.read_text()
        ex = exempt_lines(text)
        for n, line in enumerate(text.splitlines(), 1):
            if n in ex:
                continue
            if re.search(r"signature_id\s*=", line) or re.search(r"`signature_id`", line):
                fail(f"{f.relative_to(ROOT)}:{n}: use 'signatures.id' as the event "
                     f"filter key -- 'signature_id' returns 0 hits SILENTLY")


def test_no_calculated_action():
    """calculated_action does not exist; the field is recommended_action."""
    for f in list(md_files()) + list(SKILLS.rglob("*.py")):
        text = f.read_text()
        ex = exempt_lines(text)
        for n, line in enumerate(text.splitlines(), 1):
            if n in ex:
                continue
            if "calculated_action" in line.lower():
                fail(f"{f.relative_to(ROOT)}:{n}: 'calculated_action' does not exist "
                     f"-- use 'recommended_action' (record field only, not aggregatable)")


def test_manifests_valid_and_agree():
    """plugin.json and marketplace.json must parse and reference each other."""
    pj = ROOT / ".claude-plugin" / "plugin.json"
    mj = ROOT / ".claude-plugin" / "marketplace.json"
    for p in (pj, mj):
        if not p.exists():
            fail(f"missing manifest: {p.relative_to(ROOT)}")
            return
    plugin = json.loads(pj.read_text())
    market = json.loads(mj.read_text())
    if not re.fullmatch(r"\d+\.\d+\.\d+", plugin.get("version", "")):
        fail(f"plugin.json: version '{plugin.get('version')}' is not semver")
    if not market.get("description"):
        fail("marketplace.json: missing description (claude plugin validate warns)")
    names = {p.get("name") for p in market.get("plugins", [])}
    if plugin.get("name") not in names:
        fail(f"marketplace.json does not list plugin '{plugin.get('name')}'")


def test_changelog_matches_version():
    """CHANGELOG must document the version in plugin.json."""
    plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
    v = plugin.get("version")
    ch = ROOT / "CHANGELOG.md"
    if not ch.exists():
        fail("missing CHANGELOG.md")
    elif f"[{v}]" not in ch.read_text():
        fail(f"CHANGELOG.md has no entry for version {v}")


def test_skill_frontmatter():
    """Every skill needs name + description frontmatter to be discoverable."""
    for d in sorted(p for p in SKILLS.iterdir() if p.is_dir()):
        sk = d / "SKILL.md"
        if not sk.exists():
            fail(f"{d.name}: missing SKILL.md")
            continue
        text = sk.read_text()
        if not text.startswith("---"):
            fail(f"{d.name}/SKILL.md: missing YAML frontmatter")
            continue
        fm = text.split("---", 2)[1]
        for key in ("name:", "description:"):
            if key not in fm:
                fail(f"{d.name}/SKILL.md: frontmatter missing '{key}'")
        m = re.search(r"^name:\s*(\S+)", fm, re.M)
        if m and m.group(1) != d.name:
            fail(f"{d.name}/SKILL.md: frontmatter name '{m.group(1)}' != directory")


def test_python_compiles():
    """All shipped Python must at least byte-compile."""
    for f in ROOT.rglob("*.py"):
        if any(x in f.parts for x in ("__pycache__", ".venv", "venv", "reports")):
            continue
        try:
            compile(f.read_text(), str(f), "exec")
        except SyntaxError as e:
            fail(f"{f.relative_to(ROOT)}: syntax error line {e.lineno}: {e.msg}")


def test_no_secrets_committed():
    """No literal token material anywhere in tracked source."""
    pat = re.compile(r"(APIToken\s+[A-Za-z0-9+/=]{20,}|F5XC_API_TOKEN\s*=\s*[\"']?[A-Za-z0-9+/=]{20,})")
    for f in ROOT.rglob("*"):
        if not f.is_file() or any(x in f.parts for x in
                                  (".git", "dist", "reports", "changes", "__pycache__")):
            continue
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        if pat.search(text):
            fail(f"{f.relative_to(ROOT)}: possible committed credential")


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    if failures:
        print(f"FAILED — {len(failures)} problem(s):\n")
        for f in failures:
            print(f"  ✗ {f}")
        return 1
    print(f"OK — {len(tests)} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
