#!/usr/bin/env bash
# build.sh -- package individual .skill zips and the combined .plugin for f5xc-waf-skills
# Usage: ./scripts/build.sh [--clean]
#
# Uses the `zip` binary when available and falls back to python3's zipfile module
# otherwise (zip is not installed on stock WSL/Ubuntu images, and python3 always is).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SKILLS_DIR="$PLUGIN_DIR/skills"
DIST_DIR="$PLUGIN_DIR/dist"
SKILLS=(xc-security-events xc-waf-config xc-api-security xc-bot-defense xc-waf-tuning xc-waf-investigator xc-waf-solutions)

[ "${1:-}" = "--clean" ] && rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

VERSION=$(python3 -c "import json;print(json.load(open('$PLUGIN_DIR/.claude-plugin/plugin.json'))['version'])")

if command -v zip >/dev/null 2>&1; then
  for s in "${SKILLS[@]}"; do
    ( cd "$SKILLS_DIR" && zip -qr "$DIST_DIR/$s.skill" "$s" -x "*__pycache__*" )
    echo "built dist/$s.skill"
  done
  ( cd "$PLUGIN_DIR" && zip -qr "$DIST_DIR/f5xc-waf-skills-v${VERSION}.plugin" \
      .claude-plugin CLAUDE.md README.md skills hooks docs -x "*__pycache__*" "*dist*" )
  echo "built dist/f5xc-waf-skills-v${VERSION}.plugin"
else
  echo "note: 'zip' not found — using python3 zipfile fallback"
  PLUGIN_DIR="$PLUGIN_DIR" DIST_DIR="$DIST_DIR" SKILLS_DIR="$SKILLS_DIR" \
  VERSION="$VERSION" SKILLS="${SKILLS[*]}" python3 - <<'PY'
import os, pathlib, zipfile

plugin = pathlib.Path(os.environ["PLUGIN_DIR"])
dist   = pathlib.Path(os.environ["DIST_DIR"])
skills = pathlib.Path(os.environ["SKILLS_DIR"])
version = os.environ["VERSION"]

def skip(p: pathlib.Path) -> bool:
    return "__pycache__" in p.parts or p.suffix == ".pyc"

def write(zf: zipfile.ZipFile, root: pathlib.Path, base: pathlib.Path):
    for f in sorted(root.rglob("*")):
        if f.is_file() and not skip(f):
            zf.write(f, f.relative_to(base).as_posix())

for s in os.environ["SKILLS"].split():
    out = dist / f"{s}.skill"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        write(zf, skills / s, skills)
    print(f"built dist/{out.name}")

out = dist / f"f5xc-waf-skills-v{version}.plugin"
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
    for top in (".claude-plugin", "skills", "hooks", "docs"):
        d = plugin / top
        if d.is_dir():
            write(zf, d, plugin)
    for top in ("CLAUDE.md", "README.md"):
        f = plugin / top
        if f.is_file():
            zf.write(f, top)
print(f"built dist/{out.name}")
PY
fi
