#!/usr/bin/env bash
# Build build/agent.zip for AgentCore direct code deployment (PYTHON_3_14, arm64).
# Installs only hash-verified wheels from agent/requirements.lock.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
stage="$root/build/agent_pkg"
rm -rf "$stage" "$root/build/agent.zip"
mkdir -p "$stage"

python3.14 -m pip install -q --no-deps --require-hashes --only-binary=:all: \
  --platform manylinux2014_aarch64 --platform manylinux_2_28_aarch64 --platform manylinux_2_34_aarch64 \
  --python-version 3.14 --implementation cp \
  --target "$stage" -r "$root/agent/requirements.lock"

cp "$root/agent/app.py" "$root/agent/sigv4_auth.py" "$stage/"
find "$stage" -name '__pycache__' -type d -prune -exec rm -rf {} +
# Deterministic archive: sorted entries, fixed timestamps.
python3.14 - "$stage" "$root/build/agent.zip" <<'PY'
import pathlib, sys, zipfile
stage, out = pathlib.Path(sys.argv[1]), sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
    for path in sorted(p for p in stage.rglob("*") if p.is_file()):
        info = zipfile.ZipInfo(str(path.relative_to(stage)), date_time=(2026, 1, 1, 0, 0, 0))
        info.external_attr = 0o644 << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(info, path.read_bytes())
PY
echo "built $root/build/agent.zip ($(du -h "$root/build/agent.zip" | cut -f1))"
