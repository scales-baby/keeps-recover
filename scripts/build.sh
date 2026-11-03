#!/bin/sh
# Reproducible build. The release artifact is keeps-recover.js itself (no compile, no
# bundler, no dependencies), so the build is a byte-for-byte copy plus its SHA-256.
#   sh scripts/build.sh          -> dist/keeps-recover.js, dist/SHA256SUMS
#   sh scripts/build.sh --check  -> also fail unless dist/SHA256SUMS == committed SHA256SUMS
set -eu
cd "$(dirname "$0")/.."
rm -rf dist
mkdir dist
cp keeps-recover.js dist/keeps-recover.js
chmod 0644 dist/keeps-recover.js
if command -v sha256sum >/dev/null 2>&1; then SHA="sha256sum"; else SHA="shasum -a 256"; fi
(cd dist && $SHA keeps-recover.js > SHA256SUMS)
cat dist/SHA256SUMS
if [ "${1:-}" = "--check" ]; then
  cmp dist/SHA256SUMS SHA256SUMS || { echo "SHA256SUMS mismatch: rebuild differs from the committed hash" >&2; exit 1; }
  echo "reproducible: dist matches committed SHA256SUMS"
fi
