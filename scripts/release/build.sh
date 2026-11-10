#!/bin/sh
# Inside the release image: builds every package and leaves them in /out with VERSION and SHA256SUMS.
#   docker run --rm -v "$PWD":/src -v "$OUT":/out penteos-release sh scripts/release/build.sh [x64,arm64]
set -eu
ARCHES="${1:-x64,arm64}"
# Compiled output must never sit next to the sources: the bundler would take a stale .js over the
# .ts beside it (it happened: operations missing from a package). None of them is ever legitimate.
stale="$(find packages -path '*/node_modules' -prune -o -path '*/src/*' \( -name '*.js' -o -name '*.d.ts' -o -name '*.js.map' \) -print)"
if [ -n "$stale" ]; then echo "removing $(echo "$stale" | wc -l) stale compiled files next to the sources"; echo "$stale" | xargs rm -f; fi
pnpm install --frozen-lockfile
pnpm --filter @penteos/desktop package -- --arch "$ARCHES"
VERSION="$(node -p "require('./apps/desktop/package.json').version")"
mkdir -p /out
rm -f /out/penteos-* /out/SHA256SUMS /out/VERSION
for f in apps/desktop/release/penteos-"$VERSION"-*; do cp "$f" /out/; done
cp scripts/install.sh /out/install.sh
printf '%s\n' "$VERSION" > /out/VERSION
(cd /out && sha256sum penteos-* > SHA256SUMS)
cat apps/desktop/build/native.json
ls -la /out
