#!/bin/sh
# Cargo runner: ad-hoc sign the binary with the hypervisor entitlement, then run it.
# codesign's output is shown only when signing fails (a successful run would
# print "replacing existing signature" every time).
set -e
bin="$1"; shift
here="$(cd "$(dirname "$0")/.." && pwd)"
if ! out="$(codesign --force --sign - --entitlements "$here/vemu.entitlements" "$bin" 2>&1)"; then
  printf 'run-signed: cannot sign %s with %s:\n%s\n' "$bin" "$here/vemu.entitlements" "$out" >&2
  exit 1
fi
exec "$bin" "$@"
