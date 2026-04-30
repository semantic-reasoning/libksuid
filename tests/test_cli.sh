#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-or-later
#
# Integration test for the ksuid-gen binary. Drives the CLI directly
# and verifies the round-trip generation + parse contract that the
# user-facing requirement asks for.

set -eu

KSUID_GEN="${1:?usage: test_cli.sh <path/to/ksuid-gen>}"

# 1. Default invocation emits exactly one 27-character base62 line.
out=$("$KSUID_GEN")
if [ "${#out}" -ne 27 ]; then
  echo "expected 27-char default output, got ${#out}: $out" >&2
  exit 1
fi
case "$out" in
  *[!0-9A-Za-z]*)
    echo "default output contains non-base62 char: $out" >&2
    exit 1
    ;;
esac

# 2. -n 4 emits 4 distinct 27-char lines.
out=$("$KSUID_GEN" -n 4)
n_lines=$(printf '%s\n' "$out" | wc -l)
if [ "$n_lines" -ne 4 ]; then
  echo "expected 4 lines from -n 4, got $n_lines:" >&2
  printf '%s\n' "$out" >&2
  exit 1
fi
n_uniq=$(printf '%s\n' "$out" | sort -u | wc -l)
if [ "$n_uniq" -ne 4 ]; then
  echo "expected 4 distinct KSUIDs, got $n_uniq" >&2
  exit 1
fi

# 3. Round trip: parse the previously-generated KSUIDs back through
#    the CLI and confirm we get the same string.
sample=$(printf '%s\n' "$out" | head -1)
back=$("$KSUID_GEN" "$sample")
if [ "$sample" != "$back" ]; then
  echo "round-trip mismatch: $sample vs $back" >&2
  exit 1
fi

# 4. Inspect format includes the canonical labels.
inspect=$("$KSUID_GEN" -f inspect "$sample")
for label in "REPRESENTATION:" "  String:" "     Raw:" \
             "COMPONENTS:" "       Time:" "  Timestamp:" \
             "    Payload:"; do
  case "$inspect" in
    *"$label"*) ;;
    *)
      echo "inspect output missing '$label':" >&2
      printf '%s\n' "$inspect" >&2
      exit 1
      ;;
  esac
done

# 5. Verbose mode prefixes each line with the KSUID and ": ".
verbose=$("$KSUID_GEN" -v -f timestamp "$sample")
case "$verbose" in
  "$sample: "*) ;;
  *)
    echo "expected -v output to start with '$sample: ', got: $verbose" >&2
    exit 1
    ;;
esac

# 6. Known golden vector parses to the documented timestamp.
expected_ts=107608047
actual_ts=$("$KSUID_GEN" -f timestamp 0ujtsYcgvSTl8PAuAdqWYSMnLOv)
if [ "$actual_ts" != "$expected_ts" ]; then
  echo "expected timestamp $expected_ts for sample, got $actual_ts" >&2
  exit 1
fi

# 7. -f raw emits exactly 20 bytes (binary).
n_raw=$("$KSUID_GEN" -f raw 0ujtsYcgvSTl8PAuAdqWYSMnLOv | wc -c)
if [ "$n_raw" -ne 20 ]; then
  echo "expected 20 bytes from -f raw, got $n_raw" >&2
  exit 1
fi

# 8. -f payload emits exactly 16 bytes.
n_pl=$("$KSUID_GEN" -f payload 0ujtsYcgvSTl8PAuAdqWYSMnLOv | wc -c)
if [ "$n_pl" -ne 16 ]; then
  echo "expected 16 bytes from -f payload, got $n_pl" >&2
  exit 1
fi

# 9. Bogus input rejected with non-zero exit.
if "$KSUID_GEN" -f string toolong-toolong-toolong-toolong 2>/dev/null; then
  echo "expected non-zero exit for bad-length input" >&2
  exit 1
fi

# 10. Bogus format rejected.
if "$KSUID_GEN" -f wat 2>/dev/null; then
  echo "expected non-zero exit for unknown format" >&2
  exit 1
fi

echo "ksuid-gen integration: all checks passed"
