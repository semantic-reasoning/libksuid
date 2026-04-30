/* SPDX-License-Identifier: LGPL-3.0-or-later AND MIT
 *
 * ksuid-gen -- the libksuid demo CLI. Generates and inspects KSUIDs;
 * intentionally feature-aligned with upstream segmentio/ksuid's
 * `cmd/ksuid` (cmd/ksuid/main.go) MINUS the Go template format which
 * cannot be sensibly reimplemented without dragging Go's text/template
 * grammar in.
 *
 *   ksuid-gen                 -- emit one new KSUID
 *   ksuid-gen -n N            -- emit N new KSUIDs
 *   ksuid-gen -f FORMAT       -- one of {string, inspect, time,
 *                                 timestamp, payload, raw}
 *   ksuid-gen [args...]       -- treat args as KSUID strings to parse
 *                                 and format
 *   ksuid-gen -v              -- prefix each line with "<ksuid>: "
 */
#include <libksuid/ksuid.h>

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum
{
  FMT_STRING,
  FMT_INSPECT,
  FMT_TIME,
  FMT_TIMESTAMP,
  FMT_PAYLOAD,
  FMT_RAW,
};

static int
parse_format (const char *s)
{
  if (strcmp (s, "string") == 0)
    return FMT_STRING;
  if (strcmp (s, "inspect") == 0)
    return FMT_INSPECT;
  if (strcmp (s, "time") == 0)
    return FMT_TIME;
  if (strcmp (s, "timestamp") == 0)
    return FMT_TIMESTAMP;
  if (strcmp (s, "payload") == 0)
    return FMT_PAYLOAD;
  if (strcmp (s, "raw") == 0)
    return FMT_RAW;
  return -1;
}

static void
fputs_hex_upper (const uint8_t *bytes, size_t n, FILE *f)
{
  static const char digits[] = "0123456789ABCDEF";
  for (size_t i = 0; i < n; ++i) {
    fputc (digits[(bytes[i] >> 4) & 0xf], f);
    fputc (digits[bytes[i] & 0xf], f);
  }
}

static void
fputs_time_local (int64_t unix_seconds, FILE *f)
{
  time_t t = (time_t) unix_seconds;
  struct tm tm;
#if defined(_WIN32)
  if (localtime_s (&tm, &t) != 0) {
    fprintf (f, "%" PRId64, unix_seconds);
    return;
  }
#else
  if (localtime_r (&t, &tm) == NULL) {
    fprintf (f, "%" PRId64, unix_seconds);
    return;
  }
#endif
  /* Mirror Go time.Time.String() shape: "2006-01-02 15:04:05 -0700 MST" */
  char buf[64];
  if (strftime (buf, sizeof buf, "%Y-%m-%d %H:%M:%S %z %Z", &tm) == 0)
    snprintf (buf, sizeof buf, "%" PRId64, unix_seconds);
  fputs (buf, f);
}

static void
print_string (const ksuid_t *id)
{
  char s[KSUID_STRING_LEN + 1];
  ksuid_format (id, s);
  s[KSUID_STRING_LEN] = '\0';
  puts (s);
}

static void
print_inspect (const ksuid_t *id)
{
  char s[KSUID_STRING_LEN + 1];
  ksuid_format (id, s);
  s[KSUID_STRING_LEN] = '\0';
  /* Format string is byte-for-byte equivalent to upstream
   * cmd/ksuid/main.go:86-98 modulo the leading newline. */
  printf ("\n" "REPRESENTATION:\n" "\n" "  String: %s\n" "     Raw: ", s);
  fputs_hex_upper (id->b, KSUID_BYTES, stdout);
  printf ("\n" "\n" "COMPONENTS:\n" "\n" "       Time: ");
  fputs_time_local (ksuid_time_unix (id), stdout);
  printf ("\n"
      "  Timestamp: %" PRIu32 "\n" "    Payload: ", ksuid_timestamp (id));
  fputs_hex_upper (ksuid_payload (id), KSUID_PAYLOAD_LEN, stdout);
  fputs ("\n\n", stdout);
}

static void
print_time (const ksuid_t *id)
{
  fputs_time_local (ksuid_time_unix (id), stdout);
  fputc ('\n', stdout);
}

static void
print_timestamp (const ksuid_t *id)
{
  printf ("%" PRIu32 "\n", ksuid_timestamp (id));
}

static void
print_payload (const ksuid_t *id)
{
  fwrite (ksuid_payload (id), 1, KSUID_PAYLOAD_LEN, stdout);
}

static void
print_raw (const ksuid_t *id)
{
  fwrite (id->b, 1, KSUID_BYTES, stdout);
}

static void
print_one (int format, const ksuid_t *id, int verbose)
{
  if (verbose) {
    char s[KSUID_STRING_LEN + 1];
    ksuid_format (id, s);
    s[KSUID_STRING_LEN] = '\0';
    fputs (s, stdout);
    fputs (": ", stdout);
  }
  switch (format) {
    case FMT_STRING:
      print_string (id);
      break;
    case FMT_INSPECT:
      print_inspect (id);
      break;
    case FMT_TIME:
      print_time (id);
      break;
    case FMT_TIMESTAMP:
      print_timestamp (id);
      break;
    case FMT_PAYLOAD:
      print_payload (id);
      break;
    case FMT_RAW:
      print_raw (id);
      break;
    default:
      /* parse_format() validates the input; no other value reaches
       * print_one. Branch exists to satisfy
       * bugprone-switch-missing-default-case. */
      break;
  }
}

static void
usage (FILE *f, const char *argv0)
{
  fprintf (f,
      "usage: %s [-n N] [-f FORMAT] [-v] [KSUID ...]\n"
      "  -n N        number of KSUIDs to generate when no args given (default 1)\n"
      "  -f FORMAT   one of: string, inspect, time, timestamp, payload, raw\n"
      "              (default: string)\n"
      "  -v          prefix each line with the KSUID and ': '\n"
      "  -h          show this help\n"
      "When KSUID arguments are supplied they are parsed and formatted; the -n\n"
      "flag is ignored. Note: the upstream Go CLI's -t / -f template flag is\n"
      "intentionally not supported.\n", argv0);
}

int
main (int argc, char **argv)
{
  long count = 1;
  int format = FMT_STRING;
  int verbose = 0;

  /* Hand-rolled option parser. POSIX getopt(3) lives in <unistd.h>
   * which is not available on Windows MSVC, and the four flags here
   * are simple enough that pulling in a getopt shim would be more
   * code than parsing them inline. The accepted spellings are:
   *   -n N    (count, positive integer; -n N as separate tokens)
   *   -f FMT  (format name)
   *   -v      (verbose; switch)
   *   -h      (help; switch)
   * Combined short options (-vh) and attached values (-n4) are not
   * supported -- the existing tests/test_cli.sh exercises only the
   * separate-token spelling, matching upstream Go ksuid's CLI. */
  int idx = 1;
  while (idx < argc) {
    const char *a = argv[idx];
    if (a[0] != '-' || a[1] == '\0' || a[2] != '\0') {
      /* Not a recognised option; treat as a positional KSUID. */
      break;
    }
    char flag = a[1];
    if (flag == 'v') {
      verbose = 1;
      ++idx;
    } else if (flag == 'h') {
      usage (stdout, argv[0]);
      return 0;
    } else if (flag == 'n' || flag == 'f') {
      if (idx + 1 >= argc) {
        fprintf (stderr, "missing argument for -%c\n", flag);
        usage (stderr, argv[0]);
        return 1;
      }
      const char *val = argv[idx + 1];
      if (flag == 'n') {
        char *end;
        errno = 0;
        long v = strtol (val, &end, 10);
        if (errno != 0 || *end != '\0' || v <= 0) {
          fprintf (stderr, "invalid -n value: %s\n", val);
          return 1;
        }
        count = v;
      } else {
        format = parse_format (val);
        if (format < 0) {
          fprintf (stderr, "unknown format: %s\n", val);
          return 1;
        }
      }
      idx += 2;
    } else {
      fprintf (stderr, "unknown option: %s\n", a);
      usage (stderr, argv[0]);
      return 1;
    }
  }

  if (idx == argc) {
    /* Generation mode. */
    for (long i = 0; i < count; ++i) {
      ksuid_t id;
      ksuid_err_t e = ksuid_new (&id);
      if (e != KSUID_OK) {
        fprintf (stderr, "ksuid_new failed (err %d)\n", (int) e);
        return 2;
      }
      print_one (format, &id, verbose);
    }
  } else {
    /* Parse mode. */
    for (int i = idx; i < argc; ++i) {
      ksuid_t id;
      size_t len = strlen (argv[i]);
      ksuid_err_t e = ksuid_parse (&id, argv[i], len);
      if (e != KSUID_OK) {
        fprintf (stderr, "could not parse %s (err %d)\n", argv[i], (int) e);
        return 1;
      }
      print_one (format, &id, verbose);
    }
  }
  return 0;
}
