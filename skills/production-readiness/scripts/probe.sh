#!/usr/bin/env bash
# Runtime checks against a RUNNING app you own (local dev server or your own staging).
# Proves findings instead of inferring them from code. Sends ordinary HTTP requests only.
#
# Usage: probe.sh <base-url> [--protected /path]... [--login /path] [--login-attempts N]
#   --protected PATH   a route that must require login (expects 401/403 without credentials); repeatable
#   --login PATH       a login/OTP endpoint; sends N bad attempts and expects a 429 (default N=30)
#
# Never point this at a site you don't own or aren't authorized to test.
# Findings also go to $PRS_FINDINGS (tab-separated) if set.
set -uo pipefail

[ $# -ge 1 ] || { sed -n 2,10p "$0" | sed 's/^# \{0,1\}//'; exit 2; }
BASE="${1%/}"; shift
PROTECTED=(); LOGIN=""; ATTEMPTS=30
while [ $# -gt 0 ]; do
  case "$1" in
    --protected) PROTECTED+=("$2"); shift 2 ;;
    --login) LOGIN="$2"; shift 2 ;;
    --login-attempts) ATTEMPTS="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }

C=(curl -s -m 10 -A "production-readiness-probe")
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
emit(){ [ -n "${PRS_FINDINGS:-}" ] && printf "%s\t%s\t%s\t%s\n" "$1" "$2" "$3" "$4" >> "$PRS_FINDINGS"; }
say(){ printf "  %-9s %s\n" "$1" "$2"; }
fail(){ say "$1" "$4"; emit "$2" "$3" "$BASE" "$4"; }

echo "== Runtime probe: $BASE =="
code=$("${C[@]}" -o "$TMP/root" -D "$TMP/h" -w "%{http_code}" "$BASE/") || code=000
if [ "$code" = 000 ]; then echo "Could not connect to $BASE — is the app running?"; exit 1; fi
H=$(tr -d '\r' < "$TMP/h" | tr 'A-Z' 'a-z')
hdr(){ printf "%s" "$H" | grep -E "^$1:" | head -1; }

echo "-- Security headers (GET / → $code)"
case "$BASE" in https://*)
  if [ -n "$(hdr strict-transport-security)" ]; then say ok "HSTS present"; else fail WARN warning missing-hsts "No Strict-Transport-Security header"; fi ;;
esac
if [ -n "$(hdr content-security-policy)" ]; then say ok "Content-Security-Policy present"; else fail WARN warning missing-csp "No Content-Security-Policy header"; fi
if [ -n "$(hdr x-frame-options)" ] || hdr content-security-policy | grep -q frame-ancestors; then say ok "Clickjacking protection present"; else fail WARN warning missing-frame-protection "No X-Frame-Options or CSP frame-ancestors (clickjacking)"; fi
if hdr x-content-type-options | grep -q nosniff; then say ok "X-Content-Type-Options: nosniff"; else fail WARN info missing-nosniff "No X-Content-Type-Options: nosniff"; fi
pb=$(hdr x-powered-by); sv=$(hdr server)
[ -n "$pb" ] && fail INFO info stack-disclosure "Discloses stack: $pb"
printf "%s" "$sv" | grep -qE "[0-9]+\.[0-9]+" && fail INFO info stack-disclosure "Server header discloses version: $sv"

echo "-- CORS"
"${C[@]}" -o /dev/null -D "$TMP/cors" -H "Origin: https://evil.example" "$BASE/" >/dev/null 2>&1
CH=$(tr -d '\r' < "$TMP/cors" | tr 'A-Z' 'a-z')
acao=$(printf "%s" "$CH" | grep -E "^access-control-allow-origin:" | head -1 | sed 's/^[^:]*: *//')
acac=$(printf "%s" "$CH" | grep -E "^access-control-allow-credentials:" | head -1 | sed 's/^[^:]*: *//')
if [ "$acao" = "https://evil.example" ] && [ "$acac" = "true" ]; then
  fail CRITICAL critical cors-reflect-credentials "Reflects any Origin WITH credentials — any website can make logged-in requests as your users"
elif [ "$acao" = "https://evil.example" ]; then fail WARN warning cors-reflect "Reflects any Origin (no credentials)"
elif [ "$acao" = "*" ]; then fail WARN warning cors-wildcard "Access-Control-Allow-Origin: * (fine only for truly public APIs)"
else say ok "Foreign origin not allowed${acao:+ (allows: $acao)}"; fi

echo "-- Exposed files"
exposed=0
check_file(){ local path="$1" sig="$2" c
  c=$("${C[@]}" -o "$TMP/f" -w "%{http_code}" "$BASE$path") || c=000
  if [ "$c" = 200 ] && grep -qE "$sig" "$TMP/f" 2>/dev/null; then fail CRITICAL critical exposed-file "$path is publicly downloadable"; exposed=1; fi; }
check_file "/.env"             '^[A-Z_]+=.'
check_file "/.git/HEAD"        '^ref: refs/'
check_file "/.git/config"      '\[core\]'
check_file "/.env.production"  '^[A-Z_]+=.'
check_file "/config.json"      '"(password|secret|apiKey|api_key|private_key)"'
check_file "/.DS_Store"        'Bud1'
[ "$exposed" = 0 ] && say ok "No .env/.git/config files served"

echo "-- Error handling"
"${C[@]}" -o "$TMP/e1" "$BASE/__prs_does_not_exist__" >/dev/null 2>&1
TRACE='Traceback \(most recent call last\)|at [A-Za-z0-9_.<>]+ \(.*:[0-9]+:[0-9]+\)|Exception in thread|\.java:[0-9]+\)|node_modules/|File "/'
if grep -qE "$TRACE" "$TMP/e1" 2>/dev/null; then fail WARN warning stack-trace-leak "404 page shows a stack trace / file paths"; else say ok "404 page doesn't leak a stack trace"; fi
if [ -n "$LOGIN" ]; then
  "${C[@]}" -o "$TMP/e2" -X POST -H "content-type: application/json" --data '{"broken json' "$BASE$LOGIN" >/dev/null 2>&1
  if grep -qE "$TRACE" "$TMP/e2" 2>/dev/null; then fail WARN warning stack-trace-leak "Malformed JSON to $LOGIN returns a stack trace"; else say ok "Malformed input doesn't leak a stack trace"; fi
fi

if [ ${#PROTECTED[@]} -gt 0 ]; then
  echo "-- Protected routes without credentials"
  for p in "${PROTECTED[@]}"; do
    c=$("${C[@]}" -o /dev/null -w "%{http_code}" "$BASE$p") || c=000
    case "$c" in
      401|403) say ok "$p → $c" ;;
      30[1278]) say ok "$p → $c (redirect, likely to login)" ;;
      2??) fail CRITICAL critical protected-route-open "$p returned $c without credentials" ;;
      *) say "?" "$p → $c (unexpected — check manually)" ;;
    esac
  done
fi

if [ -n "$LOGIN" ]; then
  echo "-- Rate limiting on $LOGIN ($ATTEMPTS bad attempts)"
  got429=0
  for i in $(seq 1 "$ATTEMPTS"); do
    c=$("${C[@]}" -o /dev/null -w "%{http_code}" -X POST -H "content-type: application/json" \
        --data '{"email":"prs-probe@example.com","phone":"0000000000","password":"wrong-password","code":"000000"}' "$BASE$LOGIN") || c=000
    [ "$c" = 429 ] && { got429=$i; break; }
  done
  if [ "$got429" -gt 0 ]; then say ok "429 after $got429 attempts"; else fail CRITICAL critical no-login-rate-limit "No 429 after $ATTEMPTS bad attempts on $LOGIN — passwords/OTPs can be brute-forced"; fi
fi

case "$BASE" in https://*)
  echo "-- HTTPS redirect"
  c=$(curl -s -m 10 -o /dev/null -w "%{http_code} %{redirect_url}" "http://${BASE#https://}/") || c="000"
  case "$c" in 30[1278]\ https://*) say ok "http → https" ;; 000*) say "?" "http:// not reachable (fine if only https is served)" ;; *) fail WARN warning no-https-redirect "http:// is served without redirecting to https ($c)" ;; esac ;;
esac

echo
echo "Probe done. These checks are a sample, not a pentest."
