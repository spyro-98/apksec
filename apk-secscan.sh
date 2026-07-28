#!/usr/bin/env bash
#
# apk-secscan.sh — static security review for Android APKs
# -----------------------------------------------------------------------------
# Pipeline: jadx (decompile) -> ripgrep/grep (static patterns)
#           + apksigner/apkanalyzer/aapt + strings (optional native)
#           -> report sorted by severity in CSV / JSON / XML / HTML.
#
# Philosophy: separates EVIDENCE (a confirmed finding, e.g. a private key) from
#             SURFACES (to verify at runtime, e.g. a cleartext flag) from
#             INFO (public identifiers, not vulnerabilities).
#             Output is tagged type=FINDING / REVIEW / INFO.
#
# Usage:  ./apk-secscan.sh [options] <app.apk>      (run with --help for details)
#
# Reference baseline (Jun 2026): AGP 9.x (latest 9.2, Apr 2026), Gradle 9.x,
#   Kotlin 2.2.x. Google Play requires target API >= 35 (Android 15) since
#   2025-08-31; compileSdk 36 (Android 16) current. Config documents, crypto
#   material, dev artifacts or executable code shipped in assets are flagged.
# -----------------------------------------------------------------------------

set -u
shopt -s extglob 2>/dev/null || true

# ----------------------------- style / log -----------------------------------
c_red=$'\033[31m'; c_yel=$'\033[33m'; c_grn=$'\033[32m'; c_blu=$'\033[34m'
c_rst=$'\033[0m'
log()  { printf '%s[*]%s %s\n' "$c_blu" "$c_rst" "$*" >&2; }
ok()   { printf '%s[+]%s %s\n' "$c_grn" "$c_rst" "$*" >&2; }
warn() { printf '%s[!]%s %s\n' "$c_yel" "$c_rst" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$c_red" "$c_rst" "$*" >&2; }
die()  { err "$*"; exit 1; }

TAB=$'\t'
# No associative arrays or ${var^^}: maximum portability (old bash / macOS).
sev_rank() { case "$1" in
  CRITICAL) echo 0;; HIGH) echo 1;; MEDIUM) echo 2;; LOW) echo 3;; INFO) echo 4;; *) echo 9;; esac; }
upper() { printf '%s' "$1" | tr '[:lower:]' '[:upper:]'; }

# ----------------------------- default ---------------------------------------
SCOPE="all"; FORMAT="all"; OUTDIR=""; APP_PKG=""; JADX_BIN=""
KEEP=0; SKIP_DECOMPILE=""; APK=""; NATIVE=0; FAILON="none"; CVE=0; CVE_MAX=400; CVE_MOCK=""; DEPS=0

# ----------------------------- parse args ------------------------------------
usage() {
  local cy='' rs=''
  [[ -t 1 ]] && { cy=$'\033[36m'; rs=$'\033[0m'; }
  printf '%s' "$cy"
  cat <<'ART'
                __      ____    ____    ____
               /\ \    /\  _`\ /\  _`\ /\  _`\
   __     _____\ \ \/'\\ \,\L\_\ \ \L\_\ \ \/\_\
 /'__`\  /\ '__`\ \ , < \/_\__ \\ \  _\L\ \ \/_/_
/\ \L\.\_\ \ \L\ \ \ \\`\ /\ \L\ \ \ \L\ \ \ \L\ \
\ \__/.\_\\ \ ,__/\ \_\ \_\ `\____\ \____/\ \____/
 \/__/\/_/ \ \ \/  \/_/\/_/\/_____/\/___/  \/___/
            \ \_\
             \/_/
ART
  printf '%s\n' "$rs"
  cat <<'EOF'
apk-secscan.sh - static security review for Android APKs

Usage:  ./apk-secscan.sh [options] <app.apk>

Options:
  -s, --scope   app|libs|all   Code scope (default: all)
                                 app  = only the app package
                                 libs = only third-party packages
                                 all  = everything
  -f, --format  csv|json|xml|html|all   Report format(s) (default: all)
  -o, --output  <dir>          Output directory (default: ./secscan-<apk>-<ts>)
  -p, --app-package <pkg>      Force the app package (override autodetect)
      --native                 Also scan native libs (.so) with strings
      --cve                    Check known library CVEs via OSV.dev (network)
      --cve-max <n>            Max libraries to query on OSV (default 400)
      --cve-mock <file>        Use a saved OSV dump instead of the network (offline/CI)
      --fail-on  none|low|medium|high|critical
                               Exit code 2 if a FINDING >= threshold exists
                               (for CI; default: none -> exit 0)
      --jadx <path>            Path to the jadx binary
      --keep                   Keep the decompiled work directory
      --skip-decompile <dir>   Reuse an existing jadx directory (no re-jadx)
      --deps                   List the system tools used (present/missing + how to install)
  -h, --help                   This help

Scope note (-s): scope acts on the sources/ tree (where packages are meaningful).
  Manifest, resources, signature and absence checks cover the whole APK and are
  ALWAYS evaluated, regardless of scope.
EOF
exit 0; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -s|--scope)       SCOPE="${2:-}"; shift 2;;
    -f|--format)      FORMAT="${2:-}"; shift 2;;
    -o|--output)      OUTDIR="${2:-}"; shift 2;;
    -p|--app-package) APP_PKG="${2:-}"; shift 2;;
    --native)         NATIVE=1; shift;;
    --cve)            CVE=1; shift;;
    --cve-max)        CVE_MAX="${2:-}"; shift 2;;
    --cve-mock)       CVE_MOCK="${2:-}"; CVE=1; shift 2;;
    --fail-on)        FAILON="${2:-}"; shift 2;;
    --jadx)           JADX_BIN="${2:-}"; shift 2;;
    --keep)           KEEP=1; shift;;
    --skip-decompile) SKIP_DECOMPILE="${2:-}"; shift 2;;
    --deps|--check-deps) DEPS=1; shift;;
    -h|--help)        usage;;
    -*)               die "Unknown option: $1 (use --help)";;
    *)                APK="$1"; shift;;
  esac
done

[[ "$SCOPE"  =~ ^(app|libs|all)$ ]]                    || die "invalid scope: $SCOPE"
[[ "$FORMAT" =~ ^(csv|json|xml|html|all)$ ]]           || die "invalid format: $FORMAT"
[[ "$FAILON" =~ ^(none|low|medium|high|critical)$ ]]   || die "invalid fail-on: $FAILON"

# ----------------------------- tool check ------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

# List of the system tools used, with status and install command.
# Enabled with --deps and NEVER aborts (it exists precisely to diagnose what is missing).
show_deps() {
  local plat hint key
  case "$(uname -s 2>/dev/null)" in
    Darwin) plat="macOS (brew)";;
    Linux)  plat="Linux (apt/dnf)";;
    *)      plat="generic";;
  esac
  printf '\n  apk-secscan — system dependencies   [platform: %s]\n' "$plat" >&2
  printf '  Legend: %s[✓]%s present   %s[ ]%s missing\n\n' "$c_grn" "$c_rst" "$c_red" "$c_rst" >&2

  # dep NAME REQ ROLE HINT_MAC HINT_LINUX HINT_GEN
  dep() {
    local name="$1" req="$2" role="$3" hmac="$4" hlin="$5" hgen="$6" path mark
    path="$(command -v "$name" 2>/dev/null || true)"
    if [[ -n "$path" ]]; then mark="${c_grn}[✓]${c_rst}"; else mark="${c_red}[ ]${c_rst}"; fi
    case "$plat" in macOS*) hint="$hmac";; Linux*) hint="$hlin";; *) hint="$hgen";; esac
    printf '  %b %-10s %-11s %s\n' "$mark" "$name" "($req)" "${path:-—}" >&2
    printf '         ↳ %s\n         ↳ install: %s\n' "$role" "$hint" >&2
  }

  printf '  %s— REQUIRED —%s\n' "$c_blu" "$c_rst" >&2
  dep jadx    "required" "decompiles the APK (not needed with --skip-decompile)" \
      "brew install jadx" "download release github.com/skylot/jadx  (or: apt install jadx)" "github.com/skylot/jadx/releases"
  dep python3 "required" "generates the reports, CVE phase and assets analysis" \
      "brew install python  (often already present)" "apt install python3" "python.org"
  # grep PCRE: special case (grep or ggrep)
  local pcre="" g
  for g in grep ggrep; do
    if command -v "$g" >/dev/null 2>&1 && printf 'x' | "$g" -qP 'x' 2>/dev/null; then pcre="$g"; break; fi
  done
  if [[ -n "$pcre" ]]; then
    printf '  %b %-10s %-11s %s\n' "${c_grn}[✓]${c_rst}" "grep(-P)" "(required)" "$(command -v "$pcre")" >&2
  else
    printf '  %b %-10s %-11s %s\n' "${c_red}[ ]${c_rst}" "grep(-P)" "(required)" "—" >&2
  fi
  printf '         ↳ PCRE pattern search; on macOS the brew GNU grep is "ggrep"\n' >&2
  printf '         ↳ install: %s\n' "$([[ "$plat" == macOS* ]] && echo 'brew install grep  (provides ggrep)' || echo 'GNU grep, usually already present')" >&2
  dep xargs   "required" "batch execution of the search patterns" \
      "already present (BSD)" "apt install findutils" "coreutils/findutils"

  printf '\n  %s— OPTIONAL —%s\n' "$c_blu" "$c_rst" >&2
  dep rg        "optional" "fast search engine (ripgrep); falls back to grep" \
      "brew install ripgrep" "apt install ripgrep" "github.com/BurntSushi/ripgrep"
  dep apksigner "optional" "verifies APK signature schemes (Janus/CVE-2017-13156)" \
      "brew install --cask android-commandlinetools, then sdkmanager \"build-tools;35.0.0\"" \
      "apt install apksigner  (or Android SDK build-tools)" "Android SDK build-tools"
  dep aapt2     "optional" "package name and targetSdkVersion from the APK" \
      "Android SDK build-tools (see apksigner)" "apt install aapt  (or Android SDK build-tools)" "Android SDK build-tools"
  dep unzip     "optional" "--native: extracts lib/ and assets/ from the APK" \
      "already present" "apt install unzip" "unzip"
  dep strings   "optional" "--native: extracts strings/secrets from .so files" \
      "already present (Xcode CLT)" "apt install binutils" "binutils"

  printf '\n  Note: the CVE phase and assets analysis use Python'"'"'s zipfile library\n' >&2
  printf '        (no curl/unzip needed for those). Network is required only with --cve.\n\n' >&2
  exit 0
}
[[ "$DEPS" -eq 1 ]] && show_deps

[[ -z "$JADX_BIN" ]] && JADX_BIN="$(command -v jadx || true)"
APKSIGNER="$(command -v apksigner || true)"
AAPT="$(command -v aapt || command -v aapt2 || true)"

have xargs   || die "xargs missing"
have python3 || die "python3 missing (needed for the reports)"

# Find a grep with PCRE (-P) support. On macOS the Homebrew GNU grep is
# named 'ggrep' (the system 'grep' is BSD and does NOT support -P).
GREP=""
for cand in grep ggrep; do
  if command -v "$cand" >/dev/null 2>&1 && printf 'x' | "$cand" -qP 'x' 2>/dev/null; then
    GREP="$cand"; break
  fi
done
[[ -n "$GREP" ]] || die "No grep with -P (PCRE) support found. On macOS: 'brew install grep' (provides ggrep). See: $0 --deps"

# Search engine: ripgrep if present (much faster), otherwise the PCRE grep found above.
if have rg; then ENGINE="rg"; ok "Engine: ripgrep (fast)"; else ENGINE="grep"; log "Engine: $GREP (PCRE)"; fi

# Reference Android development baseline (shown in the report and --help).
REF_BASELINE="Android Jun-2026 · AGP 9.x (9.2) · Kotlin 2.2.x · Play target API>=35 (Android 15) · compileSdk 36"
log "Reference baseline: $REF_BASELINE"

# ----------------------------- decompile -------------------------------------
TS="$(date +%Y%m%d-%H%M%S)"
if [[ -n "$SKIP_DECOMPILE" ]]; then
  WORKDIR="$SKIP_DECOMPILE"
  [[ -d "$WORKDIR" ]] || die "--skip-decompile directory does not exist: $WORKDIR"
  log "Reusing existing decompilation: $WORKDIR"
else
  [[ -n "$APK" ]] || die "No APK provided. Usage: $0 [options] <app.apk>"
  [[ -f "$APK" ]] || die "APK not found: $APK"
  [[ -n "$JADX_BIN" ]] || die "jadx not found. Install jadx, use --jadx <path> or --skip-decompile"
  WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/secscan.XXXXXX")"
  log "Decompiling with jadx -> $WORKDIR (may take a few minutes)..."
  "$JADX_BIN" -q --threads-count 4 -d "$WORKDIR" "$APK" 2>"$WORKDIR/jadx.err" \
    && ok "Decompilation complete" \
    || warn "jadx reported partial errors (normal on obfuscated code) — continuing"
fi

APK_NAME="$(basename "${APK:-$WORKDIR}")"; APK_NAME="${APK_NAME%.apk}"
[[ -z "$OUTDIR" ]] && OUTDIR="./secscan-${APK_NAME}-${TS}"
mkdir -p "$OUTDIR" || die "cannot create $OUTDIR"

SRC="$WORKDIR/sources"
RES="$WORKDIR/resources"
MANIFEST="$RES/AndroidManifest.xml"
[[ -d "$SRC" ]] || warn "sources/ directory not found (empty decompilation?)"

# ----------------------------- app package -----------------------------------
# Manifest first (= the code namespace, maps the sources/ tree),
# then aapt as fallback. The -p override always wins.
if [[ -z "$APP_PKG" ]]; then
  if [[ -f "$MANIFEST" ]]; then
    APP_PKG="$("$GREP" -oP 'package="\K[^"]+' "$MANIFEST" | head -1)"
  fi
  if [[ -z "$APP_PKG" && -n "$AAPT" && -f "${APK:-/nonexistent}" ]]; then
    APP_PKG="$("$AAPT" dump badging "$APK" 2>/dev/null \
      | sed -n "s/^package: name='\([^']*\)'.*/\1/p" | head -1)"
  fi
fi
[[ -n "$APP_PKG" ]] && ok "App package: $APP_PKG" \
  || warn "App package not detected (app/libs scope imprecise). Use -p <pkg>."
APP_PKG_PATH="${APP_PKG//.//}"

# Helpful warning: when autodetect does not match the sources tree.
if [[ -n "$APP_PKG_PATH" && -d "$SRC" && ! -d "$SRC/$APP_PKG_PATH" ]]; then
  warn "Package '$APP_PKG' not found in sources/ — applicationId may differ from the namespace. Verify with -p."
fi

# ----------------------------- file lists ------------------------------------
# FILELIST: scope-dependent (for scans). FULLLIST: everything (for absence checks).
FILELIST="$WORKDIR/.filelist.$SCOPE"; : > "$FILELIST"
FULLLIST="$WORKDIR/.filelist.full";   : > "$FULLLIST"

RES_FILTER=( -name '*.xml' -o -name '*.json' -o -name '*.properties' -o -name '*.txt'
             -o -name '*.list' -o -name '*.env' -o -name '*.pem' -o -name '*.cfg'
             -o -name '*.html' -o -name '*.js' -o -name '*.smali' )

build_filelist() {
  if [[ -d "$SRC" ]]; then
    case "$SCOPE" in
      app)
        [[ -n "$APP_PKG_PATH" && -d "$SRC/$APP_PKG_PATH" ]] \
          && find "$SRC/$APP_PKG_PATH" -type f -print0 >>"$FILELIST" ;;
      libs)
        if [[ -n "$APP_PKG_PATH" ]]; then
          find "$SRC" -type f ! -path "$SRC/$APP_PKG_PATH/*" -print0 >>"$FILELIST"
        else
          find "$SRC" -type f -print0 >>"$FILELIST"
        fi ;;
      all) find "$SRC" -type f -print0 >>"$FILELIST" ;;
    esac
  fi
  if [[ "$SCOPE" != "libs" && -d "$RES" ]]; then
    find "$RES" -type f \( "${RES_FILTER[@]}" \) -print0 >>"$FILELIST"
  fi
}
build_full_filelist() {
  [[ -d "$SRC" ]] && find "$SRC" -type f -print0 >>"$FULLLIST"
  [[ -d "$RES" ]] && find "$RES" -type f \( "${RES_FILTER[@]}" \) -print0 >>"$FULLLIST"
}
build_filelist
build_full_filelist
NFILES=$(tr -cd '\0' <"$FILELIST" | wc -c)
log "Scope '$SCOPE': $NFILES files to scan"

# ----------------------------- findings store --------------------------------
FINDINGS="$WORKDIR/.findings.tsv"; : > "$FINDINGS"

# Sanitization WITHOUT a fork (parameter expansion only).
emit_row() { # sev cat type title file line match
  local sev="$1" cat="$2" typ="$3" title="$4" file="$5" line="$6" match="$7"
  file="${file#"$WORKDIR"/}"
  match="${match//$TAB/ }"; match="${match//$'\r'/ }"; match="${match//$'\n'/ }"
  match="${match:0:240}"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$sev" "$cat" "$typ" "$title" "$file" "$line" "$match" >>"$FINDINGS"
}

# Unified engine: search rx across the files of a NUL-delimited filelist.
# Emits "file:line:match" rows.
search_list() { # rx filelist
  local rx="$1" lst="$2"
  [[ -s "$lst" ]] || return 0
  if [[ "$ENGINE" == rg ]]; then
    xargs -0 rg -H -n --no-heading --color never -P -e "$rx" <"$lst" 2>/dev/null
  else
    xargs -0 "$GREP" -HnIP -e "$rx" <"$lst" 2>/dev/null
  fi
}

scan() { # SEV CAT TYPE "Title" 'REGEX'  (uses the scoped FILELIST)
  local sev="$1" cat="$2" typ="$3" title="$4" rx="$5"
  search_list "$rx" "$FILELIST" | while IFS= read -r ln; do
    local f l m; f="${ln%%:*}"; ln="${ln#*:}"; l="${ln%%:*}"; m="${ln#*:}"
    emit_row "$sev" "$cat" "$typ" "$title" "$f" "$l" "$m"
  done
}

scan_file() { # SEV CAT TYPE "Title" 'REGEX' <file>  (always, out of scope)
  local sev="$1" cat="$2" typ="$3" title="$4" rx="$5" file="$6"
  [[ -f "$file" ]] || return 0
  if [[ "$ENGINE" == rg ]]; then
    rg -H -n --no-heading --color never -P -e "$rx" "$file" 2>/dev/null
  else
    "$GREP" -HnIP -e "$rx" "$file" 2>/dev/null
  fi | while IFS= read -r ln; do
    local f l m; f="${ln%%:*}"; ln="${ln#*:}"; l="${ln%%:*}"; m="${ln#*:}"
    emit_row "$sev" "$cat" "$typ" "$title" "$f" "$l" "$m"
  done
}

note() { emit_row "$1" "$2" "$3" "$4" "${5:-(analysis)}" "-" "${6:-}"; }

# Absence: search the WHOLE tree (not the scope). 0 if present.
pattern_present() { # rx
  [[ -s "$FULLLIST" ]] || return 1
  if [[ "$ENGINE" == rg ]]; then
    xargs -0 rg -l -P -e "$1" <"$FULLLIST" 2>/dev/null | grep -q .
  else
    xargs -0 "$GREP" -lIP -e "$1" <"$FULLLIST" 2>/dev/null | grep -q .
  fi
}

log "Running static checks..."

# =============================================================================
#  Confirmed SECRETS (reused for the native scan too) — title<TAB>regex
# =============================================================================
SECRET_PATTERNS=()
add_secret() { SECRET_PATTERNS+=("$1$TAB$2"); }
add_secret "Hardcoded private key (PEM)"        '-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----'
add_secret "Google service account (JSON)"          '"type"\s*:\s*"service_account"|"private_key_id"\s*:'
add_secret "Stripe secret key"                      '\bsk_(?:live|test)_[0-9a-zA-Z]{16,}'
add_secret "AWS Access Key ID"                      '\bAKIA[0-9A-Z]{16}\b'
add_secret "Slack token"                            '\bxox[baprs]-[0-9A-Za-z-]{10,}'
add_secret "GitHub token"                           '\bgh[pousr]_[0-9A-Za-z]{36,}'
add_secret "Google OAuth client secret"             '\bGOCSPX-[0-9A-Za-z_-]{20,}'
add_secret "Hardcoded JWT"                          '\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
add_secret "Twilio API key"                         '\bSK[0-9a-fA-F]{32}\b'
add_secret "Google API key (private? verify)"   '\bAIza[0-9A-Za-z_-]{35}\b'   # see INFO note below

# CRITICAL — real secrets ("house key")
for e in "${SECRET_PATTERNS[@]}"; do
  t="${e%%$TAB*}"; rx="${e#*$TAB}"
  # AIza is treated as INFO elsewhere (public): skip it as CRITICAL here
  [[ "$t" == "Google API key"* ]] && continue
  scan CRITICAL "Secrets" FINDING "$t" "$rx"
done
scan CRITICAL "Secrets" REVIEW  "Hardcoded app/client secret (verify value)" \
  '(?i)\b(?:app_secret|client_secret|consumer_secret|api_secret)\b\s*[:=]\s*["'\''][^"'\'' ]{8,}'
scan CRITICAL "Secrets" REVIEW  "Hardcoded password (verify)" \
  '(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*["'\''][^"'\'' ]{4,}'
scan CRITICAL "Secrets" REVIEW  "AWS secret access key (likely)" \
  '(?i)aws_secret_access_key\s*[:=]\s*["'\'']?[A-Za-z0-9/+=]{40}'

# =============================================================================
#  HIGH — network / exec / webview / storage
# =============================================================================
scan HIGH "Network" REVIEW  "TrustManager that trusts everything (MITM)" \
  'TrustManager|checkServerTrusted|getAcceptedIssuers'
scan HIGH "Network" FINDING "Permissive HostnameVerifier (ALLOW_ALL)" \
  'ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier|verify\([^)]*\)\s*\{\s*return\s+true'
scan HIGH "Exec" REVIEW "Shell command execution (Runtime.exec / ProcessBuilder)" \
  'Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder'
scan HIGH "DynamicCode" REVIEW "Dynamic code loading (DexClassLoader)" \
  'DexClassLoader|PathClassLoader|InMemoryDexClassLoader|BaseDexClassLoader'
scan HIGH "WebView" FINDING "addJavascriptInterface (JS->native bridge)" 'addJavascriptInterface'
scan HIGH "WebView" REVIEW  "WebView with JavaScript enabled" 'setJavaScriptEnabled\(\s*true\s*\)'
scan HIGH "WebView" FINDING "WebView universal access from file:// URLs" \
  'setAllowUniversalAccessFromFileURLs\(\s*true\s*\)|setAllowFileAccessFromFileURLs\(\s*true\s*\)'
scan HIGH "Storage" FINDING "Files with WORLD_READABLE/WRITEABLE permissions" \
  'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE'

# =============================================================================
#  MEDIUM — weak crypto / storage / ipc / sql / logging
# =============================================================================
scan MEDIUM "Crypto" REVIEW "AES in ECB mode (insecure)" \
  'Cipher\.getInstance\(\s*"AES"\s*\)|/ECB/'
scan MEDIUM "Crypto" REVIEW "Weak algorithms (DES/RC4/Blowfish)" \
  'Cipher\.getInstance\(\s*"(?:DES|DESede|RC4|RC2|Blowfish)'
scan MEDIUM "Crypto" REVIEW "Weak hash for security (MD5/SHA-1)" \
  'MessageDigest\.getInstance\(\s*"(?:MD5|SHA-?1)"'
scan MEDIUM "Crypto" REVIEW "Static IV or insecure RNG" \
  'IvParameterSpec\(\s*new\s+byte|new\s+Random\('
scan MEDIUM "Secrets" REVIEW "Long Base64 (possible obfuscated secret)" \
  'Base64\.decode\(\s*"[A-Za-z0-9+/]{40,}={0,2}"'
scan MEDIUM "Storage" REVIEW "SharedPreferences with sensitive keys (cleartext)" \
  '(?i)(?:get|put)(?:String|Boolean)\(\s*"[^"]*(?:token|password|passwd|pin|secret|auth|jwt|session)'
scan MEDIUM "Storage" REVIEW "Write to external storage (outside sandbox)" \
  'getExternalStorageDirectory|getExternalFilesDir|Environment\.DIRECTORY_'
scan MEDIUM "Logging" REVIEW "Potentially sensitive logging" \
  '\bLog\.[dview]\(\s*[^,]+,\s*[^)]*(?:token|password|secret|auth|user|email|jwt)'
scan MEDIUM "IPC" REVIEW "PendingIntent without FLAG_IMMUTABLE" \
  'PendingIntent\.get(?:Activity|Broadcast|Service)\('
scan MEDIUM "SQL" REVIEW "SQL query via concatenation (local injection)" \
  '(?:rawQuery|execSQL)\([^)]*\+\s*[A-Za-z_]'
scan MEDIUM "IPC" REVIEW "FileProvider / grantUriPermission (verify scope)" \
  'grantUriPermission|FLAG_GRANT_(?:READ|WRITE)_URI_PERMISSION'

# =============================================================================
#  LOW / INFO — smells, endpoints, public identifiers (NOT secrets)
# =============================================================================
scan LOW  "Network" REVIEW "Cleartext HTTP endpoint (verify if real backend)" \
  'http://(?!schemas\.android\.com|www\.w3\.org|localhost|127\.0\.0\.1|10\.0\.2\.2)[A-Za-z0-9.-]+'
scan LOW  "Network" INFO   "localhost/emulator reference (likely debug)" \
  'http://(?:localhost|127\.0\.0\.1|10\.0\.2\.2)'
scan LOW  "Env" INFO       "References to non-production environments" \
  '(?i)\b(?:staging|preprod|pre-prod|\.dev\b|internal\.|debug-api|test-api|sandbox)\b'
scan LOW  "Quality" INFO   "TODO/FIXME/HACK comments" \
  '(?i)//\s*(?:TODO|FIXME|HACK|XXX|BUG)\b'
scan INFO "Endpoints" INFO "HTTPS / Cloud Functions endpoints" \
  'https://[A-Za-z0-9.-]+\.(?:cloudfunctions\.net|firebaseio\.com|firebaseapp\.com|run\.app)[A-Za-z0-9/_.-]*'
scan INFO "Identifiers" INFO "Google API key (AIzaSy…) — public, verify GCP RESTRICTIONS" \
  '\bAIza[0-9A-Za-z_-]{35}\b'
scan INFO "Identifiers" INFO "Sentry DSN — public ingest key, not a secret" \
  'https://[0-9a-f]+@[A-Za-z0-9.-]*sentry[A-Za-z0-9.-]*/[0-9]+'
scan INFO "Identifiers" INFO "RemoteConfig (remotely-driven behavior)" \
  'FirebaseRemoteConfig|getRemoteConfig|remoteConfig'

# =============================================================================
#  MANIFEST + NETWORK CONFIG (always, out of scope)
# =============================================================================
if [[ -f "$MANIFEST" ]]; then
  scan_file HIGH   "Manifest" FINDING "android:debuggable=true (NOT for production!)" \
    'android:debuggable="true"' "$MANIFEST"
  scan_file MEDIUM "Manifest" REVIEW  "android:allowBackup=true (extraction via adb)" \
    'android:allowBackup="true"' "$MANIFEST"
  scan_file HIGH   "Manifest" REVIEW  "usesCleartextTraffic=true (cleartext HTTP)" \
    'android:usesCleartextTraffic="true"' "$MANIFEST"
  scan_file MEDIUM "Manifest" REVIEW  "Component exported=true (IPC surface)" \
    'android:exported="true"' "$MANIFEST"
  scan_file MEDIUM "Manifest" REVIEW  "Deep link / custom scheme (intent vector)" \
    '<data\s+[^>]*android:scheme=' "$MANIFEST"
  scan_file LOW    "Manifest" INFO    "Dangerous permissions requested" \
    'android:name="android\.permission\.(?:READ_SMS|RECEIVE_SMS|READ_CONTACTS|ACCESS_FINE_LOCATION|RECORD_AUDIO|CAMERA|READ_EXTERNAL_STORAGE|SYSTEM_ALERT_WINDOW|REQUEST_INSTALL_PACKAGES|QUERY_ALL_PACKAGES)"' "$MANIFEST"
fi

NSC="$(grep -rlI 'network-security-config' "$RES" 2>/dev/null | head -1)"
if [[ -n "$NSC" ]]; then
  scan_file HIGH "Network" REVIEW  "cleartextTrafficPermitted=true in network_security_config" \
    'cleartextTrafficPermitted="true"' "$NSC"
  scan_file HIGH "Network" FINDING "trust-anchors trust USER certificates (easy MITM)" \
    'src="user"' "$NSC"
  scan_file LOW  "Network" INFO    "Certificate pinning declared (good)" \
    '<pin-set|<pin\b' "$NSC"
fi

# =============================================================================
#  ABSENCE CHECKS (over the whole tree)
# =============================================================================
pattern_present 'CertificatePinner|<pin-set|okhttp3\.CertificatePinner' \
  || note INFO "Hardening" REVIEW "Certificate pinning ABSENT" "(global analysis)"
pattern_present 'RootBeer|/system/bin/su\b|test-keys|Magisk|isRooted|/system/xbin/su' \
  || note INFO "Hardening" REVIEW "Root detection ABSENT" "(global analysis)"
pattern_present 'AndroidKeyStore' \
  || note INFO "Hardening" REVIEW "AndroidKeyStore not used (keys not hardware-backed?)" "(global analysis)"
pattern_present 'FLAG_SECURE|setFlags\([^)]*SECURE' \
  || note LOW  "Hardening" INFO   "FLAG_SECURE absent (screenshots of sensitive screens allowed)" "(global analysis)"

# =============================================================================
#  NATIVE LIBS (.so) via strings  — opt-in with --native
# =============================================================================
if [[ "$NATIVE" -eq 1 ]]; then
  if [[ -n "${APK:-}" && -f "${APK:-/nonexistent}" ]] && have unzip && have strings; then
    log "Native scan: extracting lib/ + assets/ and searching for secrets with strings..."
    NDIR="$WORKDIR/.native"; mkdir -p "$NDIR"
    unzip -o -q "$APK" 'lib/*' 'assets/*' -d "$NDIR" 2>/dev/null || true
    NLIST="$WORKDIR/.nativefiles"; : > "$NLIST"
    find "$NDIR" -type f \( -name '*.so' -o -path '*/assets/*' \) -print0 >>"$NLIST"
    NN=$(tr -cd '\0' <"$NLIST" | wc -c); log "Native/asset files: $NN"
    while IFS= read -r -d '' f; do
      local_str="$(strings -n 8 "$f" 2>/dev/null)"
      [[ -z "$local_str" ]] && continue
      for e in "${SECRET_PATTERNS[@]}"; do
        t="${e%%$TAB*}"; rx="${e#*$TAB}"
        [[ "$t" == "Google API key"* ]] && sv="INFO" tp="INFO" || sv="CRITICAL" tp="FINDING"
        printf '%s\n' "$local_str" | "$GREP" -nP -e "$rx" 2>/dev/null | while IFS= read -r ln; do
          emit_row "$sv" "Native" "$tp" "$t (native)" "$f" "${ln%%:*}" "${ln#*:}"
        done
      done
    done <"$NLIST"
  else
    warn "--native requires APK + unzip + strings: native scan skipped"
  fi
fi

NFOUND=$(wc -l <"$FINDINGS" 2>/dev/null || echo 0)
ok "Checks complete: $NFOUND finding rows"

# =============================================================================
#  APKSIGNER / AAPT (if available)
# =============================================================================
if [[ -n "$APKSIGNER" && -f "${APK:-/nonexistent}" ]]; then
  log "apksigner: verifying signature schemes..."
  sig="$("$APKSIGNER" verify -v "$APK" 2>/dev/null)"
  v1="$(printf '%s' "$sig" | "$GREP" -oiP 'v1 scheme.*:\s*\K(true|false)' | head -1)"
  v2="$(printf '%s' "$sig" | "$GREP" -oiP 'v2 scheme.*:\s*\K(true|false)' | head -1)"
  v3="$(printf '%s' "$sig" | "$GREP" -oiP 'v3 scheme.*:\s*\K(true|false)' | head -1)"
  if [[ "$v1" == "true" && "$v2" != "true" && "$v3" != "true" ]]; then
    note HIGH "Signing" FINDING "v1-only signature (JAR): vulnerable to Janus (CVE-2017-13156)" "(apksigner)" "v1=$v1 v2=$v2 v3=$v3"
  else
    note INFO "Signing" INFO "Signature schemes: v1=$v1 v2=$v2 v3=$v3" "(apksigner)"
  fi
fi
if [[ -n "$AAPT" && -f "${APK:-/nonexistent}" ]]; then
  tsdk="$("$AAPT" dump badging "$APK" 2>/dev/null | "$GREP" -oP "targetSdkVersion:'\K[0-9]+" | head -1)"
  if [[ -n "$tsdk" && "$tsdk" -lt 30 ]]; then
    note MEDIUM "Manifest" REVIEW "targetSdkVersion=$tsdk is low (permissive legacy behaviors)" "(aapt)"
  elif [[ -n "$tsdk" ]]; then
    note INFO "Manifest" INFO "targetSdkVersion=$tsdk" "(aapt)"
  fi
fi

# =============================================================================
#  DEPENDENCY CVEs (OSV.dev) — opt-in with --cve, requires network
# =============================================================================
if [[ "$CVE" -eq 1 ]]; then
  log "CVE phase: extracting library versions and querying OSV.dev..."
  export SS_RES="$RES" SS_FINDINGS="$FINDINGS" SS_CVE_MAX="$CVE_MAX" \
         SS_APK_PATH="${APK:-}" SS_CVE_MOCK="$CVE_MOCK"
  python3 - <<'PYCVE'
import os, glob, json, re, sys, ssl
import urllib.request, urllib.error

RES=os.environ.get("SS_RES",""); FIN=os.environ["SS_FINDINGS"]
APK=os.environ.get("SS_APK_PATH",""); MOCKP=os.environ.get("SS_CVE_MOCK","")
try: MAXN=int(os.environ.get("SS_CVE_MAX","400") or "400")
except ValueError: MAXN=400
OSV="https://api.osv.dev/v1"

# Some Python installs (notably python.org builds on macOS, which ship their
# own OpenSSL without the system trust store) fail every HTTPS request with
# CERTIFICATE_VERIFY_FAILED until "Install Certificates.command" is run.
# Fall back to certifi's CA bundle when available instead of hard-failing.
try:
    import certifi
    _SSL_CTX=ssl.create_default_context(cafile=certifi.where())
except Exception:
    _SSL_CTX=None

MOCK=None
if MOCKP and os.path.isfile(MOCKP):
    try: MOCK=json.load(open(MOCKP)); print("CVE: using local OSV dump (offline).", file=sys.stderr)
    except Exception as e: print(f"CVE: mock dump unreadable ({e})", file=sys.stderr)

coords={}
def add(name, ver):
    if name and ver and ":" in name: coords.setdefault(name, ver)

def parse_pom(txt):
    d=dict(re.findall(r'^(groupId|artifactId|version)=(.+)$', txt, re.M))
    if d.get("groupId") and d.get("artifactId") and d.get("version"):
        add(f"{d['groupId'].strip()}:{d['artifactId'].strip()}", d['version'].strip())

# (1) from the decompiled tree
for f in glob.glob(os.path.join(RES,"**","*.version"), recursive=True):
    base=os.path.basename(f)[:-8]
    if "_" in base:
        g,a=base.split("_",1)
        try: ver=open(f,encoding="utf-8",errors="replace").read().strip().splitlines()[0].strip()
        except Exception: ver=""
        add(f"{g}:{a}", ver)
for f in glob.glob(os.path.join(RES,"**","pom.properties"), recursive=True):
    try: parse_pom(open(f,encoding="utf-8",errors="replace").read())
    except Exception: pass

# (2) directly from the APK (more reliable, independent of jadx)
if APK and os.path.isfile(APK):
    try:
        import zipfile
        z=zipfile.ZipFile(APK)
        for nm in z.namelist():
            if nm.endswith(".version"):
                base=nm.rsplit("/",1)[-1][:-8]
                if "_" in base:
                    g,a=base.split("_",1)
                    try: ver=z.read(nm).decode("utf-8","replace").strip().splitlines()[0].strip()
                    except Exception: ver=""
                    add(f"{g}:{a}", ver)
            elif nm.endswith("pom.properties"):
                try: parse_pom(z.read(nm).decode("utf-8","replace"))
                except Exception: pass
    except Exception as e:
        print(f"CVE: APK read failed ({e})", file=sys.stderr)

if not coords:
    print("CVE: no versioned library detected (META-INF/*.version or pom.properties absent).", file=sys.stderr)
    sys.exit(0)
items=sorted(coords.items())[:MAXN]
print(f"CVE: {len(coords)} versioned libraries; checking {len(items)} on OSV...", file=sys.stderr)

def emit(sev, title, filef, match):
    match=(match or "").replace("\t"," ").replace("\r"," ").replace("\n"," ")[:240]
    with open(FIN,"a",encoding="utf-8") as fh:
        fh.write("\t".join([sev,"Dependency","FINDING",title,filef,"-",match])+"\n")

def map_sev(v):
    ds=((v.get("database_specific") or {}).get("severity") or "").upper()
    return {"LOW":"LOW","MODERATE":"MEDIUM","MEDIUM":"MEDIUM","HIGH":"HIGH","CRITICAL":"CRITICAL"}.get(ds,"MEDIUM")

def fixes_for(v, name):
    out=[]
    for a in v.get("affected",[]):
        if (a.get("package") or {}).get("name")!=name: continue
        for rng in a.get("ranges",[]):
            for ev in rng.get("events",[]):
                if ev.get("fixed"): out.append(ev["fixed"])
    return sorted(set(out))

def osv_post(path, payload):
    data=json.dumps(payload).encode()
    req=urllib.request.Request(OSV+path, data=data, headers={"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return json.load(r)
    except ssl.SSLCertVerificationError:
        if _SSL_CTX is None: raise
        with urllib.request.urlopen(req, timeout=25, context=_SSL_CTX) as r:
            return json.load(r)

def vulns_for(name, ver):
    if MOCK is not None: return MOCK.get(f"{name}@{ver}", []) or []
    return osv_post("/query", {"version":ver,"package":{"name":name,"ecosystem":"Maven"}}).get("vulns",[]) or []

# determine which libraries have vulnerabilities
if MOCK is not None:
    hits=[(n,v) for n,v in items if MOCK.get(f"{n}@{v}")]
else:
    try:
        q=[{"version":v,"package":{"name":n,"ecosystem":"Maven"}} for n,v in items]
        res=osv_post("/querybatch", {"queries":q}).get("results",[])
        hits=[items[i] for i,rr in enumerate(res) if rr and rr.get("vulns")]
    except urllib.error.URLError as e:
        print(f"CVE: cannot reach OSV.dev ({e}). CVE phase skipped.", file=sys.stderr); sys.exit(0)
    except Exception as e:
        print(f"CVE: OSV error ({e}). CVE phase skipped.", file=sys.stderr); sys.exit(0)

print(f"CVE: {len(hits)} libraries with known vulnerabilities.", file=sys.stderr)
ncve=0
for name,ver in hits:
    try: vulns=vulns_for(name,ver)
    except Exception as e:
        print(f"CVE: detail lookup failed for {name} ({e})", file=sys.stderr); continue
    art=name.split(":")[-1]
    for v in vulns:
        vid=v.get("id","?"); aliases=v.get("aliases",[]) or []
        cve=next((x for x in [vid]+aliases if str(x).startswith("CVE-")), None)
        disp=cve or vid
        summ=(v.get("summary") or v.get("details") or "").strip()
        fx=fixes_for(v,name)
        fxtxt=("fix: >="+", ".join(fx)) if fx else "no fix listed"
        ids=", ".join([vid]+[a for a in aliases if a!=cve])
        emit(map_sev(v), f"{disp} in {art}", f"{name}@{ver}", f"{summ[:160]} | {fxtxt} [{ids}]")
        ncve+=1
print(f"CVE: {ncve} vulnerabilities added to the report.", file=sys.stderr)
PYCVE
fi

# =============================================================================
#  ASSETS / ANOMALIES — files non-standard vs the Android baseline
# =============================================================================
log "Analyzing assets and baseline discrepancies..."
export SS_RES="$RES" SS_FINDINGS="$FINDINGS" SS_APK_PATH="${APK:-}"
python3 - <<'PYASSET'
import os, sys, posixpath
RES=os.environ.get("SS_RES",""); FIN=os.environ["SS_FINDINGS"]; APK=os.environ.get("SS_APK_PATH","")

def emit(sev,cat,typ,title,filef,match=""):
    match=(match or "").replace("\t"," ").replace("\r"," ").replace("\n"," ")[:240]
    with open(FIN,"a",encoding="utf-8") as fh:
        fh.write("\t".join([sev,cat,typ,title,filef,"-",match])+"\n")

# asset extensions "expected" by the baseline (not flagged)
EXPECTED={".tflite",".onnx",".tttf",".ttf",".otf",".woff",".woff2",".png",".jpg",".jpeg",
          ".webp",".gif",".svg",".mp3",".wav",".ogg",".m4a",".lottie",".bin",".dat",".pack",
          ".ico",".cur",".mp4",".webm"}
SENS_EXT={".pem":("HIGH","Crypto material (PEM)"),".key":("HIGH","Possible private key"),
          ".p12":("HIGH","PKCS#12 keystore"),".pfx":("HIGH","PKCS#12 keystore"),
          ".jks":("HIGH","Java KeyStore"),".keystore":("HIGH","KeyStore"),".bks":("HIGH","BouncyCastle KeyStore"),
          ".crt":("MEDIUM","Certificate"),".cer":("MEDIUM","Certificate"),".der":("MEDIUM","DER certificate")}
CONFIG={".json",".xml",".yaml",".yml",".properties",".env",".ini",".conf",".cfg",".toml",".plist",".graphql"}
CODELEAK={".map",".ts",".java",".kt",".py",".rb",".php",".sql",".c",".cpp",".h",".go",".rs"}
DYN={".apk",".dex",".jar",".aar"}
ARCH={".zip",".tar",".gz",".7z",".rar",".tgz"}
DB={".db",".sqlite",".sqlite3",".realm",".mdb"}
DOC={".txt",".md",".pdf",".rtf",".doc",".docx",".csv",".log",".html",".htm"}
DEV_NAMES=(".git/",".ds_store","thumbs.db",".idea/",".vscode/","desktop.ini",".gitignore",
           ".dockerignore",".editorconfig","local.properties")
SENS_SUB=("google-services","firebase","secret","credential","password","private_key","id_rsa","apikey","api_key")

def classify(path):
    p=path.lower(); base=posixpath.basename(p); ext=os.path.splitext(base)[1]
    for s in DEV_NAMES:
        if s in p: return ("MEDIUM","Anomaly","REVIEW",f"Development artifact in the package: {base}")
    for s in SENS_SUB:
        if s in base: return ("HIGH","Assets","FINDING",f"Potentially sensitive filename: {base}")
    if ext in SENS_EXT:
        sev,n=SENS_EXT[ext]; return (sev,"Assets","FINDING",f"{n} in assets: {base}")
    if ext in DYN:     return ("HIGH","Assets","REVIEW",f"Executable/bytecode in assets ({ext}) — possible dynamic loading: {base}")
    if ext in DB:      return ("MEDIUM","Assets","REVIEW",f"Pre-bundled database ({ext}) — verify data: {base}")
    if ext in CODELEAK:return ("MEDIUM","Assets","REVIEW",f"Possible source-code leak ({ext}): {base}")
    if ext in CONFIG:  return ("MEDIUM","Assets","REVIEW",f"Config document in assets ({ext}) — check secrets/endpoints: {base}")
    if ext in ARCH:    return ("LOW","Assets","REVIEW",f"Archive in assets ({ext}) — inspect: {base}")
    if ext in DOC:     return ("LOW","Assets","INFO",f"Document in assets ({ext}): {base}")
    if ext and ext not in EXPECTED:
        return ("LOW","Assets","INFO",f"Non-standard type in assets ({ext}): {base}")
    return None

asset_paths=[]
if APK and os.path.isfile(APK):
    try:
        import zipfile
        z=zipfile.ZipFile(APK)
        names=[n for n in z.namelist() if not n.endswith("/")]
        for nm in names:
            if nm.startswith("assets/"): asset_paths.append(nm)
        # non-standard root entries (outside the baseline known directories)
        for nm in names:
            if "/" in nm: continue
            if not nm.startswith(("classes","resources.arsc","AndroidManifest","DebugProbesKt")):
                emit("LOW","Anomaly","REVIEW",f"Non-standard root entry in the APK: {nm}", nm, "outside assets/res/lib/META-INF")
    except Exception as e:
        print(f"Assets: APK read failed ({e})", file=sys.stderr)
else:
    adir=os.path.join(RES,"assets")
    if os.path.isdir(adir):
        for root,_,files in os.walk(adir):
            for fn in files:
                rel="assets/"+os.path.relpath(os.path.join(root,fn),adir).replace(os.sep,"/")
                asset_paths.append(rel)

n=0
for ap in asset_paths:
    r=classify(ap)
    if r:
        sev,cat,typ,title=r; emit(sev,cat,typ,title,ap,"baseline discrepancy"); n+=1
print(f"Assets: {len(asset_paths)} files in assets, {n} discrepancies flagged.", file=sys.stderr)
PYASSET

# =============================================================================
#  REPORT GENERATION (python: correct escaping)
# =============================================================================
log "Generating reports in $OUTDIR ..."
export SS_FINDINGS="$FINDINGS" SS_OUTDIR="$OUTDIR" SS_FORMAT="$FORMAT"
export SS_APK="$APK_NAME" SS_SCOPE="$SCOPE" SS_PKG="$APP_PKG" SS_TS="$TS" SS_NFILES="$NFILES"
export SS_WORKDIR="$WORKDIR" SS_APK_PATH="${APK:-}" SS_BASELINE="$REF_BASELINE"

python3 - <<'PYEOF'
import os, csv, json, html, datetime
from xml.sax.saxutils import escape as xesc

fp=os.environ["SS_FINDINGS"]; outdir=os.environ["SS_OUTDIR"]; fmt=os.environ["SS_FORMAT"]
apk=os.environ.get("SS_APK",""); scope=os.environ.get("SS_SCOPE",""); pkg=os.environ.get("SS_PKG","")
nfiles=os.environ.get("SS_NFILES","0")
work=os.environ.get("SS_WORKDIR",""); apkpath=os.environ.get("SS_APK_PATH",""); baseline=os.environ.get("SS_BASELINE","")

SEV_RANK={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
SEV_COLOR={"CRITICAL":"#b00020","HIGH":"#d35400","MEDIUM":"#b8860b","LOW":"#2e7d32","INFO":"#546e7a"}
COLS=["severity","category","type","title","file","line","match"]

rows=[]
with open(fp,encoding="utf-8",errors="replace") as fh:
    for line in fh:
        line=line.rstrip("\n")
        if not line: continue
        parts=line.split("\t"); parts+=[""]*(7-len(parts))
        rows.append(dict(zip(COLS,parts[:7])))
rows.sort(key=lambda r:(SEV_RANK.get(r["severity"],9),r["category"],r["title"],r["file"]))

counts={}; tcounts={}; ccounts={}
for r in rows:
    counts[r["severity"]]=counts.get(r["severity"],0)+1
    tcounts[r["type"]]=tcounts.get(r["type"],0)+1
    ccounts[r["category"]]=ccounts.get(r["category"],0)+1

base=os.path.join(outdir,f"secscan-{apk}")
meta={"apk":apk,"scope":scope,"app_package":pkg,"baseline":baseline,
      "generated":datetime.datetime.now().isoformat(timespec="seconds"),
      "files_scanned":int(nfiles) if str(nfiles).isdigit() else nfiles,
      "totals_by_severity":counts,"totals_by_type":tcounts,"total_findings":len(rows)}
want=lambda f: fmt=="all" or fmt==f

if want("csv"):
    p=base+".csv"
    with open(p,"w",newline="",encoding="utf-8-sig") as fh:   # BOM for Excel
        w=csv.writer(fh); w.writerow(COLS)
        for r in rows: w.writerow([r[c] for c in COLS])
    print("CSV  :",p)

if want("json"):
    p=base+".json"
    with open(p,"w",encoding="utf-8") as fh:
        json.dump({"meta":meta,"findings":rows},fh,ensure_ascii=False,indent=2)
    print("JSON :",p)

if want("xml"):
    p=base+".xml"
    with open(p,"w",encoding="utf-8") as fh:
        fh.write('<?xml version="1.0" encoding="UTF-8"?>\n<report>\n  <meta>\n')
        for k,v in meta.items():
            if isinstance(v,dict):
                fh.write(f"    <{k}>\n")
                for kk,vv in v.items(): fh.write(f'      <entry key="{xesc(str(kk))}">{xesc(str(vv))}</entry>\n')
                fh.write(f"    </{k}>\n")
            else: fh.write(f"    <{k}>{xesc(str(v))}</{k}>\n")
        fh.write("  </meta>\n  <findings>\n")
        for r in rows:
            fh.write("    <finding>\n")
            for c in COLS: fh.write(f"      <{c}>{xesc(str(r[c]))}</{c}>\n")
            fh.write("    </finding>\n")
        fh.write("  </findings>\n</report>\n")
    print("XML  :",p)

if want("html"):
    p=base+".html"
    import zipfile
    # ---------- collect file contents for the preview (embedding) ----------
    CAPF=200000; BUDGET=6000000; MAXF=600
    embed={}; total=0; zf=None
    if apkpath and os.path.isfile(apkpath):
        try: zf=zipfile.ZipFile(apkpath)
        except Exception: zf=None
    znames=set(zf.namelist()) if zf else set()
    def read_bytes(relpath):
        for cand in (os.path.join(work,relpath), os.path.join(work,"resources",relpath)):
            try:
                if os.path.isfile(cand):
                    with open(cand,"rb") as fh: return fh.read()
            except Exception: pass
        if zf is not None and relpath in znames:
            try: return zf.read(relpath)
            except Exception: pass
        return None
    seen=set()
    for r in rows:
        fpath=r["file"]
        if not fpath or fpath in seen or fpath.startswith("("): continue
        seen.add(fpath)
        if len(embed)>=MAXF or total>=BUDGET: embed[fpath]={"skip":"budget"}; continue
        data=read_bytes(fpath)
        if data is None: embed[fpath]={"skip":"missing"}; continue
        if b"\x00" in data[:4096]: embed[fpath]={"skip":"binary","size":len(data)}; continue
        try: txt=data.decode("utf-8")
        except Exception:
            try: txt=data.decode("latin-1")
            except Exception: embed[fpath]={"skip":"binary","size":len(data)}; continue
        trunc=len(txt)>CAPF
        if trunc: txt=txt[:CAPF]
        embed[fpath]={"c":txt,"trunc":trunc}; total+=len(txt)
    embed_json=json.dumps(embed,ensure_ascii=False).replace("</","<\\/")

    # ---------- severity palette: two-faction Tron axis (warm=risk, cool=info) ----------
    SEV_ORDER=["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    SEVC={"CRITICAL":"#ff4d33","HIGH":"#ff8f2e","MEDIUM":"#f0b54a","LOW":"#bf9352","INFO":"#4fc2d4"}
    def esc(s): return html.escape(str(s))

    # severity tallies double as the filter toggles (count IS the control)
    sev_chk="".join(
        '<label class="sv'+(' zero' if not counts.get(s,0) else '')+'" data-sev="'+s+'" style="--c:'+SEVC[s]+'">'
        '<input type="checkbox" class="fsev" value="'+s+'" checked>'
        '<span class="n">'+str(counts.get(s,0))+'</span><span class="k">'+s+'</span></label>'
        for s in SEV_ORDER)
    typ_chk="".join(
        '<label class="ty" data-typ="'+t+'"><input type="checkbox" class="ftyp" value="'+t+'" checked>'
        '<span>'+t+'</span></label>' for t in ["FINDING","REVIEW","INFO"])
    spectrum="".join('<i class="sg" data-sev="'+s+'" style="--c:'+SEVC[s]+'"></i>' for s in SEV_ORDER)
    cat_list=sorted(ccounts.keys(), key=lambda c:(-ccounts[c], c))
    cat_chk="".join(
        '<label class="ty" data-cat="'+esc(c)+'"><input type="checkbox" class="fcat" value="'+esc(c)+'" checked>'
        '<span>'+esc(c)+'</span><span class="ycnt">'+str(ccounts[c])+'</span></label>' for c in cat_list)

    # Rows are shipped as compact JSON (not pre-rendered HTML): with deep scans
    # (10k+ rows) building one <tr> per row server-side produces a multi-MB DOM
    # that the browser struggles to lay out. The client renders only the rows
    # currently visible in the viewport (see the "virtual scroll" JS below).
    rows_data=[[r["severity"],r["category"],r["type"],r["title"],r["file"],r["line"],r["match"]] for r in rows]
    rows_json=json.dumps(rows_data,ensure_ascii=False).replace("</","<\\/")

    meta_html=('PKG <b>'+esc(pkg or "n/a")+'</b><i>//</i>SCOPE <b>'+esc(scope)+'</b><i>//</i>'
               'FILES <b>'+esc(str(nfiles))+'</b><i>//</i>'+esc(meta["generated"]))

    TEMPLATE=r'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SECSCAN // @@APK@@</title>
<style>
 :root{
  --bg:#04080d;--bg2:#070e16;--panel:#0a141d;--panel2:#0c1a26;
  --line:#143544;--line2:#0e2330;--edge:#0a1a25;
  --cy:#5cd2e6;--cyd:#2c8395;--cydim:#16414e;--cyglass:rgba(92,210,230,.08);
  --am:#ff9d33;--amd:#9a5a1c;
  --tx:#bfe6ef;--tx2:#e6f7fb;--mut:#5f8492;--mut2:#3d626f;
  --glow:rgba(92,210,230,.42);--amglow:rgba(255,157,51,.40);
  --crit:#ff4d33;--high:#ff8f2e;--med:#f0b54a;--low:#bf9352;--info:#4fc2d4;
  --mono:ui-monospace,'JetBrains Mono','SF Mono','Cascadia Mono',Menlo,Consolas,monospace;
  --hud:'DIN Alternate','Bahnschrift','Eurostile','Oswald',ui-sans-serif,system-ui,sans-serif;
 }
 *{box-sizing:border-box}
 html,body{margin:0;height:100%}
 body{display:flex;flex-direction:column;height:100vh;overflow:hidden;
  background:var(--bg);color:var(--tx);font-family:var(--mono);font-size:13px;line-height:1.45;
  background-image:
   radial-gradient(1100px 520px at 82% -8%,rgba(255,157,51,.055),transparent 60%),
   radial-gradient(900px 640px at -4% -6%,rgba(92,210,230,.07),transparent 55%),
   linear-gradient(var(--line2) 1px,transparent 1px),
   linear-gradient(90deg,var(--line2) 1px,transparent 1px);
  background-size:auto,auto,44px 44px,44px 44px;
  -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
 b{font-weight:600}
 ::selection{background:var(--am);color:#150a00}

 /* ---------- header ---------- */
 header{flex:0 0 auto;position:relative;padding:14px 22px 13px;border-bottom:1px solid var(--line);
  background:linear-gradient(180deg,var(--panel2),rgba(4,8,13,.2))}
 .hbar{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;font-size:10.5px}
 .brandcol{display:flex;flex-direction:column;gap:7px;min-width:0}
 .ascii{margin:0;font-family:var(--mono);font-size:8.5px;line-height:1.08;color:var(--cy);
  text-shadow:0 0 9px var(--glow);white-space:pre;user-select:none;overflow:hidden}
 .brand{font-family:var(--hud);letter-spacing:.32em;color:var(--mut);text-transform:uppercase;font-size:9px}
 .brand .sl{color:var(--mut2)}
 .brand .cur{display:inline-block;width:7px;height:10px;background:var(--cy);margin-left:5px;
  vertical-align:-1px;box-shadow:0 0 7px var(--glow);animation:blink 1.2s steps(1) infinite}
 @keyframes blink{50%{opacity:0}}
 .hstat{font-family:var(--hud);letter-spacing:.28em;color:var(--mut);text-transform:uppercase}
 .hstat::before{content:"";display:inline-block;width:6px;height:6px;margin-right:7px;vertical-align:1px;
  background:var(--low);border-radius:50%;box-shadow:0 0 8px var(--low)}
 h1{font-family:var(--hud);margin:7px 0 9px;font-size:25px;font-weight:700;letter-spacing:.06em;
  color:var(--tx2);text-transform:uppercase}
 h1 .ap{color:var(--am);text-shadow:0 0 18px var(--amglow)}
 h1 .ap::before{content:"\203A\00a0";color:var(--amd)}
 .meta{font-size:11px;color:var(--mut);letter-spacing:.02em}
 .meta b{color:var(--cy);font-weight:600} .meta i{color:var(--mut2);font-style:normal;margin:0 9px}
 .baseline{margin-top:7px;display:flex;align-items:center;gap:10px;font-size:10.5px;color:var(--mut)}
 .baseline .tag{font-family:var(--hud);letter-spacing:.2em;color:var(--cy);border:1px solid var(--cydim);
  padding:2px 9px;text-transform:uppercase;
  clip-path:polygon(5px 0,100% 0,100% calc(100% - 5px),calc(100% - 5px) 100%,0 100%,0 5px)}

 /* ---------- console (counts + spectrum + controls) ---------- */
 .console{flex:0 0 auto;padding:13px 22px 11px;border-bottom:1px solid var(--line);
  background:linear-gradient(180deg,rgba(10,20,30,.4),transparent)}
 .sevrow{display:flex;gap:9px;flex-wrap:wrap}
 .sv{position:relative;display:inline-flex;align-items:baseline;gap:8px;padding:6px 14px 6px 15px;cursor:pointer;
  border:1px solid var(--line);background:linear-gradient(180deg,var(--panel2),var(--panel));user-select:none;
  clip-path:polygon(0 0,100% 0,100% 100%,8px 100%,0 calc(100% - 8px));transition:border-color .14s,opacity .14s,filter .14s}
 .sv::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--c)}
 .sv .n{font-family:var(--hud);font-size:19px;font-weight:700;line-height:1;color:var(--c)}
 .sv .k{font-size:10px;letter-spacing:.2em;color:var(--mut)}
 .sv input{position:absolute;opacity:0;pointer-events:none}
 .sv:hover{border-color:var(--c)}
 .sv:not(:has(input:checked)){opacity:.34;filter:saturate(.35)}
 .sv:has(input:checked) .k{color:var(--tx)}
 .sv.zero{opacity:.22;filter:saturate(.2)}
 .sv.zero:hover{opacity:.5}
 .spectrum{display:flex;height:6px;margin:11px 0 3px;gap:2px;background:var(--bg2);
  border:1px solid var(--line2);overflow:hidden}
 .spectrum .sg{width:0;background:var(--c);box-shadow:0 0 9px -2px var(--c);transition:width .3s ease,opacity .3s}
 .catrow{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-top:11px}
 .catrow .lbl{font-family:var(--hud);letter-spacing:.18em;color:var(--cy);text-transform:uppercase;font-size:11px;margin-right:2px}
 .ty .ycnt{margin-left:6px;color:var(--mut2);font-size:9.5px}
 .btn.mini{padding:2px 8px;font-size:9.5px}
 .controls{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-top:11px;font-size:11px}
 .controls .lbl{font-family:var(--hud);letter-spacing:.18em;color:var(--cy);text-transform:uppercase}
 .grp{display:flex;gap:6px;align-items:center}
 .ty{display:inline-flex;align-items:center;cursor:pointer;user-select:none;border:1px solid var(--line);
  color:var(--mut);padding:3px 11px;letter-spacing:.12em;font-size:10.5px;transition:.14s;
  clip-path:polygon(4px 0,100% 0,100% calc(100% - 4px),calc(100% - 4px) 100%,0 100%,0 4px)}
 .ty input{display:none}
 .ty:hover{border-color:var(--cyd);color:var(--tx)}
 .ty:has(input:checked){border-color:var(--cy);color:var(--cy);background:var(--cyglass)}
 input[type=text],.btn{background:var(--bg2);border:1px solid var(--cydim);color:var(--tx);
  padding:5px 11px;font:inherit;font-size:11.5px;outline:none;
  clip-path:polygon(5px 0,100% 0,100% calc(100% - 5px),calc(100% - 5px) 100%,0 100%,0 5px)}
 #q{min-width:230px;flex:0 1 280px}
 #q::placeholder{color:var(--mut2)}
 input[type=text]:focus{border-color:var(--cy);box-shadow:0 0 0 1px var(--cyglass),0 0 14px -4px var(--glow)}
 .btn{cursor:pointer;color:var(--cy);letter-spacing:.12em;text-transform:uppercase;font-family:var(--hud)}
 .btn:hover{background:var(--cyglass)}
 .btn.on{background:rgba(92,210,230,.16);color:var(--tx2);border-color:var(--cy)}
 #shown{margin-left:auto;color:var(--mut);font-family:var(--hud);letter-spacing:.16em;font-size:11px}
 #shown b{color:var(--cy)}

 /* ---------- interaction hint ---------- */
 .hint{flex:0 0 auto;padding:7px 22px;color:var(--mut2);font-size:10.5px;letter-spacing:.02em;
  border-bottom:1px solid var(--line2);background:rgba(4,8,13,.4)}
 .hint b{color:var(--mut);font-weight:400}
 .hint .ar{color:var(--cyd)}

 /* ---------- table ---------- */
 .tablewrap{flex:1 1 auto;min-height:0;overflow:auto;
  background:linear-gradient(180deg,rgba(10,20,30,.28),rgba(4,8,13,.28))}
 table{border-collapse:collapse;table-layout:fixed;font-size:12.5px}
 thead th{position:sticky;top:0;z-index:4;text-align:left;padding:9px 12px;white-space:nowrap;
  background:#081420;color:var(--cy);font-family:var(--hud);font-weight:600;font-size:10.5px;
  letter-spacing:.18em;text-transform:uppercase;border-bottom:1px solid var(--cydim);cursor:pointer}
 thead th::after{content:"";position:absolute;left:0;right:0;bottom:-1px;height:1px;
  background:linear-gradient(90deg,transparent,var(--cy),transparent);opacity:.55}
 thead th.sp{background:#081420;cursor:default}
 thead th .sa{display:inline-block;margin-left:5px;font-size:9px;color:var(--cydim)}
 thead th.sorted{color:var(--tx2)}
 thead th.sorted .sa{color:var(--am)}
 .grip{position:absolute;top:0;right:-4px;width:9px;height:100%;cursor:col-resize;z-index:6}
 .grip::after{content:"";position:absolute;right:4px;top:24%;bottom:24%;width:1px;background:var(--cydim)}
 .grip:hover::after,.grip.drag::after{background:var(--cy);width:2px;right:3px;top:6%;bottom:6%;
  box-shadow:0 0 7px var(--glow)}
 tbody td{padding:7px 12px;border-bottom:1px solid var(--line2);vertical-align:top;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
 tbody td.c-sev{border-left:3px solid var(--rc)}
 tbody tr{cursor:pointer}
 tbody tr.vsp{cursor:default}
 tbody tr.vsp td{background:transparent!important;border:none!important;padding:0!important}
 tbody tr:nth-child(even) td{background:rgba(92,210,230,.022)}
 tbody tr:hover td{background:rgba(92,210,230,.06)}
 tbody tr.sel td{background:rgba(255,157,51,.09)}
 tbody tr.sel td.c-sev{border-left-color:var(--am)}
 table.wrap tbody td{white-space:normal;overflow:visible;text-overflow:clip;word-break:break-word}
 .bdg{display:inline-block;color:var(--c);font-size:10px;font-weight:700;letter-spacing:.08em;padding:1px 7px;
  border:1px solid color-mix(in srgb,var(--c) 50%,transparent);
  background:color-mix(in srgb,var(--c) 13%,transparent)}
 .c-cat{color:var(--tx)} .c-ttl{color:var(--tx2)}
 .mono{color:#9cccdb} .c-line{color:var(--mut);text-align:right}
 .c-match{color:#86b3c4}
 /* Type carries NO hue: severity badge owns all color. Differentiate by weight. */
 .c-typ{font-size:10.5px;letter-spacing:.1em;color:var(--mut)}
 .ty-find{color:var(--tx2);font-weight:700} .ty-rev{color:var(--tx);font-weight:500} .ty-info{color:var(--mut2)}
 #empty{display:none;padding:26px 22px;color:var(--mut)}
 #empty::before{content:"\25B8\00a0"}

 /* ---------- footer legend ---------- */
 footer{flex:0 0 auto;display:flex;flex-wrap:wrap;align-items:baseline;gap:2px 0;
  padding:10px 22px;border-top:1px solid var(--line);
  background:linear-gradient(0deg,var(--panel2),transparent);color:var(--mut);font-size:10px;letter-spacing:.02em}
 footer .ftag{font-family:var(--hud);letter-spacing:.18em;color:var(--mut2);font-size:9px;margin:0 9px 0 0}
 footer .ftag.gap{margin-left:16px}
 footer .lg{display:inline-flex;align-items:baseline;gap:6px;margin-right:14px;white-space:nowrap}
 footer b{color:var(--cy);font-family:var(--hud);letter-spacing:.1em;font-weight:600}

 /* ---------- scrollbars ---------- */
 ::-webkit-scrollbar{width:11px;height:12px}
 ::-webkit-scrollbar-track{background:#06101a}
 ::-webkit-scrollbar-thumb{background:var(--cydim);border:2px solid #06101a}
 ::-webkit-scrollbar-thumb:hover{background:var(--cyd)}
 ::-webkit-scrollbar-corner{background:#06101a}
 *{scrollbar-color:var(--cydim) #06101a;scrollbar-width:thin}
 body.resizing{cursor:col-resize;user-select:none}

 /* ---------- preview drawer ---------- */
 #ov{position:fixed;inset:0;background:rgba(2,6,10,.55);z-index:20;display:none}
 #dr{position:fixed;top:0;right:0;height:100%;width:min(960px,96vw);min-width:340px;z-index:21;transform:translateX(101%);
  transition:transform .22s ease-out;background:linear-gradient(180deg,var(--panel2),var(--bg));
  border-left:1px solid var(--cy);box-shadow:-16px 0 50px -20px var(--glow);display:flex;flex-direction:column}
 #dr.open{transform:none}
 .dgrip{position:absolute;left:0;top:0;width:11px;height:100%;cursor:col-resize;z-index:23;transform:translateX(-50%)}
 .dgrip::after{content:"";position:absolute;left:50%;top:0;bottom:0;width:1px;background:var(--cydim);transform:translateX(-50%)}
 .dgrip:hover::after,.dgrip.drag::after{background:var(--cy);width:2px;box-shadow:0 0 9px var(--glow)}
 .dhead{padding:14px 16px;border-bottom:1px solid var(--line)}
 .dhead .fn{color:var(--am);font-size:12.5px;word-break:break-all}
 .dhead .sub{color:var(--mut);font-size:10.5px;margin-top:4px;font-family:var(--hud);letter-spacing:.1em}
 .dbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:9px 16px;border-bottom:1px solid var(--line);font-size:11px}
 .dbar input[type=text]{min-width:120px;flex:1}
 .dbar .cnt{color:var(--mut);min-width:52px;text-align:right;font-family:var(--hud);letter-spacing:.08em}
 .dbar .sep{flex:0 0 1px;align-self:stretch;background:var(--line);margin:1px 2px}
 .pvwrap{flex:1;overflow:auto;background:rgba(2,8,12,.55)}
 .code{margin:0;padding:10px 0;font-size:12px;line-height:1.6;tab-size:4;--lnw:3ch;min-width:max-content}
 .code .cl{display:flex;align-items:flex-start}
 .code .cl:hover{background:rgba(92,210,230,.045)}
 .code .ln{flex:0 0 auto;width:var(--lnw);min-width:var(--lnw);text-align:right;color:#2f5563;user-select:none;
  padding:0 14px 0 16px;position:sticky;left:0;background:#06121a;border-right:1px solid var(--line2)}
 .code .lc{flex:1 1 auto;white-space:pre;padding:0 16px 0 14px}
 .code.wrap{min-width:0}
 .code.wrap .lc{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word}
 .tk-com{color:#3f6b78;font-style:italic}.tk-str{color:#ffc98f}.tk-num{color:var(--med)}
 .tk-kw{color:var(--cy);font-weight:600}.tk-anno{color:var(--am)}.tk-tag{color:var(--cy)}
 .tk-attr{color:#9cccdb}.tk-punct{color:var(--mut)}.tk-key{color:#9cccdb}
 mark{background:var(--am);color:#160b00;padding:0 1px}
 mark.active{background:var(--cy);color:#001016;box-shadow:0 0 10px var(--glow)}
 .x{cursor:pointer;color:var(--mut);font-size:14px}.x:hover{color:var(--cy)}
 #toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(18px);opacity:0;z-index:30;
  background:var(--panel2);border:1px solid var(--cy);color:var(--cy);padding:9px 18px;font-size:11.5px;
  font-family:var(--hud);letter-spacing:.12em;text-transform:uppercase;
  box-shadow:0 0 22px -6px var(--glow);transition:.22s;
  clip-path:polygon(6px 0,100% 0,100% calc(100% - 6px),calc(100% - 6px) 100%,0 100%,0 6px)}
 #toast.show{opacity:1;transform:translateX(-50%)}
 @media(max-width:680px){header,.console,.hint,footer{padding-left:12px;padding-right:12px}
  h1{font-size:20px}}
</style></head><body>
<header>
 <div class="hbar">
  <div class="brandcol">
   <pre class="ascii" aria-label="apkSEC">                __      ____    ____    ____
               /\ \    /\  _`\ /\  _`\ /\  _`\
   __     _____\ \ \/'\\ \,\L\_\ \ \L\_\ \ \/\_\
 /'__`\  /\ '__`\ \ , &lt; \/_\__ \\ \  _\L\ \ \/_/_
/\ \L\.\_\ \ \L\ \ \ \\`\ /\ \L\ \ \ \L\ \ \ \L\ \
\ \__/.\_\\ \ ,__/\ \_\ \_\ `\____\ \____/\ \____/
 \/__/\/_/ \ \ \/  \/_/\/_/\/_____/\/___/  \/___/
            \ \_\
             \/_/                                 </pre>
   <div class="brand">APK<span class="sl">//</span>SECSCAN<span class="sl"> · </span>STATIC SECURITY REVIEW<span class="cur"></span></div>
  </div>
  <div class="hstat">Scan complete</div>
 </div>
 <h1>Security&nbsp;Scan <span class="ap">@@APK@@</span></h1>
 <div class="meta">@@META@@</div>
 <div class="baseline"><span class="tag">Baseline</span><span class="bvals">@@BASELINE@@</span></div>
</header>
<div class="console">
 <div class="sevrow">@@SEVCHK@@</div>
 <div class="spectrum">@@SPECTRUM@@</div>
 <div class="catrow" id="catrow">
  <span class="lbl">Category</span>
  <button type="button" class="btn mini" id="catAll">All</button>
  <button type="button" class="btn mini" id="catNone">None</button>
  @@CATCHK@@
 </div>
 <div class="controls">
  <span class="lbl">Type</span><div class="grp">@@TYPCHK@@</div>
  <input type="text" id="q" placeholder="filter rows  (title / file / match)  ·  press / to focus">
  <button class="btn" id="wrapBtn">Wrap off</button>
  <button class="btn" id="expBtn" title="export the rows currently visible (after filters) as CSV">Export visible</button>
  <span id="shown"></span>
 </div>
</div>
<div class="hint"><span class="ar">&#9656;</span> <b>Click</b> a row to inspect the file
 &middot; <b>double-click</b> to copy its path
 &middot; <b>drag</b> a header divider to resize <b>(double-click = auto-fit)</b></div>
<div class="tablewrap">
 <table id="tbl">
  <colgroup><col><col><col><col><col><col><col><col class="sp"></colgroup>
  <thead><tr>
   <th data-k="sev">Sev<i class="sa"></i></th><th data-k="cat">Category<i class="sa"></i></th><th data-k="typ">Type<i class="sa"></i></th><th data-k="ttl">Title<i class="sa"></i></th><th data-k="file">File<i class="sa"></i></th><th data-k="line">Line<i class="sa"></i></th><th data-k="match">Match<i class="sa"></i></th><th class="sp"></th>
  </tr></thead>
  <tbody id="tb"></tbody>
 </table>
</div>
<div id="empty">no rows match the current filters</div>
<footer>
 <span class="ftag">Type</span>
 <span class="lg"><b>FINDING</b> confirmed evidence</span>
 <span class="lg"><b>REVIEW</b> runtime surface to verify</span>
 <span class="lg"><b>INFO</b> public identifier</span>
 <span class="ftag gap">Category</span>
 <span class="lg"><b>DEPENDENCY</b> known CVE &middot; OSV.dev</span>
 <span class="lg"><b>ASSETS / ANOMALY</b> baseline discrepancy</span>
</footer>
<div id="ov"></div>
<div id="dr">
 <div class="dgrip" id="dgrip" title="drag to resize · double-click for full width"></div>
 <div class="dhead"><div class="fn" id="drfn">&mdash;</div><div class="sub" id="drsub"></div></div>
 <div class="dbar">
  <input type="text" id="ps" placeholder="search (regex)">
  <button class="btn" id="pRe" title="toggle regex">.*</button>
  <button class="btn on" id="pCi" title="case-insensitive">Aa</button>
  <button class="btn" id="pPrev" title="previous">&lsaquo;</button>
  <button class="btn" id="pNext" title="next">&rsaquo;</button>
  <span class="cnt" id="pCnt"></span>
  <span class="sep"></span>
  <button class="btn" id="pWrap" title="toggle word wrap">Wrap</button>
  <button class="btn" id="pCopy">Copy path</button>
  <span class="x" id="drx" title="close (Esc)">&#10005;</span>
 </div>
 <div class="pvwrap"><div class="code" id="pv"></div></div>
</div>
<div id="toast"></div>
<script id="embed" type="application/json">@@EMBED@@</script>
<script id="rowsdata" type="application/json">@@ROWSJSON@@</script>
<script>
 const EMBED=JSON.parse(document.getElementById('embed').textContent||'{}');
 // DATA: one array per row, column order = [sev,cat,typ,title,file,line,match]
 // (matches the <thead> columns 1:1). Kept as arrays, not objects, so a 10k+
 // row report stays a few hundred KB of JSON instead of megabytes of markup.
 const DATA=JSON.parse(document.getElementById('rowsdata').textContent||'[]');
 let filtered=DATA.slice(), comparator=null;
 const SEVC={CRITICAL:'#ff4d33',HIGH:'#ff8f2e',MEDIUM:'#f0b54a',LOW:'#bf9352',INFO:'#4fc2d4'};
 const SEV_RANK={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
 const tbl=document.getElementById('tbl'),wrap=document.querySelector('.tablewrap');
 const tb=document.getElementById('tb');
 const q=document.getElementById('q'),shown=document.getElementById('shown'),empty=document.getElementById('empty');
 const SEGS=[...document.querySelectorAll('.spectrum .sg')];
 const sevSel=()=>new Set([...document.querySelectorAll('.fsev:checked')].map(c=>c.value));
 const typSel=()=>new Set([...document.querySelectorAll('.ftyp:checked')].map(c=>c.value));
 const catSel=()=>new Set([...document.querySelectorAll('.fcat:checked')].map(c=>c.value));

 // ---------- virtual scroll: only the rows visible in the viewport are ever
 // real DOM nodes (a fixed row height + top/bottom spacer <tr>s), so table
 // size no longer depends on how many findings the scan produced. ----------
 let selIdx=-1, renderedStart=-1, renderedEnd=-1, ROWH=33, rowHMeasured=false, wrapMode=false;
 const BUFFER=8;
 function tcClass(t){return t==='FINDING'?'ty-find':(t==='REVIEW'?'ty-rev':'ty-info');}
 function badge(s){return '<span class="bdg" style="--c:'+(SEVC[s]||'#5cd2e6')+'">'+esc(s)+'</span>';}
 function rowHtml(r,idx){
  const sev=r[0],cat=esc(r[1]),typ=r[2],ttl=esc(r[3]),file=esc(r[4]),line=esc(r[5]),match=esc(r[6]);
  const rc=SEVC[sev]||'#5cd2e6';
  return '<tr data-i="'+idx+'"'+(idx===selIdx?' class="sel"':'')+' style="--rc:'+rc+'">'
   +'<td class="c-sev">'+badge(sev)+'</td>'
   +'<td class="c-cat">'+cat+'</td>'
   +'<td class="c-typ '+tcClass(typ)+'">'+esc(typ)+'</td>'
   +'<td class="c-ttl" title="'+ttl+'">'+ttl+'</td>'
   +'<td class="mono c-file" title="'+file+'">'+file+'</td>'
   +'<td class="mono c-line">'+line+'</td>'
   +'<td class="mono c-match" title="'+match+'">'+match+'</td>'
   +'<td class="c-sp"></td></tr>';
 }
 function renderAll(){
  let html=''; for(let i=0;i<filtered.length;i++) html+=rowHtml(filtered[i],i);
  tb.innerHTML=html;
 }
 function renderWindow(force){
  if(wrapMode){renderAll();return;}
  const total=filtered.length;
  const scrollTop=wrap.scrollTop, viewH=wrap.clientHeight||600;
  const start=Math.max(0,Math.floor(scrollTop/ROWH)-BUFFER);
  const end=Math.min(total,Math.ceil((scrollTop+viewH)/ROWH)+BUFFER);
  if(!force && start===renderedStart && end===renderedEnd) return;
  renderedStart=start; renderedEnd=end;
  const topH=start*ROWH, botH=Math.max(0,(total-end)*ROWH);
  let html='<tr class="vsp" style="height:'+topH+'px"><td colspan="8" style="height:'+topH+'px"></td></tr>';
  for(let i=start;i<end;i++) html+=rowHtml(filtered[i],i);
  html+='<tr class="vsp" style="height:'+botH+'px"><td colspan="8" style="height:'+botH+'px"></td></tr>';
  tb.innerHTML=html;
  if(!rowHMeasured){
   const tr=tb.querySelector('tr[data-i]');
   if(tr){const h=tr.getBoundingClientRect().height;
    if(h>0){rowHMeasured=true; if(Math.abs(h-ROWH)>0.5){ROWH=h;renderedStart=-1;renderedEnd=-1;renderWindow(true);}}}
  }
 }
 let scTick=false;
 wrap.addEventListener('scroll',()=>{if(wrapMode||scTick)return;scTick=true;
  requestAnimationFrame(()=>{scTick=false;renderWindow();});});

 function apply(){
  const S=sevSel(),T=typSel(),C=catSel(),Q=q.value.toLowerCase();
  filtered=DATA.filter(r=>S.has(r[0])&&T.has(r[2])&&C.has(r[1])
   &&(Q===''||(r[0]+r[1]+r[2]+r[3]+r[4]+r[5]+r[6]).toLowerCase().includes(Q)));
  if(comparator) filtered.sort(comparator);
  const n=filtered.length; const vis={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};
  for(const r of filtered) vis[r[0]]=(vis[r[0]]||0)+1;
  shown.innerHTML='<b>'+n+'</b> / '+DATA.length+' rows';
  empty.style.display=n?'none':'block';
  const tot=n||1;
  for(const sg of SEGS){const c=vis[sg.dataset.sev]||0;sg.style.width=(c*100/tot)+'%';sg.style.opacity=c?'1':'0';}
  selIdx=-1; renderedStart=-1; renderedEnd=-1; wrap.scrollTop=0; renderWindow(true);
 }
 document.querySelectorAll('.fsev,.ftyp,.fcat').forEach(c=>c.addEventListener('change',apply));
 q.addEventListener('input',apply);
 document.getElementById('catAll').addEventListener('click',()=>{document.querySelectorAll('.fcat').forEach(c=>c.checked=true);apply();});
 document.getElementById('catNone').addEventListener('click',()=>{document.querySelectorAll('.fcat').forEach(c=>c.checked=false);apply();});
 document.addEventListener('keydown',e=>{
  if(e.key==='/'&&document.activeElement!==q&&document.activeElement!==ps){e.preventDefault();q.focus();}
 });

 // wrap toggle (word-wrap mode renders every filtered row at once: rows no
 // longer have a uniform height, so the virtual-scroll math is disabled)
 const wrapBtn=document.getElementById('wrapBtn');
 wrapBtn.addEventListener('click',()=>{wrapMode=tbl.classList.toggle('wrap');
  wrapBtn.classList.toggle('on',wrapMode);wrapBtn.textContent='Wrap '+(wrapMode?'on':'off');
  if(wrapMode&&filtered.length>2000) toast('wrap on '+filtered.length+' rows — this may be slow');
  layout();renderedStart=-1;renderedEnd=-1;renderWindow(true);});

 // ---------- deterministic column resize (data cols + flexible spacer) ----------
 const cols=[...tbl.querySelectorAll('colgroup col')];   // 7 data + 1 spacer
 const ths=[...tbl.querySelectorAll('thead th')];
 const NCOL=7;
 const DEF=[88,120,94,300,360,58,520];
 const MIN=[54,76,64,120,140,46,120];
 let W=DEF.slice();
 function layout(){
  let sum=0; for(let i=0;i<NCOL;i++){cols[i].style.width=W[i]+'px';sum+=W[i];}
  const slack=Math.max(0,wrap.clientWidth-sum-1);
  cols[NCOL].style.width=slack+'px';
  tbl.style.width=(sum+slack)+'px';
 }
 let _measureCanvas=null;
 function autofit(i){
  // Rows beyond the viewport aren't real DOM nodes (virtual scroll), so width
  // is estimated with canvas text measurement over the filtered data instead
  // of scanning <td> elements.
  const sample=tb.querySelector('td.mono')||tb.querySelector('td');
  const font=sample?getComputedStyle(sample).font:getComputedStyle(tbl).font;
  if(!_measureCanvas) _measureCanvas=document.createElement('canvas');
  const ctx=_measureCanvas.getContext('2d'); ctx.font=font;
  let mx=ctx.measureText(ths[i].textContent).width;
  for(const r of filtered){const w=ctx.measureText(String(r[i])).width;if(w>mx)mx=w;}
  return Math.min(Math.max(Math.ceil(mx)+20,MIN[i]),760);
 }
 ths.slice(0,NCOL).forEach((th,i)=>{
  const g=document.createElement('div'); g.className='grip'; th.appendChild(g);
  let sx=0,sw=0;
  const move=e=>{W[i]=Math.max(MIN[i],sw+(e.clientX-sx));layout();};
  const up=()=>{document.removeEventListener('mousemove',move);document.removeEventListener('mouseup',up);
   document.body.classList.remove('resizing');g.classList.remove('drag');};
  g.addEventListener('mousedown',e=>{sx=e.clientX;sw=W[i];g.classList.add('drag');
   document.addEventListener('mousemove',move);document.addEventListener('mouseup',up);
   document.body.classList.add('resizing');e.preventDefault();e.stopPropagation();});
  g.addEventListener('dblclick',e=>{W[i]=autofit(i);layout();e.preventDefault();e.stopPropagation();});
  g.addEventListener('click',e=>e.stopPropagation());
 });
 let rT; window.addEventListener('resize',()=>{clearTimeout(rT);
  rT=setTimeout(()=>{layout();renderedStart=-1;renderedEnd=-1;renderWindow(true);},80);});
 layout(); apply();

 // ---------- click-to-sort columns (sorts the data array, not DOM nodes) ----------
 const sortState={col:-1,dir:1};
 function sortBy(i){
  if(sortState.col===i) sortState.dir*=-1; else{sortState.col=i;sortState.dir=1;}
  const dir=sortState.dir, col=i;
  comparator=(a,b)=>{
   if(col===0) return (SEV_RANK[a[0]]-SEV_RANK[b[0]])*dir;
   const av=a[col],bv=b[col];
   const an=parseFloat(av),bn=parseFloat(bv);
   if(!isNaN(an)&&!isNaN(bn)&&String(av).trim()!=='-'&&String(bv).trim()!=='-') return (an-bn)*dir;
   return String(av).localeCompare(String(bv))*dir;
  };
  filtered.sort(comparator);
  ths.slice(0,NCOL).forEach((th,idx)=>{
   th.classList.toggle('sorted',idx===i);
   const sa=th.querySelector('.sa'); if(sa) sa.textContent=idx===i?(dir>0?'▲':'▼'):'';
  });
  renderedStart=-1;renderedEnd=-1; wrap.scrollTop=0; renderWindow(true);
 }
 ths.slice(0,NCOL).forEach((th,i)=>{
  th.addEventListener('click',e=>{ if(e.target.closest('.grip')) return; sortBy(i); });
 });

 // ---------- export currently-visible (filtered) rows as CSV ----------
 document.getElementById('expBtn').addEventListener('click',()=>{
  const csvEsc=s=>{ s=String(s); return /[",\r\n]/.test(s) ? '"'+s.replace(/"/g,'""')+'"' : s; };
  const head=['severity','category','type','title','file','line','match'];
  if(!filtered.length){toast('nothing to export');return;}
  const lines=[head.join(',')];
  for(const r of filtered) lines.push(r.map(csvEsc).join(','));
  const blob=new Blob([lines.join('\r\n')],{type:'text/csv;charset=utf-8'});
  const a=document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download='secscan-filtered.csv'; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(()=>URL.revokeObjectURL(a.href),1000);
  toast(filtered.length+' rows exported');
 });

 // ---------- preview drawer + lightweight syntax highlight ----------
 function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
 const KW='abstract assert boolean break byte case catch char class const continue default do double else enum extends final finally float for goto if implements import instanceof int interface long native new package private protected public return short static strictfp super switch synchronized this throw throws transient try void volatile while var val fun object companion data sealed when suspend lazy null true false function let typeof async await';
 const KWRE='\\b(?:'+KW.trim().split(/\s+/).join('|')+')\\b';
 const SPECS={
  json:[['com','\\/\\/.*|\\/\\*[\\s\\S]*?\\*\\/'],['str','"(?:\\\\.|[^"\\\\])*"'],['num','-?\\b\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?\\b'],['kw','\\b(?:true|false|null)\\b'],['punct','[{}\\[\\]:,]']],
  xml:[['com','<!--[\\s\\S]*?-->'],['str','"[^"]*"|\\x27[^\\x27]*\\x27'],['tag','<\\/?[A-Za-z_][\\w:.\\-]*|\\/?>'],['attr','[A-Za-z_][\\w:.\\-]*(?==)']],
  code:[['com','\\/\\/.*|\\/\\*[\\s\\S]*?\\*\\/|#.*'],['str','"(?:\\\\.|[^"\\\\])*"|\\x27(?:\\\\.|[^\\x27\\\\])*\\x27|`[^`]*`'],['anno','@[A-Za-z_]\\w*'],['kw',KWRE],['num','\\b\\d[\\w.]*\\b']],
  props:[['com','[#!].*'],['str','"[^"]*"'],['num','\\b\\d+(?:\\.\\d+)?\\b'],['key','[A-Za-z_][\\w.\\-]*(?=\\s*[=:])']],
  generic:[['com','#.*|\\/\\/.*'],['str','"(?:\\\\.|[^"\\\\])*"|\\x27[^\\x27]*\\x27'],['num','\\b\\d+(?:\\.\\d+)?\\b']]
 };
 function langOf(path){const e=(path.split('.').pop()||'').toLowerCase();
  if(e==='json')return'json';
  if(['xml','html','htm','svg','plist','graphql'].includes(e))return'xml';
  if(['java','kt','kts','js','jsx','ts','tsx','c','cpp','h','go','rs','swift','dart'].includes(e))return'code';
  if(['properties','ini','conf','cfg','env','toml','yaml','yml','gradle'].includes(e))return'props';
  return'generic';}
 function hl(code,lang){
  const spec=SPECS[lang]||SPECS.generic;
  const re=new RegExp(spec.map(s=>'('+s[1]+')').join('|'),'g');
  let out='',last=0,m;
  while((m=re.exec(code))){
   out+=esc(code.slice(last,m.index));
   let gi=0;for(let i=0;i<spec.length;i++){if(m[i+1]!==undefined){gi=i;break;}}
   out+='<span class="tk-'+spec[gi][0]+'">'+esc(m[0])+'</span>';
   last=re.lastIndex;if(m[0]===''){re.lastIndex++;}
  }
  out+=esc(code.slice(last));return out;
 }
 // split highlighted/marked HTML into per-line rows (balanced tags) + a sticky gutter
 function numberize(innerHtml){
  const re=/(<\/?[a-zA-Z][^>]*>)|([^<]+)/g;
  const lines=[[]],open=[];
  const push=s=>lines[lines.length-1].push(s);
  const nameOf=t=>{const m=/^<\s*([a-zA-Z]+)/.exec(t);return m?m[1]:'span';};
  let m;
  while((m=re.exec(innerHtml))){
   if(m[1]){const t=m[1];
    if(/^<\//.test(t)){push(t);open.pop();}
    else if(/\/>\s*$/.test(t)){push(t);}
    else{push(t);open.push(t);}
   }else{
    const parts=m[2].split('\n');
    for(let i=0;i<parts.length;i++){
     if(i>0){
      for(let k=open.length-1;k>=0;k--)push('</'+nameOf(open[k])+'>');
      lines.push([]);
      for(let k=0;k<open.length;k++)push(open[k]);
     }
     if(parts[i])push(parts[i]);
    }
   }
  }
  let R=lines.map(a=>a.join(''));
  if(R.length>1&&R[R.length-1]==='')R.pop();
  pv.style.setProperty('--lnw',Math.max(2,String(R.length).length)+'ch');
  return R.map((h,i)=>'<div class="cl"><span class="ln">'+(i+1)+'</span><span class="lc">'+(h||' ')+'</span></div>').join('');
 }
 let pvRaw='',pvLang='generic',pvPath='';
 const ov=document.getElementById('ov'),dr=document.getElementById('dr'),pv=document.getElementById('pv');
 const drfn=document.getElementById('drfn'),drsub=document.getElementById('drsub');
 const ps=document.getElementById('ps'),pCnt=document.getElementById('pCnt');
 let pCi=true,pRex=false,hits=[],hidx=-1;
 function renderPreview(){
  const Q=ps.value;
  if(!Q){pv.innerHTML=numberize(hl(pvRaw,pvLang));pCnt.textContent='';hits=[];hidx=-1;return;}
  let rx;
  try{rx=new RegExp(pRex?Q:Q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),'g'+(pCi?'i':''));}
  catch(e){pCnt.textContent='regex?';return;}
  let out='',last=0,m,c=0;
  while((m=rx.exec(pvRaw))){
   if(m.index===rx.lastIndex)rx.lastIndex++;
   out+=esc(pvRaw.slice(last,m.index))+'<mark data-i="'+c+'">'+esc(m[0])+'</mark>';
   last=m.index+m[0].length;c++;
   if(c>5000)break;
  }
  out+=esc(pvRaw.slice(last));pv.innerHTML=numberize(out);
  hits=[...pv.querySelectorAll('mark')];hidx=hits.length?0:-1;markActive();
  pCnt.textContent=hits.length?'1/'+hits.length:'0';
 }
 function markActive(){hits.forEach(h=>h.classList.remove('active'));
  if(hidx>=0&&hits[hidx]){hits[hidx].classList.add('active');hits[hidx].scrollIntoView({block:'center',inline:'nearest'});pCnt.textContent=(hidx+1)+'/'+hits.length;}}
 function step(d){if(!hits.length)return;hidx=(hidx+d+hits.length)%hits.length;markActive();}
 function openPreview(idx){
  selIdx=idx; renderedStart=-1;renderedEnd=-1; renderWindow(true);
  const path=filtered[idx][4];
  pvPath=path;drfn.textContent=path;ps.value='';
  const e=EMBED[path];
  if(e&&e.c!==undefined){pvRaw=e.c;pvLang=langOf(path);
   drsub.textContent=(e.trunc?'[truncated] ':'')+pvRaw.length+' chars · '+pvLang;}
  else{pvRaw='// preview unavailable: '+(e?({binary:'binary file',missing:'file not found',budget:'beyond embedding budget'}[e.skip]||e.skip):'not embedded')+'\n// path: '+path;pvLang='generic';drsub.textContent='';}
  renderPreview();ov.style.display='block';dr.classList.add('open');
 }
 function closePreview(){dr.classList.remove('open');ov.style.display='none';
  selIdx=-1;renderedStart=-1;renderedEnd=-1;renderWindow(true);}
 tb.addEventListener('click',e=>{const tr=e.target.closest('tr[data-i]');if(!tr)return;
  openPreview(parseInt(tr.dataset.i,10));});
 tb.addEventListener('dblclick',e=>{const tr=e.target.closest('tr[data-i]');if(!tr)return;
  copy(filtered[parseInt(tr.dataset.i,10)][4]);});
 ov.addEventListener('click',closePreview);
 document.getElementById('drx').addEventListener('click',closePreview);
 document.addEventListener('keydown',e=>{if(e.key==='Escape')closePreview();});
 ps.addEventListener('input',renderPreview);
 ps.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();step(e.shiftKey?-1:1);}});
 document.getElementById('pNext').addEventListener('click',()=>step(1));
 document.getElementById('pPrev').addEventListener('click',()=>step(-1));
 document.getElementById('pRe').addEventListener('click',function(){pRex=!pRex;this.classList.toggle('on',pRex);renderPreview();});
 document.getElementById('pCi').addEventListener('click',function(){pCi=!pCi;this.classList.toggle('on',pCi);renderPreview();});
 document.getElementById('pCopy').addEventListener('click',()=>copy(pvPath));
 // word-wrap toggle (off by default -> code shown at full width, horizontally scrollable)
 const pWrap=document.getElementById('pWrap');let pvWrapped=false;
 pWrap.addEventListener('click',()=>{pvWrapped=!pvWrapped;pv.classList.toggle('wrap',pvWrapped);pWrap.classList.toggle('on',pvWrapped);});
 // drag the left edge to resize the drawer; double-click toggles full width
 (function(){const dgrip=document.getElementById('dgrip');let sx=0,sw=0,drW=0;
  const clamp=w=>Math.max(340,Math.min(Math.round(window.innerWidth*0.98),w));
  const move=e=>{drW=clamp(sw+(sx-e.clientX));dr.style.width=drW+'px';};
  const up=()=>{document.removeEventListener('mousemove',move);document.removeEventListener('mouseup',up);document.body.classList.remove('resizing');dgrip.classList.remove('drag');};
  dgrip.addEventListener('mousedown',e=>{sx=e.clientX;sw=dr.getBoundingClientRect().width;dgrip.classList.add('drag');
   document.addEventListener('mousemove',move);document.addEventListener('mouseup',up);document.body.classList.add('resizing');e.preventDefault();});
  dgrip.addEventListener('dblclick',()=>{const full=Math.round(window.innerWidth*0.98);
   drW=(dr.getBoundingClientRect().width>=full-2)?clamp(Math.round(Math.min(960,window.innerWidth*0.96))):full;dr.style.width=drW+'px';});
 })();
 function copy(t){if(!t)return;
  try{navigator.clipboard.writeText(t).then(()=>toast('path copied'),()=>fallbackCopy(t));}
  catch(e){fallbackCopy(t);}}
 function fallbackCopy(t){const ta=document.createElement('textarea');ta.value=t;document.body.appendChild(ta);ta.select();
  try{document.execCommand('copy');toast('path copied');}catch(e){toast('copy failed');}document.body.removeChild(ta);}
 const tEl=document.getElementById('toast');let tT;
 function toast(msg){tEl.textContent=msg;tEl.classList.add('show');clearTimeout(tT);tT=setTimeout(()=>tEl.classList.remove('show'),1600);}
</script>
</body></html>'''
    # single-pass substitution: a value that itself contains "@@TOKEN@@" (e.g. a
    # finding path/match) is inserted verbatim and never re-scanned (no cascade).
    import re as _re
    _SUB={"@@APK@@":esc(apk),"@@META@@":meta_html,"@@BASELINE@@":esc(baseline),
          "@@SEVCHK@@":sev_chk,"@@TYPCHK@@":typ_chk,"@@CATCHK@@":cat_chk,"@@SPECTRUM@@":spectrum,
          "@@ROWSJSON@@":rows_json,"@@EMBED@@":embed_json}
    doc=_re.sub(r"@@[A-Z]+@@",lambda m:_SUB.get(m.group(0),m.group(0)),TEMPLATE)
    with open(p,"w",encoding="utf-8") as fh: fh.write(doc)
    print("HTML :",p)

print("\nSummary by severity:")
for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
    if counts.get(s): print(f"  {s:9s} {counts[s]}")
PYEOF

ok "Reports ready in: $OUTDIR"

# =============================================================================
#  EXIT CODE (for CI) — fail on FINDING >= threshold
# =============================================================================
EXIT=0
if [[ "$FAILON" != "none" ]]; then
  FR="$(sev_rank "$(upper "$FAILON")")"
  while IFS=$'\t' read -r sev cat typ _rest; do
    [[ "$typ" == "FINDING" ]] || continue
    r="$(sev_rank "$sev")"
    if [[ "$r" -le "$FR" ]]; then EXIT=2; break; fi
  done < "$FINDINGS"
  [[ "$EXIT" -eq 2 ]] && warn "fail-on=$FAILON: at least one FINDING >= threshold -> exit 2"
fi

# cleanup
if [[ -z "$SKIP_DECOMPILE" && "$KEEP" -eq 0 ]]; then
  rm -rf "$WORKDIR"
else
  [[ "$KEEP" -eq 1 ]] && log "Work directory kept: $WORKDIR"
fi

exit "$EXIT"
