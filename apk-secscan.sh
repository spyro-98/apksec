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
SEMGREP=0; SEMGREP_RULES=""

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
  -f, --format  csv|json|xml|html|sarif|all   Report format(s) (default: all)
  -o, --output  <dir>          Output directory (default: ./secscan-<apk>-<ts>)
  -p, --app-package <pkg>      Force the app package (override autodetect)
      --native                 Also scan native libs (.so) with strings + AES S-box search
      --cve                    Check known library CVEs via OSV.dev (network)
      --cve-max <n>            Max libraries to query on OSV (default 400)
      --cve-mock <file>        Use a saved OSV dump instead of the network (offline/CI)
      --semgrep <rules-dir>    Also run semgrep with the given ruleset on the decompiled sources
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
    --semgrep)        SEMGREP_RULES="${2:-}"; SEMGREP=1; shift 2;;
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
[[ "$FORMAT" =~ ^(csv|json|xml|html|sarif|all)$ ]]     || die "invalid format: $FORMAT"
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
  dep semgrep   "optional" "--semgrep <rules-dir>: runs a semgrep ruleset over the decompiled sources" \
      "pip install semgrep  (or: brew install semgrep)" "pip install semgrep" "pip install semgrep"

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
scan HIGH "Network" REVIEW "HttpsURLConnection.setDefaultHostnameVerifier(...) call site (verify it isn't permissive)" \
  'setDefaultHostnameVerifier\('
scan HIGH "Exec" REVIEW "Shell command execution (Runtime.exec / ProcessBuilder)" \
  'Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder'
scan HIGH "DynamicCode" REVIEW "Dynamic code loading (DexClassLoader)" \
  'DexClassLoader|PathClassLoader|InMemoryDexClassLoader|BaseDexClassLoader'
scan HIGH "WebView" FINDING "addJavascriptInterface (JS->native bridge)" 'addJavascriptInterface'
scan HIGH "WebView" REVIEW  "WebView with JavaScript enabled" 'setJavaScriptEnabled\(\s*true\s*\)'
scan HIGH "WebView" FINDING "WebView universal access from file:// URLs" \
  'setAllowUniversalAccessFromFileURLs\(\s*true\s*\)|setAllowFileAccessFromFileURLs\(\s*true\s*\)'
scan HIGH "WebView" REVIEW "WebView overrides onReceivedSslError (verify it doesn't blindly accept invalid certs)" \
  'onReceivedSslError\s*\('
scan HIGH "WebView" FINDING "WebView allows mixed content (HTTP inside HTTPS pages)" \
  'setMixedContentMode\(\s*(?:WebSettings\.)?MIXED_CONTENT_ALWAYS_ALLOW\s*\)'
scan MEDIUM "WebView" REVIEW "Dynamic JS execution via loadUrl(\"javascript:...\") — verify the input isn't attacker-influenced" \
  'loadUrl\(\s*"javascript:'
scan HIGH "Storage" FINDING "Files with WORLD_READABLE/WRITEABLE permissions" \
  'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE'
scan HIGH "Assets" FINDING "FileProvider <root-path> declared — exposes the entire device filesystem" \
  '<root-path\b'
scan MEDIUM "Assets" REVIEW "FileProvider path=\".\" grants access to an entire directory (verify scope)" \
  '<(?:files-path|external-path|external-files-path|cache-path|external-cache-path)\s+[^>]*path="\."'

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
scan MEDIUM "Crypto" REVIEW "Deprecated/weak SSL-TLS protocol requested explicitly" \
  'SSLContext\.getInstance\(\s*"(?:SSL|SSLv2|SSLv3|TLSv1|TLSv1\.1)"\s*\)'
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
  "$GREP" -qP 'android:networkSecurityConfig=' "$MANIFEST" 2>/dev/null \
    || note INFO "Hardening" REVIEW "No explicit android:networkSecurityConfig referenced (relying on platform TLS defaults)" "$MANIFEST"
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
pattern_present 'setFilterTouchesWhenObscured\(\s*true\s*\)|android:filterTouchesWhenObscured="true"' \
  || note LOW  "Hardening" REVIEW "Tapjacking mitigation absent (filterTouchesWhenObscured)" "(global analysis)"

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

    log "Native scan: searching .so files for a custom AES S-box (embedded/custom crypto)..."
    export SS_NLIST="$NLIST" SS_FINDINGS="$FINDINGS" SS_WORKDIR="$WORKDIR"
    python3 - <<'PYSBOX'
import os
NLIST=os.environ["SS_NLIST"]; FIN=os.environ["SS_FINDINGS"]; WORK=os.environ.get("SS_WORKDIR","")
# the Rijndael (AES) forward S-box: a fixed 256-byte lookup table. Any .so that
# embeds it verbatim is doing its own AES implementation rather than calling
# the platform's crypto APIs — not necessarily wrong, but worth a second look
# (custom/vendored crypto is a common way to hide weak or backdoored crypto).
SBOX=bytes([
 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16])
def emit(sev,title,filef,match):
    if WORK and filef.startswith(WORK+os.sep): filef=filef[len(WORK)+1:]
    match=(match or "")[:240]
    with open(FIN,"a",encoding="utf-8") as fh:
        fh.write("\t".join([sev,"Crypto","REVIEW",title,filef,"-",match])+"\n")
n=0
with open(NLIST,"rb") as lf:
    files=lf.read().split(b"\x00")
for fb in files:
    if not fb or not fb.endswith(b".so"): continue
    f=fb.decode("utf-8","replace")
    try:
        with open(f,"rb") as fh: data=fh.read()
    except Exception:
        continue
    if SBOX in data:
        emit("MEDIUM","Custom/embedded AES S-box found in native library (verify it isn't a weakened or backdoored implementation)",f,"AES Rijndael S-box constant")
        n+=1
print(f"Native: {n} .so files contain an embedded AES S-box.")
PYSBOX
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

def emit_status(msg):
    # Always leaves a trace of what the CVE phase actually did: a report with
    # --cve enabled must never look identical whether 0 vulns were found or
    # the phase silently failed/skipped.
    with open(FIN,"a",encoding="utf-8") as fh:
        fh.write("\t".join(["INFO","Dependency","INFO","CVE check: "+msg,"(analysis)","-",""])+"\n")

if not coords:
    print("CVE: no versioned library detected (META-INF/*.version or pom.properties absent).", file=sys.stderr)
    emit_status("no versioned libraries detected in META-INF (nothing to check)")
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
        print(f"CVE: cannot reach OSV.dev ({e}). CVE phase skipped.", file=sys.stderr)
        emit_status(f"skipped — cannot reach OSV.dev ({e})")
        sys.exit(0)
    except Exception as e:
        print(f"CVE: OSV error ({e}). CVE phase skipped.", file=sys.stderr)
        emit_status(f"skipped — OSV error ({e})")
        sys.exit(0)

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
emit_status(f"{len(items)} libraries checked on OSV.dev, {len(hits)} vulnerable, {ncve} CVE(s) listed below"
            if ncve else f"{len(items)} libraries checked on OSV.dev — no known vulnerabilities found")
PYCVE
else
  note INFO "Dependency" INFO "CVE check: not run (pass --cve to check dependencies against OSV.dev)"
fi

# =============================================================================
#  SEMGREP — opt-in with --semgrep <rules-dir>, runs over the decompiled sources
# =============================================================================
SEMGREP_BIN="$(command -v semgrep || true)"
if [[ "$SEMGREP" -eq 1 ]]; then
  if [[ -z "$SEMGREP_BIN" ]]; then
    warn "--semgrep requested but semgrep is not installed: skipping (pip install semgrep)"
    note INFO "Semgrep" INFO "Semgrep check: skipped — semgrep not installed (pip install semgrep)"
  elif [[ ! -e "$SEMGREP_RULES" ]]; then
    warn "--semgrep rules path not found: $SEMGREP_RULES"
    note INFO "Semgrep" INFO "Semgrep check: skipped — rules path not found: $SEMGREP_RULES"
  else
    log "Semgrep: running with rules from $SEMGREP_RULES ..."
    SEMGREP_OUT="$WORKDIR/.semgrep.json"
    "$SEMGREP_BIN" --config "$SEMGREP_RULES" --json --quiet "$SRC" >"$SEMGREP_OUT" 2>"$WORKDIR/semgrep.err"
    export SS_SEMGREP_OUT="$SEMGREP_OUT" SS_SEMGREP_RULES="$SEMGREP_RULES" SS_FINDINGS="$FINDINGS" SS_WORKDIR="$WORKDIR"
    python3 - <<'PYSEMGREP'
import os, json, sys
out=os.environ.get("SS_SEMGREP_OUT",""); fin=os.environ["SS_FINDINGS"]
work=os.environ.get("SS_WORKDIR",""); rules=os.environ.get("SS_SEMGREP_RULES","")

def emit(sev,title,filef,line,match):
    match=(match or "").replace("\t"," ").replace("\r"," ").replace("\n"," ")[:240]
    with open(fin,"a",encoding="utf-8") as fh:
        fh.write("\t".join([sev,"Semgrep","REVIEW",title,filef,str(line),match])+"\n")

def status(msg):
    with open(fin,"a",encoding="utf-8") as fh:
        fh.write("\t".join(["INFO","Semgrep","INFO","Semgrep check: "+msg,"(analysis)","-",""])+"\n")

SEVMAP={"ERROR":"HIGH","WARNING":"MEDIUM","INFO":"LOW"}
n=0
try:
    data=json.load(open(out,encoding="utf-8"))
    for r in data.get("results",[]):
        extra=r.get("extra",{}) or {}
        sev=SEVMAP.get((extra.get("severity") or "").upper(),"MEDIUM")
        path=r.get("path","")
        rel=os.path.relpath(path,work) if work and os.path.isabs(path) else path
        line=(r.get("start",{}) or {}).get("line","-")
        msg=(extra.get("message") or r.get("check_id") or "semgrep finding").strip().replace("\n"," ")
        emit(sev,f"[{r.get('check_id','semgrep')}] {msg[:160]}",rel,line,extra.get("lines","") or "")
        n+=1
    status(f"{n} finding(s) from rules at {rules}" if n else f"0 findings — rules at {rules} ran cleanly")
except Exception as e:
    status(f"failed to parse semgrep output ({e})")
PYSEMGREP
  fi
else
  note INFO "Semgrep" INFO "Semgrep check: not run (pass --semgrep <rules-dir>)"
fi

# =============================================================================
#  ASSETS / ANOMALIES — files non-standard vs the Android baseline
# =============================================================================
log "Analyzing assets and baseline discrepancies..."
export SS_RES="$RES" SS_FINDINGS="$FINDINGS" SS_APK_PATH="${APK:-}"
python3 - <<'PYASSET'
import os, sys, posixpath, re
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

asset_paths=[]; names=[]
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

# ---- packer/protector fingerprints (known filenames, no extraction needed) ----
PACKER_SIGS=[
    (re.compile(r'libshella-',re.I), "Tencent Legu"),
    (re.compile(r'libjiagu',re.I), "Qihoo 360 Jiagu"),
    (re.compile(r'libsecexe|libsecmain',re.I), "Bangcle/SecShell"),
    (re.compile(r'libSecShell',re.I), "SecShell"),
    (re.compile(r'secdata\d*\.jar',re.I), "SecShell (asset)"),
    (re.compile(r'jiagu_data\.bin',re.I), "Qihoo 360 Jiagu (asset)"),
    (re.compile(r'0OO00l111l1l',re.I), "Tencent Legu (asset)"),
    (re.compile(r'libAPKProtect',re.I), "APKProtect"),
    (re.compile(r'libnqshield',re.I), "NQ Shield"),
]
pn=0
for nm in names:
    base=nm.rsplit("/",1)[-1]
    for rx,vendor in PACKER_SIGS:
        if rx.search(base):
            emit("HIGH","Packer","FINDING",f"Packer/protector detected: {vendor} ({base})",nm,"known packer/protector filename signature")
            pn+=1
            break
print(f"Packer: {pn} known packer/protector filename signatures matched.", file=sys.stderr)
emit("INFO","Packer","INFO",
     f"Packer/protector check: {pn} known signature(s) matched" if pn else "Packer/protector check: no known packer/protector signatures found",
     "(analysis)")
PYASSET

# =============================================================================
#  MANIFEST XML ANALYSIS — exported components without a permission
#  (needs a real parser: jadx pretty-prints the manifest across many lines, so
#  correlating "exported" with a sibling "permission" attribute on the same
#  <provider>/<receiver>/<service> element isn't reliable with line-based grep.)
# =============================================================================
export SS_MANIFEST="$MANIFEST" SS_FINDINGS="$FINDINGS"
python3 - <<'PYMANIFEST'
import os, sys
import xml.etree.ElementTree as ET

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
MANIFEST = os.environ.get("SS_MANIFEST", ""); FIN = os.environ["SS_FINDINGS"]

def emit(sev, cat, typ, title, filef, match=""):
    match = (match or "").replace("\t", " ").replace("\r", " ").replace("\n", " ")[:240]
    with open(FIN, "a", encoding="utf-8") as fh:
        fh.write("\t".join([sev, cat, typ, title, filef, "-", match]) + "\n")

if MANIFEST and os.path.isfile(MANIFEST):
    try:
        app = ET.parse(MANIFEST).getroot().find("application")
        n = 0
        if app is not None:
            for tag in ("provider", "receiver", "service"):
                for el in app.findall(tag):
                    name = el.get(ANDROID_NS + "name", "?")
                    exported = el.get(ANDROID_NS + "exported")
                    has_intent_filter = el.find("intent-filter") is not None
                    has_perm = any(el.get(ANDROID_NS + p) for p in ("permission", "readPermission", "writePermission"))
                    # exported="true", or no explicit attribute with an intent-filter present
                    # (the pre-API-31 implicit-export default) — either way, no permission set.
                    is_exported = (exported == "true") or (exported is None and has_intent_filter)
                    if is_exported and not has_perm:
                        emit("MEDIUM", "IPC", "REVIEW", f"Exported {tag} without a permission: {name}", MANIFEST, name)
                        n += 1
        print(f"Manifest: {n} exported provider/receiver/service without a permission.", file=sys.stderr)
    except Exception as e:
        print(f"Manifest: parse failed ({e})", file=sys.stderr)
PYMANIFEST

# =============================================================================
#  TAINT-LITE — source/sink co-occurrence within the same method (heuristic).
#  NOT real data-flow analysis: no proof the tainted value actually reaches the
#  sink, just that both a "source" and a "sink" pattern appear in one method
#  body. Always REVIEW, never FINDING — a hint of where to look by hand.
# =============================================================================
log "Taint-lite: looking for source/sink co-occurrence within methods..."
TAINT_RX='getIntent\(\)\s*\.\s*get\w*Extra|\.getQueryParameter\(|@JavascriptInterface|\.loadUrl\(|\.(?:rawQuery|execSQL)\(|Runtime\.getRuntime\(\)\.exec\(|new\s+ProcessBuilder\('
TAINTLIST="$WORKDIR/.taintcandidates"; : > "$TAINTLIST"
if [[ -s "$FILELIST" ]]; then
  if [[ "$ENGINE" == rg ]]; then
    xargs -0 rg -l -P -e "$TAINT_RX" <"$FILELIST" 2>/dev/null | tr '\n' '\0' >>"$TAINTLIST"
  else
    xargs -0 "$GREP" -lIP -e "$TAINT_RX" <"$FILELIST" 2>/dev/null | tr '\n' '\0' >>"$TAINTLIST"
  fi
fi
TN=$(tr -cd '\0' <"$TAINTLIST" | wc -c); log "Taint-lite: $TN candidate files to inspect"
export SS_TAINTLIST="$TAINTLIST" SS_FINDINGS="$FINDINGS" SS_WORKDIR="$WORKDIR"
python3 - <<'PYTAINT'
import os, re
LIST=os.environ["SS_TAINTLIST"]; FIN=os.environ["SS_FINDINGS"]; WORK=os.environ.get("SS_WORKDIR","")

SOURCES=[("IntentExtra",re.compile(r'getIntent\(\)\s*\.\s*get\w*Extra\b')),
         ("URIQueryParam",re.compile(r'\.getQueryParameter\(')),
         ("JSBridge",re.compile(r'@JavascriptInterface'))]
SINKS=[("WebViewLoadUrl",re.compile(r'\.loadUrl\(')),
       ("SQLRaw",re.compile(r'\.(?:rawQuery|execSQL)\(')),
       ("ShellExec",re.compile(r'Runtime\.getRuntime\(\)\.exec\(|new\s+ProcessBuilder\('))]
METH_RE=re.compile(r'(?:public|private|protected|static|final|synchronized|\s)+[\w<>\[\],.?]+\s+(\w+)\s*\([^;{}]*\)\s*(?:throws\s+[\w,.\s]+)?\{')

def method_bodies(text):
    for m in METH_RE.finditer(text):
        start=m.end()-1; depth=0; end=start
        for i in range(start,min(len(text),start+20000)):
            c=text[i]
            if c=='{': depth+=1
            elif c=='}':
                depth-=1
                if depth==0: end=i; break
        yield m.group(1), text[start:end+1]

def emit(title,filef,line,match):
    if WORK and filef.startswith(WORK+os.sep): filef=filef[len(WORK)+1:]
    match=(match or "").replace("\t"," ").replace("\r"," ").replace("\n"," ")[:240]
    with open(FIN,"a",encoding="utf-8") as fh:
        fh.write("\t".join(["MEDIUM","Taint","REVIEW",title,filef,str(line),match])+"\n")

n=0
with open(LIST,"rb") as lf:
    files=[f.decode("utf-8","replace") for f in lf.read().split(b"\x00") if f]
for f in files:
    try:
        text=open(f,encoding="utf-8",errors="replace").read()
    except Exception:
        continue
    for mname,body in method_bodies(text):
        src_hit=next((name for name,rx in SOURCES if rx.search(body)),None)
        sink_hit=next((name for name,rx in SINKS if rx.search(body)),None)
        if src_hit and sink_hit:
            line=text.count("\n",0,text.find(body))+1
            emit(f"Possible {src_hit} -> {sink_hit} in method {mname}() (heuristic — same method only, not real data-flow; verify manually)",
                 f,line,f"{src_hit} + {sink_hit} in {mname}()")
            n+=1
print(f"Taint-lite: {n} possible source/sink co-occurrence(s) flagged.")
with open(FIN,"a",encoding="utf-8") as fh:
    msg=f"{n} possible source/sink co-occurrence(s) found in {len(files)} candidate file(s)" if n else f"no source/sink co-occurrence found in {len(files)} candidate file(s)"
    fh.write("\t".join(["INFO","Taint","INFO","Taint-lite check: "+msg,"(analysis)","-",""])+"\n")
PYTAINT

# =============================================================================
#  REPORT GENERATION (python: correct escaping)
# =============================================================================
log "Generating reports in $OUTDIR ..."
export SS_FINDINGS="$FINDINGS" SS_OUTDIR="$OUTDIR" SS_FORMAT="$FORMAT"
export SS_APK="$APK_NAME" SS_SCOPE="$SCOPE" SS_PKG="$APP_PKG" SS_TS="$TS" SS_NFILES="$NFILES"
export SS_WORKDIR="$WORKDIR" SS_APK_PATH="${APK:-}" SS_BASELINE="$REF_BASELINE"

python3 - <<'PYEOF'
import os, csv, json, html, datetime, re
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

# ---- OWASP MASVS v2 tagging (interoperability, not new detection logic) ----
# Category-level mapping is an approximation, not per-control precision; the
# two overrides below correct the clearest mismatches within "Hardening".
MASVS_CAT={"Secrets":"MASVS-STORAGE","Network":"MASVS-NETWORK","WebView":"MASVS-PLATFORM",
    "Manifest":"MASVS-PLATFORM","Crypto":"MASVS-CRYPTO","Storage":"MASVS-STORAGE",
    "Logging":"MASVS-PRIVACY","IPC":"MASVS-PLATFORM","SQL":"MASVS-CODE","Exec":"MASVS-CODE",
    "DynamicCode":"MASVS-CODE","Assets":"MASVS-CODE","Anomaly":"MASVS-CODE","Signing":"MASVS-CODE",
    "Dependency":"MASVS-CODE","Hardening":"MASVS-RESILIENCE","Env":"MASVS-CODE",
    "Identifiers":"MASVS-PRIVACY","Endpoints":"MASVS-NETWORK","Quality":"MASVS-CODE",
    "Packer":"MASVS-RESILIENCE","Semgrep":"MASVS-CODE","Taint":"MASVS-CODE"}
MASVS_TITLE_OVERRIDE=[("FLAG_SECURE absent","MASVS-PRIVACY"),("AndroidKeyStore not used","MASVS-CRYPTO")]
def masvs_tag(cat,title):
    for needle,tag in MASVS_TITLE_OVERRIDE:
        if needle in title: return tag
    return MASVS_CAT.get(cat)
for r in rows:
    tag=masvs_tag(r["category"],r["title"])
    if tag: r["title"]=r["title"]+f" [{tag}]"

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

if want("sarif"):
    p=base+".sarif"
    LEVEL={"CRITICAL":"error","HIGH":"error","MEDIUM":"warning","LOW":"note","INFO":"note"}
    def rule_id(cat): return re.sub(r"[^a-z0-9]+","-",cat.lower()).strip("-") or "finding"
    rule_ids=sorted({rule_id(r["category"]) for r in rows})
    sarif={
        "$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version":"2.1.0",
        "runs":[{
            "tool":{"driver":{
                "name":"apk-secscan",
                "informationUri":"https://github.com/",
                "rules":[{"id":rid,"name":rid} for rid in rule_ids],
            }},
            "results":[{
                "ruleId":rule_id(r["category"]),
                "level":LEVEL.get(r["severity"],"warning"),
                "message":{"text":r["title"]+((" — "+r["match"]) if r["match"] else "")},
                "locations":[{"physicalLocation":{
                    "artifactLocation":{"uri":r["file"].replace("\\","/")},
                    **({"region":{"startLine":int(r["line"])}} if r["line"].isdigit() else {}),
                }}],
            } for r in rows],
        }],
    }
    with open(p,"w",encoding="utf-8") as fh:
        json.dump(sarif,fh,ensure_ascii=False,indent=2)
    print("SARIF:",p)

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

    # ---------- severity palette: "Imperial Archive" (verified WCAG AA + CIEDE2000-distinct) ----------
    SEV_ORDER=["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    SEVC={"CRITICAL":"#E05A4E","HIGH":"#E08C42","MEDIUM":"#E3D2A0","LOW":"#7FA6CC","INFO":"#A29C93"}
    def esc(s): return html.escape(str(s))

    # severity tallies double as the filter toggles (count IS the control); a
    # hollow ring carries the color, never a filled pill/background.
    sev_chk="".join(
        '<label class="sv'+(' zero' if not counts.get(s,0) else '')+'" data-sev="'+s+'" style="--c:'+SEVC[s]+'">'
        '<input type="checkbox" class="fsev" value="'+s+'" checked>'
        '<span class="lft"><i class="ring"></i><span class="n">'+str(counts.get(s,0))+'</span></span>'
        '<span class="k">'+s+'</span></label>'
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

    pkg_esc=esc(pkg or "n/a"); scope_esc=esc(scope); nfiles_esc=esc(str(nfiles)); generated_esc=esc(meta["generated"])

    # The CVE phase always leaves exactly one "CVE check: ..." status row (see
    # PYCVE/the --cve-not-run note), but on a 10k-row report sorted by
    # severity it's an INFO row buried at the very end — easy to miss. Surface
    # it as its own always-visible sidebar line instead of making people
    # scroll/filter to confirm the phase even ran.
    cve_status=next((r["title"] for r in rows if r["category"]=="Dependency" and r["title"].startswith("CVE check:")), "")
    cve_status_esc=esc(cve_status[len("CVE check: "):] if cve_status else "not run (pass --cve)")

    TEMPLATE=r'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SECSCAN // @@APK@@</title>
<style>
 :root{
  --bg:#070A12;--bg2:#0E121C;--sbg:#0A0E17;--panel:#141926;
  --line:#242A3A;--lineS:#626A7D;
  --gold:#C9A54D;--blue:#8098BC;--vault:#5AA99C;--vaultd:#02110e;
  --tx:#E8E6DF;--tx2:#AEB2BD;--mut:#828896;
  --crit:#E05A4E;--high:#E08C42;--med:#E3D2A0;--low:#7FA6CC;--info:#A29C93;
  --serif:'Iowan Old Style','Palatino Linotype',Palatino,'Book Antiqua',Georgia,'Times New Roman',serif;
  --sans:-apple-system,BlinkMacSystemFont,'Segoe UI Variable Text','Segoe UI','Helvetica Neue',Helvetica,Arial,sans-serif;
  --mono:ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'Liberation Mono','DejaVu Sans Mono',monospace;
  --sbw:284px;
 }
 *{box-sizing:border-box}
 html,body{margin:0;height:100%}
 body{height:100vh;overflow:hidden;background:var(--bg);color:var(--tx);
  font-family:var(--sans);font-size:14px;line-height:1.5;
  -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
 b{font-weight:600}
 ::selection{background:var(--gold);color:#1a1305}
 .app{display:flex;height:100vh}
 /* always-on instrument-panel marker — passive/ambient, no interaction needed.
    A calibrated tick-rule (fine ticks every 12px, a long tick every 60px),
    not a HUD corner bracket: this is a measuring instrument, not a game overlay.
    Neutral-into-gold rather than pure gold: gold stays mostly reserved for
    active/focused states (the drawer's own corner cut lights up solid gold). */
 .app::before,.app::after{content:"";position:fixed;left:0;width:9px;height:132px;pointer-events:none;z-index:50;
  background:
    repeating-linear-gradient(to bottom,rgba(201,165,77,.55) 0 1px,transparent 1px 12px) left/5px 100% no-repeat,
    repeating-linear-gradient(to bottom,rgba(201,165,77,.55) 0 1px,transparent 1px 60px) left/9px 100% no-repeat}
 .app::before{top:22px}
 .app::after{bottom:22px}

 /* ---------- sidebar: every control lives here, narrow and scrollable ---------- */
 .sidebar{position:relative;flex:0 0 var(--sbw);width:var(--sbw);height:100%;display:flex;flex-direction:column;
  background:var(--sbg);border-right:1px solid var(--lineS)}
 /* resize handles: a taut tether line with a diamond anchor node at each end —
    not a plain hairline. The line lives on the element's own background so
    both ::before/::after are free for the two anchors. */
 .sbgrip{position:absolute;top:0;right:-4px;width:9px;height:100%;cursor:col-resize;z-index:10;
  background:linear-gradient(var(--lineS),var(--lineS)) no-repeat right 4px center/1px 100%}
 .sbgrip::before,.sbgrip::after{content:"";position:absolute;right:2px;width:5px;height:5px;
  background:var(--lineS);transform:rotate(45deg);transition:background .15s}
 .sbgrip::before{top:6px} .sbgrip::after{bottom:6px}
 .sbgrip:hover,.sbgrip.drag{background:linear-gradient(var(--gold),var(--gold)) no-repeat right 3px center/2px 100%}
 .sbgrip:hover::before,.sbgrip.drag::before,.sbgrip:hover::after,.sbgrip.drag::after{background:var(--gold)}
 .sb-brand{position:relative;overflow:hidden;flex:0 0 auto;padding:20px 20px 16px;border-bottom:1px solid var(--line)}
 /* the tool's own emblem: a wireframe cuboctahedron (12 vertices/24 edges, a
    three-face projection so a square and two triangles read at once) — never
    a sphere or ring, which read as generic sci-fi rather than anything
    specific. Reused twice: large and faint as an ambient corner mark, small
    and crisp as the actual logo glyph next to the wordmark. No fill, no glow,
    no animation. */
 .radiant{pointer-events:none;fill:none;stroke:var(--gold);stroke-linecap:square;vector-effect:non-scaling-stroke}
 .radiant.wm{position:absolute;top:-10px;right:-14px;width:104px;height:104px;
  transform:rotate(-7deg);stroke-width:.75;stroke-opacity:.22}
 .radiant.mark{width:18px;height:18px;stroke-width:1.4;stroke-opacity:.85;flex:0 0 auto}
 .radiant.tiny{width:16px;height:16px;stroke-width:1.2;stroke-opacity:.55;margin:0 auto 12px;display:block}
 .wordmark{display:inline-flex;align-items:center;gap:7px;font-family:var(--serif);font-size:19px;letter-spacing:.01em;color:var(--tx)}
 .wordmark .dim{color:var(--mut);font-family:var(--sans)}
 .tagline{margin-top:5px;font-size:12px;text-transform:uppercase;letter-spacing:.14em;color:var(--gold)}
 .sb-scroll{flex:1 1 auto;min-height:0;overflow-y:auto;padding:18px 20px 24px;
  display:flex;flex-direction:column;gap:22px}
 /* a brass-on-marble bevel instead of a flat rule: a bright hairline, a solid
    gold seam, a dark cast shadow — a physical edge, not a line drawn on top */
 .sb-lbl{display:block;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.14em;
  color:var(--gold);margin-bottom:10px;padding-bottom:10px;border-bottom:0;
  background-image:linear-gradient(to bottom,rgba(232,230,223,.10) 0 1px,var(--gold) 1px 2px,rgba(0,0,0,.55) 2px 3px);
  background-repeat:no-repeat;background-position:bottom left;background-size:100% 3px}

 .sb-title h1{font-family:var(--serif);font-size:18px;font-weight:600;margin:0 0 12px;color:var(--tx);
  word-break:break-word;line-height:1.3}
 .sb-meta{display:flex;flex-direction:column;gap:4px}
 .mrow{display:flex;justify-content:space-between;gap:10px;font-size:12px}
 .mrow .mk{color:var(--mut);text-transform:uppercase;letter-spacing:.06em;font-size:12px;flex:0 0 auto}
 .mrow .mv{color:var(--tx2);text-align:right;word-break:break-word}
 .sb-baseline{margin-top:12px;font-size:12px;line-height:1.5;color:var(--tx2);
  padding:8px 10px;border:1px solid var(--line);border-radius:3px}
 .sb-baseline .tag{display:inline-block;color:var(--gold);text-transform:uppercase;letter-spacing:.12em;
  font-size:12px;margin-right:6px;font-weight:600}
 .sb-baseline .tag.cve{color:var(--vault)} /* a lookup result, not a static scan fact — kept visually distinct */

 /* severity: hollow ring + count keep the hue; the fill never changes */
 .sevrow{display:flex;flex-direction:column;gap:6px}
 .sv{position:relative;display:flex;align-items:center;justify-content:space-between;gap:10px;
  padding:6px 10px;border:1px solid var(--line);border-radius:3px;background:var(--panel);
  cursor:pointer;user-select:none;transition:border-color .15s,opacity .15s}
 .sv .lft{display:flex;align-items:center;gap:8px}
 .sv .ring{width:8px;height:8px;border-radius:50%;border:1.5px solid var(--c);flex:0 0 auto}
 .sv .n{font-weight:700;font-size:14px;line-height:1;color:var(--c)}
 .sv .k{font-size:12px;letter-spacing:.08em;color:var(--tx2);text-transform:uppercase}
 .sv input{position:absolute;opacity:0;pointer-events:none}
 .sv:hover{border-color:var(--c)}
 .sv:has(input:checked){border-color:var(--c)}
 .sv:not(:has(input:checked)){opacity:.4}
 .sv.zero{opacity:.28}
 /* faceted severity gauge: each segment is cut at both ends like a gem facet
    (clip-path, not a gap) with a seam across the middle that only lights up
    on hover/activation — feedback via a precise measurement detail, never a
    glow. Hover previews, click isolates that severity (see JS). */
 .spectrum{display:flex;height:14px;margin-top:2px;background:var(--bg);
  border:1px solid var(--line);overflow:hidden;cursor:pointer}
 .spectrum .sg{position:relative;width:0;background:var(--c);opacity:.55;
  clip-path:polygon(3px 0,100% 0,calc(100% - 3px) 100%,0 100%);
  transition:width .3s ease,opacity .15s}
 .spectrum .sg::after{content:"";position:absolute;left:0;right:0;top:50%;height:1px;
  background:var(--bg);opacity:0;transition:opacity .12s}
 .spectrum .sg.sg-hover{opacity:1}
 .spectrum .sg.sg-hover::after{opacity:.85}
 tbody tr.rowdim td{opacity:.28;transition:opacity .12s}

 /* generic chip (type / category): gold is the only active-state color, fill never changes */
 .grp,.catrow{display:flex;flex-wrap:wrap;gap:8px}
 .ty{position:relative;display:inline-flex;align-items:center;gap:5px;cursor:pointer;user-select:none;
  border:1px solid var(--lineS);border-radius:3px;color:var(--tx2);background:var(--panel);
  padding:5px 10px;font-size:12px;letter-spacing:.06em;text-transform:uppercase;transition:.15s}
 .ty input{display:none}
 .ty:hover{border-color:var(--gold);color:var(--tx)}
 .ty:has(input:checked){border-color:var(--gold);color:var(--gold)}
 .ty:has(input:checked)::after{content:"";position:absolute;left:0;right:0;bottom:-1px;height:2px;background:var(--gold)}
 .ty .ycnt{color:var(--mut);font-size:12px}

 /* category: collapsible by default, so 15+ chips don't dominate a narrow sidebar */
 details.sb-cat{border:none}
 .sb-cat>summary{cursor:pointer;list-style:none;display:flex;align-items:center;
  font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.14em;color:var(--gold);
  margin-bottom:10px;padding-bottom:10px;border-bottom:0;
  background-image:linear-gradient(to bottom,rgba(232,230,223,.10) 0 1px,var(--gold) 1px 2px,rgba(0,0,0,.55) 2px 3px);
  background-repeat:no-repeat;background-position:bottom left;background-size:100% 3px}
 .sb-cat>summary::-webkit-details-marker{display:none}
 .sb-cat>summary::after{content:"▾";color:var(--mut);font-size:12px;letter-spacing:0;
  text-transform:none;margin-left:auto}
 .sb-cat[open]>summary::after{content:"▴"}
 .catsum{color:var(--tx2);letter-spacing:0;text-transform:none;font-weight:400;font-size:12px;margin-left:8px}
 .catactions{display:flex;gap:8px;margin:2px 0 10px}
 .btn.mini{padding:3px 9px;font-size:12px}

 input[type=text],.btn{background:var(--panel);border:1px solid var(--lineS);color:var(--tx);
  padding:7px 11px;font:inherit;font-size:12px;border-radius:3px;outline:none;transition:border-color .15s}
 input[type=text]{width:100%}
 input[type=text]::placeholder{color:var(--mut)}
 input[type=text]:focus{border-color:var(--gold)}
 .btn{cursor:pointer;color:var(--tx2);letter-spacing:.06em;text-transform:uppercase;font-size:12px}
 .btn:hover{border-color:var(--gold);color:var(--gold)}
 .btn.on{border-color:var(--gold);color:var(--gold);background:rgba(201,165,77,.1)}
 .sb-actions{display:flex;gap:8px;margin-top:10px}
 .sb-actions .btn{flex:1 1 0;text-align:center;padding:7px 8px}
 .shown-row{margin-top:10px;font-size:12px;color:var(--tx2)}
 #shown b{color:var(--gold)}

 .lgroup{margin-top:10px}
 .lgroup:first-child{margin-top:0}
 /* a shorter bevel than the primary section labels — a partial seam, not a
    full-width one, marks this as a secondary heading within the section */
 .lgtitle{font-size:12px;text-transform:uppercase;letter-spacing:.1em;color:var(--mut);margin-bottom:8px;
  padding-bottom:6px;background-image:linear-gradient(to bottom,rgba(232,230,223,.08) 0 1px,var(--lineS) 1px 2px);
  background-repeat:no-repeat;background-position:bottom left;background-size:34% 2px}
 .lg{font-size:12px;color:var(--tx2);line-height:1.7}
 .lg b{color:var(--tx);font-weight:600;margin-right:4px}
 .sb-hint{font-size:12px;line-height:1.6;color:var(--mut)}
 .sb-hint b{color:var(--tx2);font-weight:600}

 /* ---------- main: nothing but the table, full width and full height ---------- */
 .main{flex:1 1 auto;min-width:0;height:100%;display:flex;flex-direction:column;background:var(--bg)}
 .tablewrap{flex:1 1 auto;min-height:0;overflow:auto;background:var(--bg)}
 /* tabular-nums + a lighter, wider-tracked header: an engraved ledger reads
    numbers in fixed-width columns and sets headings light-weight/wide-spaced
    rather than bold — bold headers read as "printed", this reads as "cut" */
 table{border-collapse:collapse;table-layout:fixed;font-size:14px;font-family:var(--mono);
  font-variant-numeric:tabular-nums;font-feature-settings:"tnum" 1}
 thead th{position:sticky;top:0;z-index:4;text-align:left;padding:12px 14px;white-space:nowrap;
  background:var(--bg2);color:var(--gold);font-family:var(--sans);font-weight:500;font-size:12px;
  letter-spacing:.16em;text-transform:uppercase;border-bottom:1px solid var(--lineS);cursor:pointer}
 thead th.sp{background:var(--bg2);cursor:default}
 thead th .sa{display:inline-block;margin-left:5px;font-size:12px;color:var(--mut)}
 thead th.sorted{color:var(--tx)}
 thead th.sorted .sa{color:var(--gold)}
 .grip{position:absolute;top:0;right:-4px;width:9px;height:100%;cursor:col-resize;z-index:6;
  background:linear-gradient(var(--lineS),var(--lineS)) no-repeat right 4px center/1px 100%}
 .grip::before,.grip::after{content:"";position:absolute;right:2px;width:5px;height:5px;
  background:var(--lineS);transform:rotate(45deg);transition:background .15s}
 .grip::before{top:6px} .grip::after{bottom:6px}
 .grip:hover,.grip.drag{background:linear-gradient(var(--gold),var(--gold)) no-repeat right 3px center/2px 100%}
 .grip:hover::before,.grip.drag::before,.grip:hover::after,.grip.drag::after{background:var(--gold)}
 tbody td{padding:10px 14px;border-bottom:1px solid rgba(36,42,58,.55);vertical-align:top;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--tx2)}
 /* severity as a quadrant notch (inset, not a filled border) that widens on
    hover — a measurement detail coming into focus, not a highlight */
 tbody td.c-sev{border-left:0;box-shadow:inset 3px 0 0 var(--rc);padding-left:14px;transition:box-shadow .1s}
 tbody tr:hover td.c-sev{box-shadow:inset 6px 0 0 var(--rc)}
 tbody tr{cursor:pointer}
 tbody tr.vsp{cursor:default}
 tbody tr.vsp td{background:transparent!important;border:none!important;padding:0!important}
 tbody tr:nth-child(even) td{background:rgba(255,255,255,.012)}
 tbody tr:hover td{background:rgba(201,165,77,.035)}
 tbody tr.sel td{background:rgba(201,165,77,.09)}
 tbody tr.sel td.c-sev{box-shadow:inset 6px 0 0 var(--gold)}
 table.wrap tbody td{white-space:normal;overflow:visible;text-overflow:clip;word-break:break-word}
 /* severity: colored label only — never a filled pill (see .sv above) */
 .sevlbl{font-weight:700;font-size:12px;letter-spacing:.08em;text-transform:uppercase}
 .c-cat{color:var(--tx2)} .c-ttl{color:var(--tx)}
 .mono{color:var(--tx2)} .c-line{color:var(--mut);text-align:right}
 .c-match{color:var(--tx2)}
 /* Type carries NO hue: severity owns all color. Differentiate by weight. */
 .c-typ{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut)}
 .ty-find{color:var(--tx);font-weight:700} .ty-rev{color:var(--tx2);font-weight:500} .ty-info{color:var(--mut)}
 /* the empty state is the one legitimate place for a circle — only inside a
    specific triad (a minute mark, a centered body, a sharp horizon), never a
    circle alone, which is what made the earlier watermark read as generic */
 #empty{display:none;position:relative;height:100%;color:var(--mut);font-size:13px;text-align:center}
 #empty .horizon{position:absolute;left:12%;right:12%;top:33%;height:1px;
  background:linear-gradient(to right,transparent,rgba(201,165,77,.45) 18%,rgba(201,165,77,.45) 82%,transparent)}
 #empty .body{position:absolute;left:50%;top:9%;width:min(220px,30vw);aspect-ratio:1;transform:translateX(-50%);
  border:1px solid rgba(201,165,77,.20);border-radius:50%}
 #empty .mote{position:relative;margin:0 auto 14px}
 #empty .mote{position:absolute;left:50%;top:calc(33% - 8px);transform:translateX(-50%);margin:0}
 #empty .emptxt{position:absolute;left:0;right:0;top:calc(33% + 22px)}

 /* ---------- scrollbars ---------- */
 ::-webkit-scrollbar{width:11px;height:12px}
 ::-webkit-scrollbar-track{background:var(--bg)}
 ::-webkit-scrollbar-thumb{background:var(--lineS);border:3px solid var(--bg);border-radius:6px}
 ::-webkit-scrollbar-thumb:hover{background:var(--gold)}
 ::-webkit-scrollbar-corner{background:var(--bg)}
 *{scrollbar-color:var(--lineS) var(--bg);scrollbar-width:thin}
 body.resizing{cursor:col-resize;user-select:none}

 /* ---------- preview drawer ---------- */
 #ov{position:fixed;inset:0;background:rgba(3,5,9,.6);z-index:20;display:none}
 #dr{position:fixed;top:0;right:0;height:100%;width:min(960px,96vw);min-width:340px;z-index:21;transform:translateX(101%);
  transition:transform .22s ease-out;background:var(--bg2);
  border-left:1px solid var(--gold);box-shadow:-24px 0 50px -20px rgba(0,0,0,.6);display:flex;flex-direction:column}
 #dr.open{transform:none}
 /* focus frame: signals "this file is the one under analysis right now" — a
    corner cut at 45°, not a HUD bracket: the corner is sliced off, not boxed */
 #dr.open::before,#dr.open::after{content:"";position:absolute;width:18px;height:18px;
  pointer-events:none;z-index:24;border:2px solid var(--gold)}
 #dr.open::before{top:8px;left:8px;border-right:none;border-bottom:none;
  clip-path:polygon(0 0,100% 0,100% 45%,45% 100%,0 100%)}
 #dr.open::after{bottom:8px;right:8px;border-left:none;border-top:none;
  clip-path:polygon(55% 0,100% 0,100% 100%,0 100%,0 55%)}
 .dgrip{position:absolute;left:0;top:0;width:11px;height:100%;cursor:col-resize;z-index:23;transform:translateX(-50%);
  background:linear-gradient(var(--lineS),var(--lineS)) no-repeat center/1px 100%}
 .dgrip::before,.dgrip::after{content:"";position:absolute;left:50%;width:5px;height:5px;margin-left:-2.5px;
  background:var(--lineS);transform:rotate(45deg);transition:background .15s}
 .dgrip::before{top:6px} .dgrip::after{bottom:6px}
 .dgrip:hover,.dgrip.drag{background:linear-gradient(var(--gold),var(--gold)) no-repeat center/2px 100%}
 .dgrip:hover::before,.dgrip.drag::before,.dgrip:hover::after,.dgrip.drag::after{background:var(--gold)}
 .dhead{padding:16px 18px;border-bottom:1px solid var(--line)}
 .dhead .fn{color:var(--gold);font-size:13px;word-break:break-all;font-family:var(--mono)}
 .dhead .sub{color:var(--mut);font-size:12px;margin-top:5px;letter-spacing:.06em}
 .dnav{display:flex;align-items:center;gap:8px;margin-top:9px}
 .dnav .cnt{font-size:11px;color:var(--mut)}
 .dbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:10px 18px;border-bottom:1px solid var(--line);font-size:12px}
 .dbar input[type=text]{min-width:120px;flex:1}
 .dbar .cnt{color:var(--mut);min-width:52px;text-align:right;font-size:12px}
 .dbar .sep{flex:0 0 1px;align-self:stretch;background:var(--line);margin:1px 2px}
 .icobtn{font-size:17px;line-height:1;padding:6px 12px;min-width:38px;text-align:center;font-family:var(--mono)}
 .pvwrap{flex:1;overflow:auto;background:var(--bg)}
 .code{margin:0;padding:10px 0;font-size:13px;font-family:var(--mono);line-height:1.6;tab-size:4;--lnw:3ch;min-width:max-content}
 .code .cl{display:flex;align-items:flex-start}
 .code .cl:hover{background:rgba(201,165,77,.05)}
 .code .ln{flex:0 0 auto;width:var(--lnw);min-width:var(--lnw);text-align:right;color:var(--mut);user-select:none;
  padding:0 14px 0 16px;position:sticky;left:0;background:var(--bg2);border-right:1px solid var(--line)}
 .code .lc{flex:1 1 auto;white-space:pre;padding:0 16px 0 14px;color:var(--tx2)}
 .code.wrap{min-width:0}
 .code.wrap .lc{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word}
 /* deliberately varied, not a rainbow: gold=keywords/structure (the language's own
    grammar), vault=literals/data (what the code operates on), blue=numbers/markup,
    high(amber)=metadata/annotations, low(soft blue)=object keys — five distinct
    hues instead of "everything gold". */
 .tk-com{color:var(--mut);font-style:italic}.tk-str{color:var(--vault)}.tk-num{color:var(--blue)}
 .tk-kw{color:var(--gold);font-weight:600}.tk-anno{color:var(--high)}.tk-tag{color:var(--blue)}
 .tk-attr{color:var(--tx2)}.tk-punct{color:var(--tx2)}.tk-key{color:var(--low)}
 /* gold = authority/structure (active states, selection); vault = analyzed/derived
    data (search results, CVE lookups) — kept deliberately separate, never mixed
    on the same element, so gold doesn't end up meaning "everything". */
 mark{background:var(--vault);color:var(--vaultd);padding:0 1px}
 mark.active{background:var(--gold);color:#1a1305}
 .x{cursor:pointer;color:var(--mut);font-size:22px;line-height:1}.x:hover{color:var(--gold)}
 /* the reported line is analyzed/derived data, not structure — vault, not gold;
    brighter than the search-mark background since this is the one line that
    matters most in the whole file, not a passing match. */
 .code .cl.hl-line{background:rgba(90,169,156,.30);box-shadow:inset 4px 0 0 var(--vault)}
 .code .cl.hl-line .ln{background:rgba(90,169,156,.22);color:var(--tx)}
 #toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(18px);opacity:0;z-index:30;
  background:var(--panel);border:1px solid var(--gold);color:var(--gold);padding:9px 18px;font-size:12px;
  letter-spacing:.08em;text-transform:uppercase;border-radius:3px;
  box-shadow:0 12px 30px -10px rgba(0,0,0,.5);transition:.22s}
 #toast.show{opacity:1;transform:translateX(-50%)}
 /* readout tooltip: full text of a truncated cell — a styled, fast-appearing
    replacement for the native browser title tooltip */
 #qtip{position:fixed;z-index:40;display:none;max-width:min(70vw,640px);padding:7px 11px;
  font-family:var(--mono);font-size:13px;color:var(--tx);background:var(--panel);
  border:1px solid var(--vault);border-radius:3px;box-shadow:0 12px 28px -10px rgba(0,0,0,.6);
  pointer-events:none;word-break:break-all;white-space:pre-wrap}
 #qtip.show{display:block}

 /* keyboard focus: an explicit ring only for keyboard navigation, never for
    mouse clicks (:focus-visible) — the report has zero focus styling today */
 .sv,.ty,.btn,.icobtn,summary,input,tbody tr{outline:none}
 .sv:focus-visible,.ty:focus-visible,.btn:focus-visible,.icobtn:focus-visible,
 summary:focus-visible,input:focus-visible,tbody tr:focus-visible{
  outline:2px solid var(--gold);outline-offset:2px}

 /* a finding you've already opened stays quietly marked (a thinner notch than
    the active-selection one) even after the drawer closes and you scroll on */
 tbody tr.lastv td.c-sev{box-shadow:inset 4px 0 0 var(--gold)}

 /* a file with no embedded source (outside the preview budget) reads as
    underlined-dotted rather than silently failing when you click it */
 .c-file.no-src{text-decoration:underline dotted rgba(174,178,189,.45);text-underline-offset:2px}

 /* live confirmation of the include/exclude search syntax, since the only
    explanation today is a placeholder that disappears on first keystroke */
 #qchips{display:flex;flex-wrap:wrap;gap:5px;margin-top:7px}
 #qchips:empty{display:none}
 #qchips span{font-size:11px;padding:2px 7px;border-radius:3px;border:1px solid var(--lineS);color:var(--tx2)}
 #qchips span.qinc{border-color:var(--gold);color:var(--gold)}
 #qchips span.qexc{border-color:var(--mut);color:var(--mut);text-decoration:line-through}

 @media print{
  html,body{height:auto;overflow:visible;background:#fff;color:#000}
  .sidebar,#dr,#ov,#toast,#qtip,.app::before,.app::after{display:none!important}
  .app,.main{height:auto;display:block}
  .tablewrap{overflow:visible;height:auto}
  thead th{position:static;background:#eee;color:#000}
  tbody td{white-space:normal;color:#000;overflow:visible;text-overflow:clip}
  tbody tr:hover td{background:none}
 }
</style></head><body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true"><symbol id="radiant-glyph" viewBox="0 0 64 64">
<path d="M18 23L32 51M18 23L4 32M18 23L46 23M18 23L18 4M32 51L18 60M32 51L46 23M32 51L46 60M4 32L18 60M4 32L18 4M4 32L18 41M18 60L46 60M18 60L18 41M46 23L46 4M46 23L60 32M18 4L46 4M18 4L32 13M46 60L60 32M46 60L46 41M18 41L32 13M18 41L46 41M46 4L60 32M46 4L32 13M60 32L46 41M32 13L46 41"/>
</symbol></svg>
<div class="app">
 <aside class="sidebar">
  <div class="sb-brand">
   <svg class="radiant wm"><use href="#radiant-glyph"></use></svg>
   <div class="wordmark"><svg class="radiant mark"><use href="#radiant-glyph"></use></svg>APK<span class="dim">//</span>SECSCAN</div>
   <div class="tagline">Static Security Review</div>
  </div>
  <div class="sb-scroll">
   <div class="sb-title">
    <h1>@@APK@@</h1>
    <div class="sb-meta">
     <div class="mrow"><span class="mk">Package</span><span class="mv">@@PKG@@</span></div>
     <div class="mrow"><span class="mk">Scope</span><span class="mv">@@SCOPE@@</span></div>
     <div class="mrow"><span class="mk">Files</span><span class="mv">@@NFILES@@</span></div>
     <div class="mrow"><span class="mk">Scanned</span><span class="mv">@@GENERATED@@</span></div>
     <div class="mrow"><span class="mk">Embedded</span><span class="mv" id="embedRow"></span></div>
    </div>
    <div class="sb-baseline"><span class="tag">Baseline</span>@@BASELINE@@</div>
    <div class="sb-baseline"><span class="tag cve">CVE</span>@@CVESTATUS@@</div>
   </div>

   <div class="sb-sec">
    <span class="sb-lbl">Severity</span>
    <div class="sevrow">@@SEVCHK@@</div>
    <div class="spectrum" title="hover: preview · click: isolate this severity">@@SPECTRUM@@</div>
   </div>

   <div class="sb-sec">
    <span class="sb-lbl">Type</span>
    <div class="grp">@@TYPCHK@@</div>
   </div>

   <details class="sb-sec sb-cat" id="catDetails">
    <summary><span>Category</span><span class="catsum" id="catSummary"></span></summary>
    <div class="catactions">
     <button type="button" class="btn mini" id="catAll">All</button>
     <button type="button" class="btn mini" id="catNone">None</button>
    </div>
    <div class="catrow" id="catrow">@@CATCHK@@</div>
   </details>

   <div class="sb-sec">
    <span class="sb-lbl">Search</span>
    <input type="text" id="q" placeholder="title / file / match  ·  -term excludes  ·  press /">
    <div id="qchips"></div>
    <div class="sb-actions">
     <button class="btn" id="wrapBtn">Wrap off</button>
     <button class="btn" id="expBtn" title="export the rows currently visible (after filters) as CSV">Export CSV</button>
     <button class="btn" id="resetBtn" title="clear all filters and search">Reset</button>
    </div>
    <div class="shown-row" id="shown" aria-live="polite" aria-atomic="true"></div>
   </div>

   <div class="sb-sec">
    <span class="sb-lbl">Legend</span>
    <div class="lgroup">
     <div class="lgtitle">Type</div>
     <div class="lg"><b>FINDING</b> confirmed evidence</div>
     <div class="lg"><b>REVIEW</b> runtime surface to verify</div>
     <div class="lg"><b>INFO</b> public identifier</div>
    </div>
    <div class="lgroup">
     <div class="lgtitle">Category</div>
     <div class="lg"><b>DEPENDENCY</b> known CVE &middot; OSV.dev</div>
     <div class="lg"><b>ASSETS / ANOMALY</b> baseline discrepancy</div>
    </div>
   </div>

   <div class="sb-sec sb-hint">
    <b>Click</b> a row to inspect the file &middot; <b>double-click</b> to copy its path &middot;
    <b>drag</b> a header divider to resize <b>(double-click = auto-fit)</b> &middot;
    <b>hover/click</b> the severity bar to preview/isolate &middot;
    <b>j/k</b> in the drawer moves between findings in the same file
   </div>
  </div>
 </aside>
 <main class="main">
  <div class="tablewrap">
   <table id="tbl">
    <colgroup><col><col><col><col><col><col><col><col class="sp"></colgroup>
    <thead><tr>
     <th data-k="sev">Sev<i class="sa"></i></th><th data-k="cat">Category<i class="sa"></i></th><th data-k="typ">Type<i class="sa"></i></th><th data-k="ttl">Title<i class="sa"></i></th><th data-k="file">File<i class="sa"></i></th><th data-k="line">Line<i class="sa"></i></th><th data-k="match">Match<i class="sa"></i></th><th class="sp"></th>
    </tr></thead>
    <tbody id="tb"></tbody>
   </table>
  </div>
  <div id="empty">
   <div class="body"></div>
   <div class="horizon"></div>
   <svg class="radiant tiny mote"><use href="#radiant-glyph"></use></svg>
   <div class="emptxt">no rows match the current filters</div>
  </div>
 </main>
</div>
<div id="ov"></div>
<div id="dr">
 <div class="dgrip" id="dgrip" title="drag to resize · double-click for full width"></div>
 <div class="dhead"><div class="fn" id="drfn">&mdash;</div><div class="sub" id="drsub"></div>
  <div class="dnav" id="dnav" style="display:none">
   <button class="btn icobtn" id="pFPrev" title="previous finding in this file (k)">&lsaquo;</button>
   <span class="cnt" id="dnavCnt"></span>
   <button class="btn icobtn" id="pFNext" title="next finding in this file (j)">&rsaquo;</button>
  </div>
 </div>
 <div class="dbar">
  <input type="text" id="ps" placeholder="search (regex)">
  <button class="btn icobtn" id="pRe" title="toggle regex">.*</button>
  <button class="btn icobtn on" id="pCi" title="case-insensitive">Aa</button>
  <button class="btn icobtn" id="pPrev" title="previous match">&lsaquo;</button>
  <button class="btn icobtn" id="pNext" title="next match">&rsaquo;</button>
  <span class="cnt" id="pCnt"></span>
  <span class="sep"></span>
  <button class="btn on" id="pHl" title="highlight the line the finding was matched on">Highlight</button>
  <button class="btn" id="pWrap" title="toggle word wrap">Wrap</button>
  <button class="btn" id="pCopy">Copy path</button>
  <span class="x" id="drx" title="close (Esc)">&#10005;</span>
 </div>
 <div class="pvwrap"><div class="code" id="pv"></div></div>
</div>
<div id="toast"></div>
<div id="qtip"></div>
<script id="embed" type="application/json">@@EMBED@@</script>
<script id="rowsdata" type="application/json">@@ROWSJSON@@</script>
<script>
 const EMBED=JSON.parse(document.getElementById('embed').textContent||'{}');
 (function(){
  const paths=Object.keys(EMBED); const okN=paths.filter(p=>EMBED[p]&&EMBED[p].c!==undefined).length;
  const el=document.getElementById('embedRow'); if(el) el.textContent=okN+'/'+paths.length+' files';
 })();
 // DATA: one array per row, column order = [sev,cat,typ,title,file,line,match]
 // (matches the <thead> columns 1:1). Kept as arrays, not objects, so a 10k+
 // row report stays a few hundred KB of JSON instead of megabytes of markup.
 const DATA=JSON.parse(document.getElementById('rowsdata').textContent||'[]');
 let filtered=DATA.slice(), comparator=null;
 const SEVC={CRITICAL:'#E05A4E',HIGH:'#E08C42',MEDIUM:'#E3D2A0',LOW:'#7FA6CC',INFO:'#A29C93'};
 const SEV_RANK={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
 const tbl=document.getElementById('tbl'),wrap=document.querySelector('.tablewrap');
 const tb=document.getElementById('tb');
 const q=document.getElementById('q'),shown=document.getElementById('shown'),empty=document.getElementById('empty');
 const SEGS=[...document.querySelectorAll('.spectrum .sg')];
 // "Prime Radiant": hover a severity segment to preview-dim the other rows
 // currently on screen (no refiltering); click it to actually isolate that
 // severity (sets only its checkbox, unchecks the rest).
 SEGS.forEach(sg=>{
  sg.addEventListener('mouseenter',()=>{
   sg.classList.add('sg-hover');
   for(const tr of tb.children) if(tr.dataset.sev&&tr.dataset.sev!==sg.dataset.sev) tr.classList.add('rowdim');
  });
  sg.addEventListener('mouseleave',()=>{
   sg.classList.remove('sg-hover');
   for(const tr of tb.children) tr.classList.remove('rowdim');
  });
  sg.addEventListener('click',()=>{
   document.querySelectorAll('.fsev').forEach(c=>{c.checked=(c.value===sg.dataset.sev);});
   apply();
  });
 });
 const sevSel=()=>new Set([...document.querySelectorAll('.fsev:checked')].map(c=>c.value));
 const typSel=()=>new Set([...document.querySelectorAll('.ftyp:checked')].map(c=>c.value));
 const catSel=()=>new Set([...document.querySelectorAll('.fcat:checked')].map(c=>c.value));

 // ---------- virtual scroll: only the rows visible in the viewport are ever
 // real DOM nodes (a fixed row height + top/bottom spacer <tr>s), so table
 // size no longer depends on how many findings the scan produced. ----------
 let selIdx=-1, renderedStart=-1, renderedEnd=-1, ROWH=43, rowHMeasured=false, wrapMode=false;
 let lastRecord=null; // the last row opened in the drawer — reference-equal, survives re-filtering
 const BUFFER=8;
 function tcClass(t){return t==='FINDING'?'ty-find':(t==='REVIEW'?'ty-rev':'ty-info');}
 function badge(s){return '<span class="sevlbl" style="color:'+(SEVC[s]||'#A29C93')+'">'+esc(s)+'</span>';}
 function rowHtml(r,idx){
  const sev=r[0],cat=esc(r[1]),typ=r[2],ttl=esc(r[3]),file=esc(r[4]),line=esc(r[5]),match=esc(r[6]);
  const rc=SEVC[sev]||'#A29C93';
  const e=EMBED[r[4]]; const noSrc=!(e&&e.c!==undefined);
  const cls=[]; if(idx===selIdx)cls.push('sel'); if(r===lastRecord)cls.push('lastv');
  return '<tr data-i="'+idx+'" data-sev="'+sev+'"'+(cls.length?' class="'+cls.join(' ')+'"':'')
   +' style="--rc:'+rc+'" tabindex="0" role="button">'
   +'<td class="c-sev">'+badge(sev)+'</td>'
   +'<td class="c-cat">'+cat+'</td>'
   +'<td class="c-typ '+tcClass(typ)+'">'+esc(typ)+'</td>'
   +'<td class="c-ttl" title="'+ttl+'">'+ttl+'</td>'
   +'<td class="mono c-file'+(noSrc?' no-src':'')+'" title="'+file+(noSrc?' (no embedded preview)':'')+'">'+file+'</td>'
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

 // "-term" in the search box excludes rows containing it (space-separated,
 // AND across include terms, OR across exclude terms) — lets you narrow down
 // what to hide, not just what to show, without touching the chip filters.
 function parseQuery(v){
  const inc=[],exc=[];
  for(const t of v.trim().split(/\s+/).filter(Boolean)){
   if(t.length>1&&t[0]==='-') exc.push(t.slice(1).toLowerCase()); else inc.push(t.toLowerCase());
  }
  return {inc,exc};
 }
 const qchips=document.getElementById('qchips');
 function apply(){
  const S=sevSel(),T=typSel(),C=catSel(); const {inc,exc}=parseQuery(q.value);
  qchips.innerHTML=inc.map(t=>'<span class="qinc">'+esc(t)+'</span>').join('')
   +exc.map(t=>'<span class="qexc">-'+esc(t)+'</span>').join('');
  filtered=DATA.filter(r=>{
   if(!(S.has(r[0])&&T.has(r[2])&&C.has(r[1]))) return false;
   if(!inc.length&&!exc.length) return true;
   const hay=(r[0]+' '+r[1]+' '+r[2]+' '+r[3]+' '+r[4]+' '+r[5]+' '+r[6]).toLowerCase();
   for(const t of inc) if(!hay.includes(t)) return false;
   for(const t of exc) if(hay.includes(t)) return false;
   return true;
  });
  if(comparator) filtered.sort(comparator);
  const n=filtered.length; const vis={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};
  for(const r of filtered) vis[r[0]]=(vis[r[0]]||0)+1;
  shown.innerHTML='<b>'+n+'</b> / '+DATA.length+' rows';
  empty.style.display=n?'none':'block';
  const tot=n||1;
  for(const sg of SEGS){const c=vis[sg.dataset.sev]||0;sg.style.width=(c*100/tot)+'%';sg.style.opacity=c?'1':'0';}
  updateCatSummary();
  selIdx=-1; renderedStart=-1; renderedEnd=-1; wrap.scrollTop=0; renderWindow(true);
 }
 function updateCatSummary(){
  const boxes=[...document.querySelectorAll('.fcat')];
  const on=boxes.filter(c=>c.checked).length;
  const el=document.getElementById('catSummary');
  if(el) el.textContent=on+'/'+boxes.length;
 }
 document.querySelectorAll('.fsev,.ftyp,.fcat').forEach(c=>c.addEventListener('change',apply));
 q.addEventListener('input',apply);
 document.getElementById('catAll').addEventListener('click',()=>{document.querySelectorAll('.fcat').forEach(c=>c.checked=true);apply();});
 document.getElementById('catNone').addEventListener('click',()=>{document.querySelectorAll('.fcat').forEach(c=>c.checked=false);apply();});
 document.getElementById('resetBtn').addEventListener('click',()=>{
  document.querySelectorAll('.fsev,.ftyp,.fcat').forEach(c=>{c.checked=true;});
  q.value='';
  comparator=null; sortState.col=-1; sortState.dir=1;
  ths.slice(0,NCOL).forEach(th=>{th.classList.remove('sorted');const sa=th.querySelector('.sa');if(sa)sa.textContent='';});
  apply();
 });
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
 const DEF=[75,120,95,270,320,60,360];
 const MIN=[58,80,68,130,150,50,130];
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

 // ---------- sidebar resize (drag the right edge, same language as the column grips) ----------
 (function(){
  const sidebar=document.querySelector('.sidebar');
  const sg=document.createElement('div'); sg.className='sbgrip'; sidebar.appendChild(sg);
  const SBMIN=220,SBMAX=520; let sx=0,sw=0;
  const move=e=>{
   const w=Math.max(SBMIN,Math.min(SBMAX,sw+(e.clientX-sx)));
   sidebar.style.flex='0 0 '+w+'px'; sidebar.style.width=w+'px';
   layout(); renderedStart=-1; renderedEnd=-1; renderWindow(true);
  };
  const up=()=>{document.removeEventListener('mousemove',move);document.removeEventListener('mouseup',up);
   document.body.classList.remove('resizing');sg.classList.remove('drag');};
  sg.addEventListener('mousedown',e=>{sx=e.clientX;sw=sidebar.getBoundingClientRect().width;sg.classList.add('drag');
   document.addEventListener('mousemove',move);document.addEventListener('mouseup',up);
   document.body.classList.add('resizing');e.preventDefault();});
 })();

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
 // split highlighted/marked HTML into per-line rows (balanced tags) + a sticky gutter.
 // hlLine (1-indexed), when set, marks the line the finding was matched on.
 function numberize(innerHtml,hlLine){
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
  return R.map((h,i)=>'<div class="cl'+((hlLine&&i+1===hlLine)?' hl-line':'')+'"><span class="ln">'+(i+1)+'</span><span class="lc">'+(h||' ')+'</span></div>').join('');
 }
 let pvRaw='',pvLang='generic',pvPath='',pvLine=0,hlOn=true;
 const ov=document.getElementById('ov'),dr=document.getElementById('dr'),pv=document.getElementById('pv');
 const drfn=document.getElementById('drfn'),drsub=document.getElementById('drsub');
 const ps=document.getElementById('ps'),pCnt=document.getElementById('pCnt');
 let pCi=true,pRex=false,hits=[],hidx=-1;
 function renderPreview(){
  const Q=ps.value; const hlLine=hlOn?pvLine:0;
  if(!Q){pv.innerHTML=numberize(hl(pvRaw,pvLang),hlLine);pCnt.textContent='';hits=[];hidx=-1;
   if(hlLine){const el=pv.querySelector('.cl.hl-line');if(el)el.scrollIntoView({block:'center'});}
   return;}
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
  out+=esc(pvRaw.slice(last));pv.innerHTML=numberize(out,hlLine);
  hits=[...pv.querySelectorAll('mark')];hidx=hits.length?0:-1;markActive();
  pCnt.textContent=hits.length?'1/'+hits.length:'0';
 }
 function markActive(){hits.forEach(h=>h.classList.remove('active'));
  if(hidx>=0&&hits[hidx]){hits[hidx].classList.add('active');hits[hidx].scrollIntoView({block:'center',inline:'nearest'});pCnt.textContent=(hidx+1)+'/'+hits.length;}}
 function step(d){if(!hits.length)return;hidx=(hidx+d+hits.length)%hits.length;markActive();}
 const dnav=document.getElementById('dnav'),dnavCnt=document.getElementById('dnavCnt');
 let sameFileIdxs=[],sameFilePos=-1;
 function openPreview(idx){
  hideQtip();
  selIdx=idx; lastRecord=filtered[idx];
  wrap.scrollTop=Math.max(0,idx*ROWH-wrap.clientHeight/2);
  renderedStart=-1;renderedEnd=-1; renderWindow(true);
  const path=filtered[idx][4]; const lnRaw=String(filtered[idx][5]||'').trim();
  pvLine=/^\d+$/.test(lnRaw)?parseInt(lnRaw,10):0;
  pvPath=path;drfn.textContent=path;ps.value='';
  sameFileIdxs=filtered.map((r,i)=>i).filter(i=>filtered[i][4]===path);
  sameFilePos=sameFileIdxs.indexOf(idx);
  if(sameFileIdxs.length>1){dnav.style.display='flex';dnavCnt.textContent=(sameFilePos+1)+'/'+sameFileIdxs.length+' in file';}
  else dnav.style.display='none';
  const e=EMBED[path];
  if(e&&e.c!==undefined){pvRaw=e.c;pvLang=langOf(path);
   drsub.textContent=(e.trunc?'[truncated] ':'')+pvRaw.length+' chars · '+pvLang;}
  else{pvRaw='// preview unavailable: '+(e?({binary:'binary file',missing:'file not found',budget:'beyond embedding budget'}[e.skip]||e.skip):'not embedded')+'\n// path: '+path;pvLang='generic';drsub.textContent='';}
  renderPreview();ov.style.display='block';dr.classList.add('open');
 }
 function stepFile(d){
  if(sameFileIdxs.length<2) return;
  sameFilePos=(sameFilePos+d+sameFileIdxs.length)%sameFileIdxs.length;
  openPreview(sameFileIdxs[sameFilePos]);
 }
 document.getElementById('pFPrev').addEventListener('click',()=>stepFile(-1));
 document.getElementById('pFNext').addEventListener('click',()=>stepFile(1));
 function closePreview(){dr.classList.remove('open');ov.style.display='none';
  selIdx=-1;renderedStart=-1;renderedEnd=-1;renderWindow(true);}
 tb.addEventListener('click',e=>{const tr=e.target.closest('tr[data-i]');if(!tr)return;
  openPreview(parseInt(tr.dataset.i,10));});
 tb.addEventListener('dblclick',e=>{const tr=e.target.closest('tr[data-i]');if(!tr)return;
  copy(filtered[parseInt(tr.dataset.i,10)][4]);});
 tb.addEventListener('keydown',e=>{
  if(e.key!=='Enter'&&e.key!==' ')return;
  const tr=e.target.closest('tr[data-i]');if(!tr)return;
  e.preventDefault();openPreview(parseInt(tr.dataset.i,10));
 });

 // ---------- readout tooltip on truncated cells (title/file/match) ----------
 const qtip=document.getElementById('qtip');
 let qtipTimer=null,qtipTd=null;
 function positionQtip(x,y){
  const pad=12,vw=window.innerWidth,vh=window.innerHeight;
  const w=qtip.offsetWidth,h=qtip.offsetHeight;
  qtip.style.left=Math.max(pad,Math.min(x+14,vw-w-pad))+'px';
  qtip.style.top=Math.max(pad,Math.min(y+18,vh-h-pad))+'px';
 }
 function hideQtip(){qtip.classList.remove('show');qtipTd=null;clearTimeout(qtipTimer);}
 tb.addEventListener('mouseover',e=>{
  const td=e.target.closest('td[title]');
  if(!td||td===qtipTd){return;}
  hideQtip();
  const x=e.clientX,y=e.clientY;
  qtipTimer=setTimeout(()=>{
   const txt=td.getAttribute('title');if(!txt)return;
   qtip.textContent=txt;qtip.classList.add('show');qtipTd=td;positionQtip(x,y);
  },400);
 });
 tb.addEventListener('mousemove',e=>{if(qtip.classList.contains('show'))positionQtip(e.clientX,e.clientY);});
 tb.addEventListener('mouseout',e=>{if(e.target.closest('td[title]'))hideQtip();});
 wrap.addEventListener('scroll',hideQtip);

 ov.addEventListener('click',closePreview);
 document.getElementById('drx').addEventListener('click',closePreview);
 document.addEventListener('keydown',e=>{if(e.key==='Escape')closePreview();});
 document.addEventListener('keydown',e=>{
  if(!dr.classList.contains('open'))return;
  const tag=(document.activeElement&&document.activeElement.tagName)||'';
  if(tag==='INPUT'||tag==='TEXTAREA')return;
  if(e.key==='j'){e.preventDefault();stepFile(1);}
  else if(e.key==='k'){e.preventDefault();stepFile(-1);}
 });
 window.addEventListener('beforeprint',()=>{renderAll();});
 window.addEventListener('afterprint',()=>{renderedStart=-1;renderedEnd=-1;renderWindow(true);});
 ps.addEventListener('input',renderPreview);
 ps.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();step(e.shiftKey?-1:1);}});
 document.getElementById('pNext').addEventListener('click',()=>step(1));
 document.getElementById('pPrev').addEventListener('click',()=>step(-1));
 document.getElementById('pRe').addEventListener('click',function(){pRex=!pRex;this.classList.toggle('on',pRex);renderPreview();});
 document.getElementById('pCi').addEventListener('click',function(){pCi=!pCi;this.classList.toggle('on',pCi);renderPreview();});
 document.getElementById('pHl').addEventListener('click',function(){hlOn=!hlOn;this.classList.toggle('on',hlOn);renderPreview();});
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
    _SUB={"@@APK@@":esc(apk),"@@PKG@@":pkg_esc,"@@SCOPE@@":scope_esc,"@@NFILES@@":nfiles_esc,
          "@@GENERATED@@":generated_esc,"@@BASELINE@@":esc(baseline),"@@CVESTATUS@@":cve_status_esc,
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
