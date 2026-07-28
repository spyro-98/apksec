# apk-secscan

Command-line tool (a single bash script) for **static security review of Android APKs**. It decompiles the APK, searches for risk patterns in the code/resources, and produces a navigable report with results classified by severity.

Pipeline: **jadx** (decompilation) → **ripgrep/grep** (static patterns) → **apksigner / aapt2 / strings** (optional binary-level checks) → report in **CSV / JSON / XML / HTML**.

## Philosophy

Every result is tagged with a `type` to separate three levels of certainty, so a security "smell" is never treated as if it were proof:

| Type | Meaning |
|---|---|
| `FINDING` | confirmed evidence (e.g. a hardcoded private key, `debuggable=true`) |
| `REVIEW`  | surface to verify at runtime (e.g. a cleartext traffic flag, an exported component) |
| `INFO`    | public identifier, not a vulnerability (e.g. a public Google API key, a Sentry DSN) |

Every row also has a `severity` (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) and a `category` (`Secrets`, `Network`, `WebView`, `Storage`, `Crypto`, `Manifest`, `Dependency`, `Assets`, etc.).

## Requirements

Required:

- **bash** (macOS/Linux; the script avoids associative arrays to stay portable on older bash)
- **jadx** — APK decompiler (not needed if you use `--skip-decompile`)
- **python3** — generates the reports, the CVE phase and the assets analysis
- **grep with PCRE support (`-P`)** — on macOS the system grep is BSD and doesn't support it: you need Homebrew's GNU grep (`ggrep` binary)
- **xargs**

Optional:

- **ripgrep (`rg`)** — faster search engine; falls back to the PCRE grep found above if absent
- **apksigner** — verifies signature schemes (detects Janus, CVE‑2017‑13156)
- **aapt / aapt2** — extracts the package name and `targetSdkVersion`
- **unzip** and **strings** — only required with `--native`, to extract and inspect `lib/*.so` and `assets/*`

Run `./apk-secscan.sh --deps` for an interactive diagnosis of what's present/missing on your system, with install commands for macOS (brew) and Linux (apt).

### Quick install (macOS)

```bash
brew install jadx ripgrep grep          # grep provides ggrep (GNU, -P support)
brew install --cask android-commandlinetools
sdkmanager "build-tools;35.0.0"         # for apksigner/aapt2
```

### Quick install (Linux/Debian)

```bash
sudo apt install python3 xargs findutils ripgrep unzip binutils
# jadx: download the release from github.com/skylot/jadx (or "apt install jadx" if available)
# apksigner/aapt: Android SDK build-tools
```

## Usage

```bash
./apk-secscan.sh [options] <app.apk>
```

Examples:

```bash
# full scan, all report formats
./apk-secscan.sh app.apk

# only the app's own code (excludes third-party libraries), HTML report only
./apk-secscan.sh -s app -f html app.apk

# also check known CVEs on dependencies (needs network) and native .so checks
./apk-secscan.sh --cve --native app.apk

# reuse an existing jadx decompilation, without re-running jadx
./apk-secscan.sh --skip-decompile ./previous-workdir app.apk

# CI usage: fails (exit 2) if there is at least one FINDING >= HIGH
./apk-secscan.sh --fail-on high --format json -o ./out app.apk
```

### Options

| Option | Description |
|---|---|
| `-s, --scope app\|libs\|all` | scope of the code to scan (default `all`). `app` = only the app's package, `libs` = only third-party libraries, `all` = everything. Manifest, resources, signature and absence checks **always** cover the whole APK, regardless of scope. |
| `-f, --format csv\|json\|xml\|html\|all` | output format(s) (default `all`) |
| `-o, --output <dir>` | output directory (default `./secscan-<apk>-<timestamp>`) |
| `-p, --app-package <pkg>` | force the app's package (bypasses manifest/aapt autodetection) |
| `--native` | also scan native libraries (`.so`) with `strings`, looking for embedded secrets |
| `--cve` | check known library CVEs via [OSV.dev](https://osv.dev) (needs network) |
| `--cve-max <n>` | maximum number of libraries queried on OSV (default 400) |
| `--cve-mock <file>` | use a saved OSV dump instead of the network (offline/CI use) — implies `--cve` |
| `--fail-on none\|low\|medium\|high\|critical` | exit code 2 if a `FINDING` >= threshold exists (for CI; default `none` → always exit 0) |
| `--jadx <path>` | path to the jadx binary |
| `--keep` | keep the decompilation work directory (don't delete it at the end of the scan) |
| `--skip-decompile <dir>` | reuse an existing jadx directory (no re-decompilation) |
| `--deps` | list the system tools used (present/missing + install command) |
| `-h, --help` | help |

## What gets checked

Static patterns over decompiled sources, resources and the manifest, including:

- **Secrets** — PEM private keys, Google service accounts, Stripe/AWS/Slack/GitHub/Twilio/OAuth keys, hardcoded JWTs, hardcoded passwords/secrets (CRITICAL)
- **Network** — permissive `TrustManager`/`HostnameVerifier`, cleartext HTTP endpoints, `usesCleartextTraffic`, network security config with `cleartextTrafficPermitted` or user trust-anchors
- **WebView** — `addJavascriptInterface`, JavaScript enabled, universal access from `file://`
- **Manifest** — `debuggable=true`, `allowBackup=true`, `exported=true` components, deep links, dangerous permissions
- **Crypto** — AES in ECB mode, weak algorithms (DES/RC4/Blowfish), weak hashes (MD5/SHA‑1), static IVs/insecure RNG
- **Storage / Logging / IPC / SQL** — SharedPreferences with sensitive keys in cleartext, writes to external storage, potentially sensitive logging, `PendingIntent` without `FLAG_IMMUTABLE`, SQL queries built via concatenation, `grantUriPermission`
- **Exec / DynamicCode** — `Runtime.exec`/`ProcessBuilder`, `DexClassLoader` and similar
- **Assets/Anomaly** — cryptographic material or keystores in bundles, pre-loaded databases, possible source-code leaks, development artifacts (`.git/`, `.idea/`, etc.) left in the package
- **Signing** — v1‑only signature scheme (vulnerable to Janus, CVE‑2017‑13156), via `apksigner`
- **Dependency** — known CVEs in embedded Maven libraries, via OSV.dev (with `--cve`)
- **Hardening (absence)** — missing certificate pinning, missing root detection, `AndroidKeyStore` not used, missing `FLAG_SECURE`

Reference baseline documented in the script header and in the report (current AGP/Kotlin/target SDK), used only as informational context, not as a failing rule.

## CVE phase (`--cve`)

Extracts `groupId:artifactId@version` coordinates of Maven libraries from the APK (`*.version` files and `pom.properties` in `META-INF/`) and queries them in batch against `https://api.osv.dev/v1/querybatch`, then fetches the detail (CVE ID, severity, fixed version) for each vulnerable library.

- Requires an outbound network connection to `api.osv.dev`. Without network, the phase is skipped with a message (`CVE: cannot reach OSV.dev (...). CVE phase skipped.`) and the rest of the scan proceeds normally.
- For **offline or air-gapped CI use**, use `--cve-mock <file>` with a JSON dump in the format `{"group:artifact@version": [<OSV vuln>, ...]}`.
- **macOS note**: if your `python3` comes from the python.org installer (not Homebrew), HTTPS requests can fail with `CERTIFICATE_VERIFY_FAILED` until you run `Install Certificates.command` once (found in `/Applications/Python 3.x/`). The script still attempts an automatic fallback using `certifi`'s certificate bundle, if the package is installed (`pip install certifi`).

## The HTML report

The `html` format generates a **single self-contained file** (no external dependencies, no network calls): the source code of the lines involved in findings is embedded in the file itself for the preview, within a budget of ~6&nbsp;MB / 600 files.

The table uses **virtualized ("windowed") rendering**: regardless of whether a scan produces a hundred or a hundred thousand rows, only the handful currently visible in the viewport are ever real DOM nodes — the rest exist purely as data in memory and are drawn on the fly as you scroll. This is what lets a report with tens of thousands of findings stay smooth and open instantly, instead of freezing the browser while it tries to lay out one `<tr>` per row.

Features:

- filter by **severity**, **type** (`FINDING`/`REVIEW`/`INFO`) and **category** (dynamic chips with counts, with "All"/"None" shortcuts)
- full‑text search box on title/file/match (keyboard shortcut **`/`** to focus it)
- **sortable columns**: click a header to sort (click again to reverse), with a ▲/▼ indicator; the Sev column sorts by actual severity, not alphabetically
- **resizable columns** (drag the border, double-click to auto-fit)
- **CSV export** of only the rows currently visible (respects the active filters) — useful for extracting a subset without re-running the scan
- click a row → side drawer with a **source file preview**, syntax highlighting, regex search with match navigation, copy file path
- word-wrap mode (the "Wrap" button) renders every filtered row at once rather than just the visible window, since wrapped rows no longer share a uniform height — on very large result sets, filter down first for the smoothest experience

> **Warning**: the HTML report embeds portions of the scanned app's real source code and can contain real secrets in `CRITICAL` findings. Treat it as sensitive material: don't commit it to a public repository and don't share it without first reviewing/removing confidential content. The project's `.gitignore` excludes locally-generated `secscan-*` files by default.

## CI usage

```bash
./apk-secscan.sh --fail-on high -f json -o ./out app.apk || exit 1
```

With `--fail-on <threshold>` the script exits with code **2** if at least one `type=FINDING` result with severity ≥ threshold exists; otherwise it exits with **0**. `REVIEW`/`INFO` results never affect the exit code, since by definition they require manual verification.

## Limitations

- **Static** analysis: it doesn't run the app, and doesn't detect behavior that depends purely on remote/runtime configuration (`REVIEW` results exist precisely to flag what to verify by hand).
- Heavily obfuscated/minified code reduces the effectiveness of patterns based on known class/method names.
- Regex patterns can produce **false positives** (hence the FINDING/REVIEW/INFO distinction) and, in theory, false negatives on uncovered variants.
- It doesn't replace a manual penetration test or a full code review: it's meant as a **fast first pass**.
