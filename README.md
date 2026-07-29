# apk-secscan

Command-line tool (a single bash script) for **static security review of Android APKs**. It decompiles the APK, searches for risk patterns in the code/resources, optionally cross-references dependency CVEs and a pluggable [Semgrep](https://semgrep.dev) ruleset, and produces a navigable report with results classified by severity.

Pipeline: **jadx** (decompilation) → **ripgrep/grep** (static patterns) + a few **Python** passes (manifest XML parsing, asset/packer analysis, a source/sink heuristic) → optional **OSV.dev** (CVE) and **Semgrep** (custom rules) → report in **CSV / JSON / XML / SARIF / HTML**.

## Quick start

```bash
./apk-secscan.sh -s app -f html --native --cve file.apk
```

This is the recommended default for a first look at an app: `-s app` scopes the scan to the app's own code (skips the noise of third-party libraries), `-f html` produces the interactive report, `--native` also inspects `lib/*.so` for embedded secrets and custom crypto, and `--cve` cross-checks every embedded library against known CVEs. Open the resulting `secscan-<apk>-<timestamp>/secscan-<apk>.html` file in any browser — no server, no build step, no network calls beyond the optional CVE lookup.

Don't have the dependencies yet? See [Installation](#installation) below, or just run:

```bash
./apk-secscan.sh --deps
```

## Philosophy

Every result is tagged with a `type` to separate three levels of certainty, so a security "smell" is never treated as if it were proof:

| Type | Meaning |
|---|---|
| `FINDING` | confirmed evidence (e.g. a hardcoded private key, `debuggable=true`) |
| `REVIEW`  | surface to verify at runtime (e.g. a cleartext traffic flag, an exported component, a heuristic hit) |
| `INFO`    | public identifier or status note, not a vulnerability (e.g. a public Google API key, "CVE check: 40 libraries checked, 0 vulnerable") |

Every row also has a `severity` (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) and a `category` (`Secrets`, `Network`, `WebView`, `Storage`, `Crypto`, `Manifest`, `Dependency`, `Assets`, `Packer`, `Semgrep`, `Taint`, etc.). Every check is additionally tagged in its title with the [OWASP MASVS v2](https://mas.owasp.org/MASVS/) control area it maps to (`MASVS-STORAGE`, `MASVS-NETWORK`, `MASVS-CRYPTO`, `MASVS-PLATFORM`, `MASVS-CODE`, `MASVS-RESILIENCE`, `MASVS-PRIVACY`), for interoperability with other tooling and reports — this is a category-level mapping for quick cross-referencing, not a per-control certification.

A phase that can run but found nothing (CVE, Semgrep, packer signatures, the taint heuristic) always leaves a visible `INFO` status row saying so. A report should never look identical whether a check found zero issues or silently didn't run.

## Installation

### Requirements

Required:

| Tool | Role |
|---|---|
| **bash** | macOS/Linux; the script avoids associative arrays to stay portable on older bash |
| **jadx** | APK decompiler (not needed if you use `--skip-decompile`) |
| **python3** | generates the reports, the CVE/Semgrep phases, manifest parsing and the asset/packer/taint analysis |
| **grep with PCRE support (`-P`)** | on macOS the system grep is BSD and doesn't support it: you need Homebrew's GNU grep (`ggrep` binary) |
| **xargs** | batch execution of the search patterns |

Optional:

| Tool | Role | Needed for |
|---|---|---|
| **ripgrep (`rg`)** | faster search engine | falls back to the PCRE grep above if absent |
| **apksigner** | verifies signature schemes (detects Janus, CVE‑2017‑13156) | signature check |
| **aapt / aapt2** | extracts the package name and `targetSdkVersion` | manifest metadata |
| **unzip**, **strings** | extract and inspect `lib/*.so` and `assets/*` | `--native` |
| **semgrep** | runs a custom static-analysis ruleset over the decompiled sources | `--semgrep <rules-dir>` |
| **certifi** (`pip install certifi`) | CA bundle fallback if `python3`'s own HTTPS trust store is broken | `--cve` on some macOS Python installs (see below) |

### Quick install (macOS)

```bash
brew install jadx ripgrep grep          # grep provides ggrep (GNU, -P support)
brew install --cask android-commandlinetools
sdkmanager "build-tools;35.0.0"         # for apksigner/aapt2
pip install semgrep                     # optional, for --semgrep
```

### Quick install (Linux/Debian)

```bash
sudo apt install python3 xargs findutils ripgrep unzip binutils
# jadx: download the release from github.com/skylot/jadx (or "apt install jadx" if available)
# apksigner/aapt: Android SDK build-tools
pip install semgrep                     # optional, for --semgrep
```

### Check dependency status

```bash
./apk-secscan.sh --deps
```

Prints every tool the script uses — required and optional — with a `[✓]`/`[ ]` status, the resolved path if found, what it's used for, and the exact install command for your platform (macOS/brew or Linux/apt, auto-detected). Safe to run any time, on any system: it never aborts or requires an APK, it exists specifically to answer "what do I still need to install". Run it whenever a scan complains about a missing tool, or before your first run on a new machine.

## Usage

```bash
./apk-secscan.sh [options] <app.apk>
```

Examples:

```bash
# recommended default: app-only scope, HTML report, native + CVE checks
./apk-secscan.sh -s app -f html --native --cve file.apk

# full scan, every report format, every third-party library included
./apk-secscan.sh app.apk

# also run a custom semgrep ruleset over the decompiled sources
./apk-secscan.sh --cve --native --semgrep ./my-android-rules app.apk

# reuse an existing jadx decompilation, without re-running jadx
./apk-secscan.sh --skip-decompile ./previous-workdir app.apk

# CI usage: fails (exit 2) if there is at least one FINDING >= HIGH,
# SARIF output for GitHub code scanning / other SARIF-aware tooling
./apk-secscan.sh --fail-on high --format sarif -o ./out app.apk
```

### Options

| Option | Description |
|---|---|
| `-s, --scope app\|libs\|all` | scope of the code to scan (default `all`). `app` = only the app's package, `libs` = only third-party libraries, `all` = everything. Manifest, resources, signature and absence checks **always** cover the whole APK, regardless of scope. |
| `-f, --format csv\|json\|xml\|html\|sarif\|all` | output format(s) (default `all`) |
| `-o, --output <dir>` | output directory (default `./secscan-<apk>-<timestamp>`) |
| `-p, --app-package <pkg>` | force the app's package (bypasses manifest/aapt autodetection) |
| `--native` | also scan native libraries (`.so`) with `strings` for embedded secrets, and search for a hardcoded AES S-box (custom/embedded crypto) |
| `--cve` | check known library CVEs via [OSV.dev](https://osv.dev) (needs network) |
| `--cve-max <n>` | maximum number of libraries queried on OSV (default 400) |
| `--cve-mock <file>` | use a saved OSV dump instead of the network (offline/CI use) — implies `--cve` |
| `--semgrep <rules-dir>` | also run [semgrep](https://semgrep.dev) with the given ruleset over the decompiled sources (needs `semgrep` installed; you supply the ruleset, e.g. an Android-focused community ruleset) |
| `--fail-on none\|low\|medium\|high\|critical` | exit code 2 if a `FINDING` >= threshold exists (for CI; default `none` → always exit 0) |
| `--jadx <path>` | path to the jadx binary |
| `--keep` | keep the decompilation work directory (don't delete it at the end of the scan) |
| `--skip-decompile <dir>` | reuse an existing jadx directory (no re-decompilation) |
| `--deps` | list the system tools used (present/missing + install command) — see [Check dependency status](#check-dependency-status) |
| `-h, --help` | help |

## What gets checked

Static patterns over decompiled sources, resources and the manifest, including:

- **Secrets** — PEM private keys, Google service accounts, Stripe/AWS/Slack/GitHub/Twilio/OAuth keys, hardcoded JWTs, hardcoded passwords/secrets (CRITICAL)
- **Network** — permissive `TrustManager`/`HostnameVerifier` (including `setDefaultHostnameVerifier`), cleartext HTTP endpoints, `usesCleartextTraffic`, network security config with `cleartextTrafficPermitted` or user trust-anchors
- **WebView** — `addJavascriptInterface`, JavaScript enabled, universal access from `file://`, WebView SSL error bypass (`onReceivedSslError`), mixed content always allowed, dynamic JS execution via `loadUrl("javascript:...")`
- **Manifest** — `debuggable=true`, `allowBackup=true`, `exported=true` components, exported providers/receivers/services without a permission (parsed with a real XML parser, not regex), deep links, dangerous permissions
- **Crypto** — AES in ECB mode, weak algorithms (DES/RC4/Blowfish), weak hashes (MD5/SHA‑1), static IVs/insecure RNG, deprecated SSL/TLS protocols (SSLv3, TLSv1.0/1.1), an embedded/custom AES S-box in native libraries (with `--native`)
- **Storage / Logging / IPC / SQL** — SharedPreferences with sensitive keys in cleartext, writes to external storage, potentially sensitive logging, `PendingIntent` without `FLAG_IMMUTABLE`, SQL queries built via concatenation, `grantUriPermission`
- **Exec / DynamicCode** — `Runtime.exec`/`ProcessBuilder`, `DexClassLoader` and similar
- **Assets/Anomaly** — cryptographic material or keystores in bundles, overly permissive `FileProvider` paths, pre-loaded databases, possible source-code leaks, development artifacts (`.git/`, `.idea/`, etc.) left in the package
- **Packer** — known filename/asset signatures of common Android packers/protectors (e.g. Tencent Legu, Qihoo 360 Jiagu, Bangcle/SecShell) — a fingerprint check, not an unpacker
- **Taint** (heuristic) — a "source" pattern (an Intent extra, a URI query parameter, a `@JavascriptInterface` bridge) and a "sink" pattern (`WebView.loadUrl`, a raw SQL call, a shell exec) found in the **same method body**. This is **not real data-flow analysis**: there's no proof the value from the source actually reaches the sink, just textual co-occurrence in one method — always reported as `REVIEW`, never `FINDING`, and meant purely to point at methods worth reading by hand
- **Signing** — v1‑only signature scheme (vulnerable to Janus, CVE‑2017‑13156), via `apksigner`
- **Dependency** — known CVEs in embedded Maven libraries, via OSV.dev (with `--cve`)
- **Semgrep** (with `--semgrep <rules-dir>`) — whatever the supplied ruleset flags, merged into the same report and severity scale
- **Hardening (absence)** — missing certificate pinning, missing root detection, `AndroidKeyStore` not used, missing `FLAG_SECURE`, missing tapjacking mitigation (`filterTouchesWhenObscured`), no explicit `networkSecurityConfig`

Reference baseline documented in the script header and in the report (current AGP/Kotlin/target SDK), used only as informational context, not as a failing rule.

## CVE phase (`--cve`)

Extracts `groupId:artifactId@version` coordinates of Maven libraries from the APK (`*.version` files and `pom.properties` in `META-INF/`) and queries them in batch against `https://api.osv.dev/v1/querybatch`, then fetches the detail (CVE ID, severity, fixed version) for each vulnerable library.

- Requires an outbound network connection to `api.osv.dev`. Without network, the phase is skipped with a message (`CVE: cannot reach OSV.dev (...). CVE phase skipped.`) and the rest of the scan proceeds normally.
- For **offline or air-gapped CI use**, use `--cve-mock <file>` with a JSON dump in the format `{"group:artifact@version": [<OSV vuln>, ...]}`.
- **macOS note**: if your `python3` comes from the python.org installer (not Homebrew), HTTPS requests can fail with `CERTIFICATE_VERIFY_FAILED` until you run `Install Certificates.command` once (found in `/Applications/Python 3.x/`). The script still attempts an automatic fallback using `certifi`'s certificate bundle, if the package is installed (`pip install certifi`).
- The report always shows a `Dependency`/`INFO` status row summarizing what the phase actually did — libraries checked, vulnerable, or why it was skipped. Without `--cve` at all, the row instead says the check wasn't run.

## Semgrep phase (`--semgrep <rules-dir>`)

`apk-secscan.sh` doesn't ship a bundled Semgrep ruleset (you choose and own the rules), but the decompiled-source layout it produces is exactly what community Android/Java Semgrep rulesets expect: run `semgrep --config <rules-dir> <sources-dir>` yourself once to sanity-check a ruleset, then point `--semgrep` at the same directory to have it run automatically as part of every scan, with results merged into the unified report (category `Semgrep`, severity mapped from Semgrep's `ERROR`/`WARNING`/`INFO`, always type `REVIEW`).

- If `semgrep` isn't installed, or the rules path doesn't exist, the phase is skipped with a clear warning and an `INFO` status row — it never fails the whole scan.
- Entirely offline once you have a local ruleset — no network call is made by this phase itself.
- Without `--semgrep`, the status row says the check wasn't run.

## SARIF export (`-f sarif`)

[SARIF](https://docs.github.com/en/code-security/concepts/code-scanning/sarif-files) is the standard JSON format most code-scanning integrations (GitHub Code Scanning included) understand. Each category becomes a SARIF `rule`, severity maps to SARIF `level` (`CRITICAL`/`HIGH` → `error`, `MEDIUM` → `warning`, `LOW`/`INFO` → `note`), and file/line become the result's physical location — so a scan can be uploaded directly as a code-scanning result set.

## The HTML report

The `html` format generates a **single self-contained file** (no external dependencies, no network calls): the source code of the lines involved in findings is embedded in the file itself for the preview, within a budget of ~6&nbsp;MB / 600 files.

The layout is a narrow **left sidebar** holding every control (severity, type, category, search, actions, legend) with the **findings table filling the rest of the width and the full viewport height** — no horizontal space is wasted on a header/toolbar strip above the data. The sidebar itself is **resizable** (drag its right edge). The table uses **virtualized ("windowed") rendering**: regardless of whether a scan produces a hundred or a hundred thousand rows, only the handful currently visible in the viewport are ever real DOM nodes — the rest exist purely as data in memory and are drawn on the fly as you scroll. This is what lets a report with tens of thousands of findings stay smooth and open instantly, instead of freezing the browser while it tries to lay out one `<tr>` per row.

Features:

- filter by **severity**, **type** (`FINDING`/`REVIEW`/`INFO`) and **category** (dynamic chips with counts, with "All"/"None" shortcuts) — Category is collapsed by default (showing an "N/M selected" summary) to keep the sidebar compact with scans that produce many categories
- full‑text search that filters both **what to show and what to hide**: plain words are an AND of include terms, and a `-word` term excludes any row containing it (e.g. `-network trustmanager`) — on top of unchecking a severity/type/category chip, which already hides that whole group
- an **interactive severity bar**: hover a severity segment to preview-dim the other rows currently on screen (no filters touched), click it to actually isolate that severity (checks only it, unchecks the rest) — a one-click way to jump straight to, say, every `CRITICAL` finding
- **sortable columns**: click a header to sort (click again to reverse), with a ▲/▼ indicator; the Sev column sorts by actual severity, not alphabetically
- **resizable columns** (drag the border, double-click to auto-fit)
- a **hover readout** on truncated cells (title/file/match): a styled panel with the full text near the cursor, instead of relying on the browser's native tooltip
- **CSV export** of only the rows currently visible (respects the active filters) — useful for extracting a subset without re-running the scan
- click a row → side drawer with a **source file preview**, syntax highlighting, and the **exact reported line highlighted** (toggle it off with the "Highlight" button if it's in the way), regex search with match navigation, copy file path
- inside the drawer, when a file has more than one finding, **`j`/`k` (or the ‹/› buttons) step to the next/previous finding in that same file** without closing the preview
- the last row you opened stays quietly marked (a thin notch on its severity edge) even after you close the drawer and keep scrolling — useful to keep your place in a long list
- word-wrap mode (the "Wrap" button) renders every filtered row at once rather than just the visible window, since wrapped rows no longer share a uniform height — on very large result sets, filter down first for the smoothest experience
- a **Reset** button clears every filter, the search box and any active sort in one click
- printing (Ctrl/Cmd+P) renders every currently-filtered row, not just the ones on screen

No text in the report renders below 11px. Keyboard focus (Tab) is visible throughout, and every row is reachable and openable from the keyboard (Enter/Space).

> **Warning**: the HTML report embeds portions of the scanned app's real source code and can contain real secrets in `CRITICAL` findings. Treat it as sensitive material: don't commit it to a public repository and don't share it without first reviewing/removing confidential content. The project's `.gitignore` excludes locally-generated `secscan-*` files by default.

## CI usage

```bash
./apk-secscan.sh --fail-on high -f json -o ./out app.apk || exit 1
```

With `--fail-on <threshold>` the script exits with code **2** if at least one `type=FINDING` result with severity ≥ threshold exists; otherwise it exits with **0**. `REVIEW`/`INFO` results never affect the exit code, since by definition they require manual verification. Use `-f sarif` if the CI platform can ingest SARIF (e.g. GitHub code scanning).

## Limitations

- **Static** analysis: it doesn't run the app, and doesn't detect behavior that depends purely on remote/runtime configuration (`REVIEW` results exist precisely to flag what to verify by hand).
- Heavily obfuscated/minified code reduces the effectiveness of patterns based on known class/method names. jadx output is frequently not valid, compilable Java — this is why the detection engine is pattern/heuristic-based (bash + ripgrep + a couple of Python passes) rather than a full AST/bytecode analyzer: tools that require a real Java parser or JVM bytecode (PMD, Error Prone, SpotBugs) generally can't run reliably on decompiled DEX output.
- The **Taint** category is a textual heuristic (same-method source/sink co-occurrence), not real inter-procedural data-flow analysis. For actual taint tracking across the whole call graph, use a dedicated tool (e.g. FlowDroid, Amandroid) directly on the APK — that's a fundamentally different, much heavier analysis this script doesn't attempt to replicate.
- The **Packer** category only fingerprints known filenames/assets; it doesn't unpack or analyze what a packer is protecting.
- Regex patterns can produce **false positives** (hence the FINDING/REVIEW/INFO distinction) and, in theory, false negatives on uncovered variants.
- It doesn't replace a manual penetration test or a full code review: it's meant as a **fast first pass**, optionally extended with your own Semgrep rules for anything project-specific.
