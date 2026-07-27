# apk-secscan

Tool a riga di comando (un unico script bash) per la **revisione di sicurezza statica di APK Android**. Decompila l'APK, cerca pattern di rischio nel codice/risorse e produce un report navigabile con i risultati classificati per severità.

Pipeline: **jadx** (decompilazione) → **ripgrep/grep** (pattern statici) → **apksigner / aapt2 / strings** (controlli opzionali sul binario) → report in **CSV / JSON / XML / HTML**.

## Filosofia

Ogni risultato è etichettato con un `type` per separare tre livelli di certezza, ed evitare di trattare un "odore" di sicurezza come se fosse una prova:

| Type | Significato |
|---|---|
| `FINDING` | evidenza confermata (es. una chiave privata hardcoded, `debuggable=true`) |
| `REVIEW`  | superficie da verificare a runtime (es. un flag di cleartext traffic, un componente esportato) |
| `INFO`    | identificatore pubblico, non una vulnerabilità (es. una Google API key pubblica, un DSN Sentry) |

Ogni riga ha anche una `severity` (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) e una `category` (`Secrets`, `Network`, `WebView`, `Storage`, `Crypto`, `Manifest`, `Dependency`, `Assets`, ecc.).

## Requisiti

Obbligatori:

- **bash** (macOS/Linux; lo script evita array associativi per restare portabile su bash datato)
- **jadx** — decompilatore APK (non serve se usi `--skip-decompile`)
- **python3** — genera i report, la fase CVE e l'analisi degli assets
- **grep con supporto PCRE (`-P`)** — su macOS il grep di sistema è BSD e non lo supporta: serve il GNU grep di Homebrew (binario `ggrep`)
- **xargs**

Opzionali:

- **ripgrep (`rg`)** — motore di ricerca più veloce; se assente si usa il grep PCRE trovato sopra
- **apksigner** — verifica gli schemi di firma (rileva Janus, CVE‑2017‑13156)
- **aapt / aapt2** — estrae package name e `targetSdkVersion`
- **unzip** e **strings** — richiesti solo con `--native`, per estrarre ed ispezionare `lib/*.so` e `assets/*`

Esegui `./apk-secscan.sh --deps` per una diagnosi interattiva di cosa è presente/mancante sul tuo sistema, coi comandi di installazione per macOS (brew) e Linux (apt).

### Installazione rapida (macOS)

```bash
brew install jadx ripgrep grep          # grep fornisce ggrep (GNU, supporto -P)
brew install --cask android-commandlinetools
sdkmanager "build-tools;35.0.0"         # per apksigner/aapt2
```

### Installazione rapida (Linux/Debian)

```bash
sudo apt install python3 xargs findutils ripgrep unzip binutils
# jadx: scarica la release da github.com/skylot/jadx (o "apt install jadx" se disponibile)
# apksigner/aapt: Android SDK build-tools
```

## Uso

```bash
./apk-secscan.sh [opzioni] <app.apk>
```

Esempi:

```bash
# scansione completa, tutti i formati di report
./apk-secscan.sh app.apk

# solo il codice dell'app (esclude le librerie terze parti), solo report HTML
./apk-secscan.sh -s app -f html app.apk

# includi anche il controllo CVE sulle dipendenze note (richiede rete) e i controlli sulle .so native
./apk-secscan.sh --cve --native app.apk

# riusa una decompilazione jadx già fatta, senza rilanciare jadx
./apk-secscan.sh --skip-decompile ./workdir-precedente app.apk

# uso in CI: fallisce (exit 2) se c'è almeno un FINDING >= HIGH
./apk-secscan.sh --fail-on high --format json -o ./out app.apk
```

### Opzioni

| Opzione | Descrizione |
|---|---|
| `-s, --scope app\|libs\|all` | ambito del codice da scansionare (default `all`). `app` = solo il package dell'app, `libs` = solo librerie terze, `all` = tutto. Manifest, risorse, firma e i controlli di assenza coprono **sempre** l'intero APK, indipendentemente dallo scope. |
| `-f, --format csv\|json\|xml\|html\|all` | formato/i di output (default `all`) |
| `-o, --output <dir>` | cartella di output (default `./secscan-<apk>-<timestamp>`) |
| `-p, --app-package <pkg>` | forza il package dell'app (bypassa l'autodetect da manifest/aapt) |
| `--native` | scansiona anche le librerie native (`.so`) con `strings`, cercando segreti embedded |
| `--cve` | verifica le CVE note delle librerie via [OSV.dev](https://osv.dev) (richiede rete) |
| `--cve-max <n>` | numero massimo di librerie interrogate su OSV (default 400) |
| `--cve-mock <file>` | usa un dump OSV salvato invece della rete (uso offline/CI) — implica `--cve` |
| `--fail-on none\|low\|medium\|high\|critical` | exit code 2 se esiste un `FINDING` ≥ soglia (per CI; default `none` → sempre exit 0) |
| `--jadx <path>` | percorso del binario jadx |
| `--keep` | mantiene la cartella di lavoro della decompilazione (non la cancella a fine scan) |
| `--skip-decompile <dir>` | riusa una cartella jadx già esistente (nessuna ri-decompilazione) |
| `--deps` | elenca i tool di sistema usati (presenti/mancanti + comando di installazione) |
| `-h, --help` | aiuto |

## Cosa viene controllato

Pattern statici su sorgenti decompilati, risorse e manifest, tra cui:

- **Secrets** — chiavi private PEM, service account Google, chiavi Stripe/AWS/Slack/GitHub/Twilio/OAuth, JWT hardcoded, password/secret hardcoded (CRITICAL)
- **Network** — `TrustManager`/`HostnameVerifier` permissivi, endpoint in cleartext HTTP, `usesCleartextTraffic`, network security config con `cleartextTrafficPermitted` o trust-anchor utente
- **WebView** — `addJavascriptInterface`, JavaScript abilitato, accesso universale da `file://`
- **Manifest** — `debuggable=true`, `allowBackup=true`, componenti `exported=true`, deep link, permessi pericolosi
- **Crypto** — AES in ECB, algoritmi deboli (DES/RC4/Blowfish), hash deboli (MD5/SHA‑1), IV statici/RNG insicuro
- **Storage / Logging / IPC / SQL** — SharedPreferences con chiavi sensibili in chiaro, scritture su storage esterno, log potenzialmente sensibili, `PendingIntent` senza `FLAG_IMMUTABLE`, query SQL costruite per concatenazione, `grantUriPermission`
- **Exec / DynamicCode** — `Runtime.exec`/`ProcessBuilder`, `DexClassLoader` e affini
- **Assets/Anomaly** — materiale crittografico o keystore nei bundle, database pre-caricati, possibili leak di codice sorgente, artefatti di sviluppo (`.git/`, `.idea/`, ecc.) rimasti nel pacchetto
- **Signing** — schema di firma v1‑only (vulnerabile a Janus, CVE‑2017‑13156), via `apksigner`
- **Dependency** — CVE note delle librerie Maven embedded, via OSV.dev (con `--cve`)
- **Hardening (assenza)** — certificate pinning assente, root detection assente, `AndroidKeyStore` non usato, `FLAG_SECURE` assente

Baseline di riferimento documentata nell'header dello script e nel report (AGP/Kotlin/target SDK correnti), usata solo come contesto informativo, non come regola di failing.

## Fase CVE (`--cve`)

Estrae le coordinate `groupId:artifactId@version` delle librerie Maven dall'APK (file `*.version` e `pom.properties` in `META-INF/`) e le interroga in batch su `https://api.osv.dev/v1/querybatch`, poi recupera il dettaglio (ID CVE, severity, versione con fix) per ogni libreria vulnerabile.

- Richiede una connessione di rete in uscita verso `api.osv.dev`. In assenza di rete la fase viene saltata con un messaggio (`CVE: cannot reach OSV.dev (...). CVE phase skipped.`) e il resto della scansione prosegue normalmente.
- Per uso **offline o in CI air-gapped**, usa `--cve-mock <file>` con un dump JSON nel formato `{"gruppo:artefatto@versione": [<vuln OSV>, ...]}`.
- **Nota macOS**: se il tuo `python3` viene dall'installer di python.org (non da Homebrew), le richieste HTTPS possono fallire con `CERTIFICATE_VERIFY_FAILED` finché non esegui una volta `Install Certificates.command` (si trova in `/Applications/Python 3.x/`). Lo script tenta comunque un fallback automatico usando il bundle di certificati di `certifi`, se il pacchetto è installato (`pip install certifi`).

## Il report HTML

Il formato `html` genera un **singolo file autonomo** (nessuna dipendenza esterna, nessuna chiamata di rete): tutto il codice sorgente delle righe con findings viene incorporato nel file stesso per la preview, entro un budget di ~6&nbsp;MB / 600 file.

Funzionalità:

- filtro per **severità**, **tipo** (`FINDING`/`REVIEW`/`INFO`) e **categoria** (chip dinamiche coi conteggi, con scorciatoie "All"/"None")
- casella di ricerca full‑text su titolo/file/match (scorciatoia da tastiera **`/`** per metterci il focus)
- **colonne ordinabili**: click sull'intestazione per ordinare (di nuovo per invertire), con indicatore ▲/▼; la colonna Sev ordina per severità reale, non alfabeticamente
- colonne **ridimensionabili** (trascina il bordo, doppio click per auto-fit)
- **export CSV** delle sole righe attualmente visibili (rispetta i filtri applicati) — utile per estrarre un sottoinsieme senza rilanciare la scansione
- click su una riga → drawer laterale con **preview del file sorgente**, syntax highlight, ricerca regex con navigazione tra i match, copia del percorso file

> **Attenzione**: il report HTML incorpora porzioni di codice sorgente reale dell'app scansionata e può contenere segreti reali nei findings `CRITICAL`. Trattalo come materiale sensibile: non committarlo in un repository pubblico e non condividerlo senza prima aver verificato/rimosso i contenuti riservati. Il `.gitignore` del progetto esclude di default i file `secscan-*` generati in locale.

## Uso in CI

```bash
./apk-secscan.sh --fail-on high -f json -o ./out app.apk || exit 1
```

Con `--fail-on <soglia>` lo script esce con codice **2** se esiste almeno un risultato `type=FINDING` con severità ≥ soglia; altrimenti esce con **0**. I risultati `REVIEW`/`INFO` non incidono mai sull'exit code, perché per definizione richiedono una verifica manuale.

## Limitazioni

- Analisi **statica**: non esegue l'app, non rileva comportamenti che dipendono solo da configurazione remota/runtime (i `REVIEW` esistono apposta per segnalare cosa verificare a mano).
- Codice fortemente offuscato/minificato riduce l'efficacia dei pattern basati su nomi di classi/metodi noti.
- I pattern regex possono generare **falsi positivi** (per questo la distinzione FINDING/REVIEW/INFO) e, in teoria, falsi negativi su varianti non coperte.
- Non sostituisce un penetration test manuale o una code review completa: è pensato come **prima passata rapida**.
