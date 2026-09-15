# Case Study: Breaking a Self-Healing WordPress Reinfection Loop

## The situation

A client came in with four WordPress sites on shared cPanel hosting, all showing signs of compromise, two of which had already been reinfected multiple times despite repeated manual cleanups. Wordfence and CleanTalk were both installed and running scheduled scans on the affected sites throughout — neither detected or stopped the infection.

To bring the scope under control, the client removed two of the four sites entirely (files and database) early in the engagement, leaving two — referred to here as **Client Site A** and **Client Site B** — to fully diagnose and remediate.

## First pass: the files looked clean, and that was the problem

An 18-check filesystem scanner (`wpscan.sh` in this repo) was built and run against `wp-content` on both sites: drop-in files, mu-plugins, webshell signatures, obfuscated code blobs, dangerous `.htaccess`/`.user.ini` directives, and more.

Both sites came back clean. Every finding that did surface — an `extract()` call in Elementor Pro, long CamelCase vendor filenames, a security plugin's own historical log entry — turned out, on inspection, to be a false positive with a specific, verifiable explanation.

That result didn't match the client's actual experience of repeated reinfection. Something the file scan couldn't see was still there.

## Second pass: the database was the real infection site

A second scanner (`wpdbscan.sh`) was built to audit the database directly — WP-Cron hooks, capability injection, code-like payloads stored in `wp_options`, and stored code-snippet plugin content.

This is where the infection actually was. On Client Site B's database:

- **31 malware-owned options**, including an ~860KB encoded payload sitting in `wp_options`
- **Two self-healing cron hooks** (`sc_cron_guard`, `sc_cron_fetch`) rescheduling every 10 minutes
- **Command-and-control addresses resolved through an on-chain RPC endpoint** rather than a fixed domain — meaning takedown of any single domain would not disable it
- **An administrator account created days earlier**, using a name pattern designed to look like a legitimate site backup (`backup_<hex>`)
- **The malware's own internal manifest of every file it had planted** — recorded as a database option, evidently used by the malware itself to verify and restore its own files

That last item was the breakthrough. Rather than continuing to guess which files might be compromised, the malware had already written down its own target list.

## Why file scans alone kept failing

Cross-referencing the recovered manifest against the live filesystem explained the reinfection loop precisely. The infection used five independent, mutually-reinforcing persistence layers:

| Layer | Mechanism |
|---|---|
| **Drop-ins** | `db.php`, `advanced-cache.php`, `object-cache.php` — auto-loaded by WordPress core with no entry in any config file or plugin list |
| **mu-plugin** | Runs on every request; cannot be disabled from wp-admin |
| **Duplicate plugin entry** | A second copy of the same code, registered as an ordinary plugin |
| **Active theme injection** | The site's real, active theme's `functions.php` had code appended. The malware even stored a hash and byte-for-byte copy of the *original* file in the database, apparently to defeat naive diffing or restore it during evasion |
| **Hidden directory** | A dot-prefixed directory (invisible to a plain `ls`) holding staging files |

Delete any one layer — or even all the file-based layers — and the database-resident payload and cron hooks would simply rewrite them on the next request. This is why manual, file-only cleanup had failed repeatedly before this engagement.

## Remediation

1. **Evidence preservation** — full database export taken before any destructive action, plus the malware's own option values (manifest, payload, C2 config) extracted to a separate file for reference
2. **Verification against source** — the injected theme's live file was hash-compared against the malware's own stored "pristine" copy; matched exactly, confirming the theme had already been swapped back to clean, but it was reinstalled from wordpress.org anyway rather than trusted
3. **Database cleanup** — all `sc_*` malware options removed, cron array reset, `active_plugins` cleared (plugins reactivated manually afterward, deliberately, rather than trusting the stored list), backdoor administrator account deleted
4. **Core & plugin integrity** — `wp core verify-checksums` and `wp plugin verify-checksums` run against wordpress.org to confirm every core and plugin file matched upstream byte-for-byte
5. **Fresh credentials** — new database password, new WordPress salts, new admin passwords for every legitimate account, generated only after the database was confirmed clean (connecting a fresh config to an uncleaned database would have restarted the whole cycle)
6. **Hardening** — `DISALLOW_FILE_EDIT` enabled, PHP execution blocked inside `wp-content/uploads/`, direct access blocked for archive and dump file extensions, directory listing disabled account-wide
7. **Verification pass** — both scanners re-run post-cleanup and again after a period of live traffic, confirming zero critical findings

## Incidental findings along the way

Three unrelated public exposures were found and closed during the engagement, none of which the client had been aware of:

- A full site backup folder left inside the public web root, directly downloadable
- A `wp-content.zip` archive sitting in a live document root
- An 870MB infected site-migration archive left inside a quarantined copy's `wp-content` — never restored, moved outside the web root

## Result

Both sites restored to production on checksum-verified core, scanned clean at both the file and database layer, with hardening in place to close the specific vectors this infection depended on. The client retained both scanner scripts for ongoing self-service auditing.

## Lesson

A WordPress malware family with a documented history of surviving repeated cleanups had one specific reason it kept surviving: cleanup only ever addressed the layer that happened to be visible. The fix was not a better file scanner — it was recognizing that the infection had two independent storage locations, and refusing to declare victory until both had been individually and separately verified.
