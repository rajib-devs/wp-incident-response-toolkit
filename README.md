# WordPress Incident Response Toolkit

Two read-only Bash scanners built during a live incident-response engagement against a persistent, self-healing WordPress malware family. Both are safe to run on production: they only ever `SELECT` / read — nothing is modified, moved, or deleted.

- **`wpscan.sh`** — 18-check filesystem scanner for a WordPress `wp-content` directory
- **`wpdbscan.sh`** — 14-check database scanner (WP-Cron hooks, capability injection, stored payloads, WPCode/code-snippet plugins)

See [`docs/CASE-STUDY.md`](docs/CASE-STUDY.md) for the full incident writeup — how the infection was found, what made it survive repeated cleanups, and how it was finally removed.

## Why two scanners

The infection this toolkit was built against split itself across two places that don't get checked together:

- **Files** — drop-ins (`db.php`, `object-cache.php`, `advanced-cache.php`), an mu-plugin, a duplicate plugin copy, and a hidden dot-directory.
- **Database** — the actual payload, C2 configuration, and self-healing cron hooks, stored entirely in `wp_options`.

Scanning only the filesystem — which is what most tools do, and what the site's active security plugins were doing — misses the second half completely. Files can be wiped clean and the malware simply rewrites itself from the database on the next page load. Both scanners are meant to run together.

## Requirements

- Bash (any shared-hosting cPanel/SSH shell works)
- `wpscan.sh`: just core utilities (`find`, `grep`, `stat`) — no dependencies
- `wpdbscan.sh`: either [WP-CLI](https://wp-cli.org/) **or** a plain `mysql`/`mariadb` client. It tries WP-CLI first and falls back automatically.

## Usage

### File scanner

```bash
bash wpscan.sh /path/to/site/wp-content [output-file]
```

Or point it at a site root — it steps into `wp-content` automatically:

```bash
bash wpscan.sh /path/to/site
```

Control how far back "recently modified" looks (default 45 days):

```bash
SCAN_DAYS=90 bash wpscan.sh /path/to/site
```

### Database scanner

With a working `wp-config.php` in the site directory:

```bash
bash wpdbscan.sh /path/to/wordpress [output-file]
```

Or scan a database directly — no WordPress install needed (useful mid-rebuild, when `wp-config.php` has been intentionally removed to stop reinfection):

```bash
bash wpdbscan.sh --db DATABASE_NAME [--path /path/to/site] [output-file]
```

Direct mode reads credentials from `~/.my.cnf` (`[client]` section) so a database password is never typed on the command line or left in shell history.

Both scripts write a full report to `~/wpscan-<name>-<timestamp>.txt` / `~/wpdbscan-<name>-<timestamp>.txt` and print a pass/fail summary table to the screen.

## Reading the output

Each finding is graded:

| Grade | Meaning |
|---|---|
| **CRITICAL** | Should be empty on a clean install. Any row here needs reading before you dismiss it. |
| **WARNING** | Expected to have some rows on every install (admin accounts, active plugins, the full cron list). Read for anything unrecognized, don't panic at a nonzero count. |
| **INFO** | Baseline inventory for comparison. |

The verdict line (`INFECTED` / `LIKELY CLEAN` / `CLEAN`, or `REVIEW REQUIRED` for the DB scanner) is a starting point, not a final answer — a few CRITICAL sections are known to have legitimate causes (see below). Read the matched rows before concluding anything.

## Known false positives

Both scanners are pattern-based, so they will occasionally flag legitimate code. Documented cases hit during real use:

- `extract($__view_data, ...)` in Elementor Pro — matched a superglobal-extraction pattern because `$__view_data` also starts with `$_`
- Long CamelCase vendor class names (`ApplicationDefaultCredentials.php`) — matched a "random filename" heuristic
- `FilesMan` substring inside unrelated method names (`countFilesMandatory`)
- Empty 0-byte `index.php` guard files in `uploads/`
- `upgrade-temp-backup/` — created by WordPress core itself (6.3+) during plugin updates
- A security plugin's own historical log entry containing a malware version string as serialized log data, not live code

None of these should be taken as blanket exclusions — each was individually verified by reading the actual matched content before being dismissed. Always do the same.

## What these are not

- Not a replacement for a security plugin's real-time protection — this is a point-in-time forensic sweep
- Not an automatic cleaner — every finding is meant to be read and understood before anything is deleted
- Not a guarantee — a scanner can only catch patterns it knows about; the case study describes at least one persistence layer (a database-stored WPCode/`insert-headers-and-footers` snippet running arbitrary PHP) that no filesystem scan could ever see, which is exactly why the DB scanner exists

## License

MIT — see [LICENSE](LICENSE).
