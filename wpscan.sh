#!/bin/bash
#=====================================================================
#  WordPress wp-content Malware Scanner   v2.1
#
#  Usage:   bash wpscan.sh /path/to/wp-content  [output-file]
#           bash wpscan.sh /path/to/site-root   [output-file]
#
#  Read-only. Never modifies, moves or deletes anything.
#=====================================================================

TARGET="$1"
OUT="$2"
DAYS="${SCAN_DAYS:-45}"

if [ -z "$TARGET" ]; then
    echo "Usage: bash wpscan.sh /path/to/wp-content [output-file]"
    exit 1
fi

# Accept a site root and step into wp-content automatically
[ -d "$TARGET/wp-content" ] && TARGET="$TARGET/wp-content"

if [ ! -d "$TARGET" ]; then
    echo "ERROR: not a directory: $TARGET"
    exit 1
fi

TARGET="$(cd "$TARGET" && pwd)"
SITE="$(basename "$(dirname "$TARGET")")"
[ -z "$OUT" ] && OUT="$HOME/wpscan-${SITE}-$(date +%Y%m%d-%H%M%S).txt"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cd "$TARGET" || exit 1

N=0
META="$TMP/meta"
: > "$META"

# Register a finished check:  reg <severity> <title> <file> <hint>
reg() {
    N=$((N + 1))
    cp "$3" "$TMP/$N.out"
    printf '%s|%s|%s\n' "$1" "$2" "$4" >> "$META"
}

# Vendor paths that legitimately contain scary-looking code
NOISE='/plugins/wordfence/|/wflogs/|/phpseclib/|/monolog/|/symfony/|/guzzlehttp/|/twig/|/paragonie/|/composer/|/sodium_compat/|/polyfill|/vendor_prefixed/|/apiclient|/node_modules/|/cmb2/|/wp-background-processing/'

GREPOPT="-rl --include=*.php --exclude-dir=node_modules"

echo "Scanning $TARGET ..." >&2

#---------------------------------------------------------------------
# 1. DROP-INS  (auto-loaded by WordPress core with no config entry)
#---------------------------------------------------------------------
: > "$TMP/w"
for f in db.php object-cache.php advanced-cache.php sunrise.php \
         install.php maintenance.php fatal-error-handler.php db-error.php; do
    [ -f "$f" ] && ls -la "$f" >> "$TMP/w"
done
reg CRITICAL "WordPress drop-ins present" "$TMP/w" \
    "These load on every request with no entry in wp-config or .htaccess. This is how the SC malware persisted. Any file here must be justified."

#---------------------------------------------------------------------
# 2. MU-PLUGINS
#---------------------------------------------------------------------
: > "$TMP/w"
if [ -d mu-plugins ]; then
    find mu-plugins -maxdepth 1 -type f ! -name index.php 2>/dev/null > "$TMP/w"
fi
reg CRITICAL "mu-plugins contents" "$TMP/w" \
    "Must-use plugins auto-activate and cannot be disabled from wp-admin. Expect this to be empty."

#---------------------------------------------------------------------
# 3. EXECUTABLE FILES IN UPLOADS
#---------------------------------------------------------------------
: > "$TMP/w"
[ -d uploads ] && find uploads -type f \( -iname '*.php' -o -iname '*.php[0-9]' \
    -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.phps' -o -iname '*.pht' \
    -o -iname '*.shtml' -o -iname '*.cgi' -o -iname '*.pl' -o -iname '*.suspected' \
    \) ! \( -name 'index.php' -size -200c \) 2>/dev/null > "$TMP/w"
reg CRITICAL "Executable files inside uploads/" "$TMP/w" \
    "uploads/ should contain media only. Empty index.php guards are normal; anything with real code is a webshell."

#---------------------------------------------------------------------
# 4. SC-FAMILY MARKERS  (this specific infection)
#---------------------------------------------------------------------
grep $GREPOPT -e 'SCV:' -e 'SC_DB_BEGIN' -e 'SC_TH_BEGIN' -e 'SC_DD_BEGIN' \
    -e 'SC_TH_LD_' -e 'SC_WC' -e 'lumen-provider' -e 'sc_cron_guard' \
    -e 'sc_cron_fetch' -e 'Cipher Optimizer' . 2>/dev/null | sort -u > "$TMP/w"
reg CRITICAL "Known SC-family malware markers" "$TMP/w" \
    "Direct fingerprints of the infection. Hits inside wordfence/wflogs are usually its scan-signature database, not live malware - check context before panicking."

#---------------------------------------------------------------------
# 5. HIGH-CONFIDENCE WEBSHELL SIGNATURES
#---------------------------------------------------------------------
grep $GREPOPT -E \
 "eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|stripslashes|\\\$_(GET|POST|REQUEST|COOKIE))|assert[[:space:]]*\([[:space:]]*\\\$_(GET|POST|REQUEST|COOKIE)|\\\$_(GET|POST|REQUEST|COOKIE)[[:space:]]*\[[^]]*\][[:space:]]*\(|FilesMan|WSOsetcookie|wso_version|b374k|r57shell|c99shell|IndoXploit|preg_replace[[:space:]]*\([[:space:]]*['\"][^'\"]*['\"][a-z]*e[a-z]*['\"]|\\\$\{[[:space:]]*['\"]_(GET|POST|REQUEST)|edoced_46esab|extract[[:space:]]*\([[:space:]]*\\\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)" \
 . 2>/dev/null | sort -u > "$TMP/w"
reg CRITICAL "High-confidence webshell signatures" "$TMP/w" \
    "These patterns have essentially no legitimate use in a WordPress plugin. Treat every hit as a backdoor until proven otherwise."

#---------------------------------------------------------------------
# 6. LARGE ENCODED BLOBS
#---------------------------------------------------------------------
grep $GREPOPT -E "['\"][A-Za-z0-9+/=]{400,}['\"]" . 2>/dev/null \
    | grep -vE "$NOISE" | sort -u > "$TMP/w"
reg CRITICAL "Large base64-style blobs (400+ chars)" "$TMP/w" \
    "Staged payloads look like this. The original db.php carried a 175,000-character base64 string. Fonts and inline images can also match - check what the string decodes to."

#---------------------------------------------------------------------
# 7. DANGEROUS PHP/SERVER DIRECTIVES
#---------------------------------------------------------------------
: > "$TMP/w"
find . \( -name '.htaccess' -o -name '.user.ini' -o -name 'php.ini' \) 2>/dev/null \
| while IFS= read -r f; do
    h="$(grep -nEi 'auto_prepend_file|auto_append_file|AddHandler|AddType[[:space:]]+application/x-httpd|SetHandler|php_value|php_flag|Action[[:space:]]+application/x-httpd' "$f" 2>/dev/null)"
    [ -n "$h" ] && { echo "--- $f"; echo "$h"; }
done > "$TMP/w"
reg CRITICAL "Dangerous .htaccess / .user.ini directives" "$TMP/w" \
    "auto_prepend_file forces a file to run before every request, entirely outside WordPress. AddHandler/AddType can make .jpg files execute as PHP."

#---------------------------------------------------------------------
# 8. LOOSE PHP FILES AT THE TOP OF plugins/
#---------------------------------------------------------------------
: > "$TMP/w"
[ -d plugins ] && find plugins -maxdepth 1 -type f -name '*.php' \
    ! -name 'index.php' ! -name 'hello.php' 2>/dev/null > "$TMP/w"
reg CRITICAL "Loose .php files directly in plugins/" "$TMP/w" \
    "Real plugins live in their own folder. A bare .php file here is a classic single-file backdoor."

#---------------------------------------------------------------------
# 9. RANDOM-LOOKING FILENAMES
#---------------------------------------------------------------------
find . -type f -name '*.php' 2>/dev/null | grep -vE "$NOISE" \
| grep -E '/([a-f0-9]{8,32}|[a-z]{6,}[0-9]{3,}[a-z0-9]*)\.php$' \
| sort -u > "$TMP/w"
reg WARNING "Random-looking PHP filenames" "$TMP/w" \
    "Malware drops files named with random hex (e.g. 773640a1.php). Minified vendor files can also match."

#---------------------------------------------------------------------
# 10. OBFUSCATED LONG LINES
#---------------------------------------------------------------------
find . -type f -name '*.php' -print0 2>/dev/null \
| xargs -0 awk 'length>2000 {print FILENAME"  line "FNR"  ("length" chars)"}' 2>/dev/null \
| grep -vE "$NOISE" | awk '!seen[$1]++' | head -60 > "$TMP/w"
reg WARNING "Very long lines (possible obfuscation)" "$TMP/w" \
    "Vendor data tables (Unicode maps, crypto constants, icon sets) legitimately do this. A long line in a small plugin file does not."

#---------------------------------------------------------------------
# 11. SUSPICIOUS FUNCTIONS - TRIAGE LIST
#---------------------------------------------------------------------
grep $GREPOPT -E \
 "eval[[:space:]]*\(|assert[[:space:]]*\(|create_function|gzinflate|gzuncompress|str_rot13[[:space:]]*\(|shell_exec|passthru|proc_open|popen[[:space:]]*\(|\bsystem[[:space:]]*\(|\bexec[[:space:]]*\(|auto_prepend_file|ini_set[[:space:]]*\([[:space:]]*['\"]disable" \
 . 2>/dev/null | grep -vE "$NOISE" | sort -u > "$TMP/w"
reg WARNING "Suspicious functions (needs triage)" "$TMP/w" \
    "Legitimate plugins do use some of these. Judge by whether the file's purpose explains it."

#---------------------------------------------------------------------
# 12. NON-STANDARD ENTRIES AT THE TOP OF wp-content
#---------------------------------------------------------------------
ls -A . 2>/dev/null | grep -vxE 'plugins|themes|uploads|upgrade|upgrade-temp|upgrade-temp-backup|languages|cache|fonts|index\.php|\.htaccess|\.user\.ini|wflogs|ai1wm-backups|et-cache|w3tc-config|backup|backups|mu-plugins|updraft|wpvivid|litespeed|autoptimize|bps-backup|uploads-webpc|smush-webp|debug\.log|advanced-cache\.php|object-cache\.php|db\.php' > "$TMP/w"
reg WARNING "Unexpected items in wp-content root" "$TMP/w" \
    "Compare against what your plugins are known to create. Hidden dot-directories here (.sc_xxxxxxxx) were where the webshells hid."

#---------------------------------------------------------------------
# 13. HIDDEN FILES AND DIRECTORIES
#---------------------------------------------------------------------
find . -name '.*' ! -name '.' ! -name '..' ! -name '.htaccess' \
    ! -name '.gitignore' ! -name '.gitattributes' ! -name '.editorconfig' \
    ! -name '.jshintrc' ! -name '.eslintrc*' ! -name '.babelrc' \
    ! -name '.distignore' ! -name '.phpcs.xml*' ! -name '.travis.yml' \
    2>/dev/null | grep -vE "$NOISE" | sort | head -60 > "$TMP/w"
reg WARNING "Hidden files and directories" "$TMP/w" \
    "Most are harmless developer leftovers. Look for hidden DIRECTORIES containing .php files."

#---------------------------------------------------------------------
# 14. BACKUP ARCHIVES
#---------------------------------------------------------------------
find . -type f \( -iname '*.wpress' -o -iname '*.sql' -o -iname '*.sql.gz' \
    -o -iname '*.tar' -o -iname '*.tar.gz' -o -iname '*.tgz' -o -iname '*.zip' \
    -o -iname '*.gz' \) -size +1M 2>/dev/null \
    -exec ls -lh {} \; 2>/dev/null | head -40 > "$TMP/w"
reg WARNING "Backup archives inside wp-content" "$TMP/w" \
    "A backup taken while infected contains the full malware. Never restore one, and never leave one web-accessible."

#---------------------------------------------------------------------
# 15. WORLD-WRITABLE OR EXECUTABLE PHP
#---------------------------------------------------------------------
: > "$TMP/w"
find . -type f -perm -o+w 2>/dev/null | head -30 >> "$TMP/w"
find . -type f -name '*.php' -perm -u+x 2>/dev/null | head -30 >> "$TMP/w"
reg WARNING "World-writable or executable files" "$TMP/w" \
    "PHP files should be 644. World-writable files let any account on a shared server modify them."

#---------------------------------------------------------------------
# 16. SYMLINKS
#---------------------------------------------------------------------
find . -type l -exec ls -la {} \; 2>/dev/null | head -30 > "$TMP/w"
reg WARNING "Symbolic links" "$TMP/w" \
    "Attackers symlink to other users' files on shared hosting to read their wp-config.php."

#---------------------------------------------------------------------
# 17. RECENTLY MODIFIED PHP
#---------------------------------------------------------------------
find . -type f -name '*.php' -mtime -"$DAYS" 2>/dev/null \
    | grep -vE "$NOISE" | sort | head -80 > "$TMP/w"
reg INFO "PHP modified in the last $DAYS days" "$TMP/w" \
    "Cross-reference against when you actually updated plugins. Unexplained changes matter."

#---------------------------------------------------------------------
# 18. INVENTORY
#---------------------------------------------------------------------
{
    echo "-- PLUGINS --"
    [ -d plugins ] && ls -1 plugins/ 2>/dev/null
    echo
    echo "-- THEMES --"
    [ -d themes ] && ls -1 themes/ 2>/dev/null
    echo
    echo "-- PLUGINS WITH NO readme --"
    if [ -d plugins ]; then
        for d in plugins/*/; do
            [ -d "$d" ] || continue
            ls "$d" 2>/dev/null | grep -qiE '^readme' || echo "  ${d%/}"
        done
    fi
    echo
    echo "-- COUNTS --"
    echo "  PHP files : $(find . -name '*.php' -type f 2>/dev/null | wc -l)"
    echo "  All files : $(find . -type f 2>/dev/null | wc -l)"
    echo "  Disk used : $(du -sh . 2>/dev/null | cut -f1)"
} > "$TMP/w"
reg INFO "Inventory" "$TMP/w" \
    "A plugin folder with no readme is not automatically bad, but every fake plugin this malware created had none."

#=====================================================================
#  RENDER REPORT
#=====================================================================
CRIT=0; WARNC=0
i=0
while IFS='|' read -r sev title hint; do
    i=$((i + 1))
    c=$(grep -c . "$TMP/$i.out" 2>/dev/null); c=${c:-0}
    if [ "$c" -gt 0 ]; then
        [ "$sev" = "CRITICAL" ] && CRIT=$((CRIT + 1))
        [ "$sev" = "WARNING" ]  && WARNC=$((WARNC + 1))
    fi
done < "$META"

if [ "$CRIT" -gt 0 ]; then
    VERDICT="INFECTED  --  do not reuse this wp-content"
elif [ "$WARNC" -gt 0 ]; then
    VERDICT="LIKELY CLEAN  --  $WARNC section(s) need a human look"
else
    VERDICT="CLEAN  --  nothing flagged"
fi

{
echo "====================================================================="
echo " wp-content MALWARE SCAN REPORT"
echo "====================================================================="
echo " Target   : $TARGET"
echo " Host     : $(whoami)@$(hostname 2>/dev/null)"
echo " Date     : $(date)"
echo " Scanner  : wpscan.sh v2.1"
echo "---------------------------------------------------------------------"
echo " VERDICT  : $VERDICT"
echo "---------------------------------------------------------------------"
echo " SUMMARY"

i=0
while IFS='|' read -r sev title hint; do
    i=$((i + 1))
    c=$(grep -c . "$TMP/$i.out" 2>/dev/null); c=${c:-0}
    if [ "$c" -eq 0 ]; then
        mark="  ok  "
    elif [ "$sev" = "CRITICAL" ]; then
        mark=" CRIT "
    elif [ "$sev" = "WARNING" ]; then
        mark=" WARN "
    else
        mark=" info "
    fi
    printf "  [%s] %2d. %-46s %s\n" "$mark" "$i" "$title" "$c hit(s)"
done < "$META"

echo "====================================================================="
echo
echo "Sections marked 'ok' produced no output and are omitted below."
echo

i=0
while IFS='|' read -r sev title hint; do
    i=$((i + 1))
    c=$(grep -c . "$TMP/$i.out" 2>/dev/null); c=${c:-0}
    [ "$c" -eq 0 ] && continue
    echo "---------------------------------------------------------------------"
    echo "[$sev] $i. $title   ($c hit(s))"
    echo "---------------------------------------------------------------------"
    echo "WHY THIS MATTERS: $hint"
    echo
    cat "$TMP/$i.out"
    echo
done < "$META"

echo "====================================================================="
echo " END OF REPORT   --   $VERDICT"
echo "====================================================================="
} > "$OUT" 2>&1

echo
echo "VERDICT: $VERDICT"
echo "Report : $OUT"
echo
grep -E '^  \[' "$OUT"
