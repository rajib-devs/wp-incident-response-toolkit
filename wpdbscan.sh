#!/bin/bash
#=====================================================================
#  WordPress DATABASE Malware Scanner   v1.2
#
#  Usage:
#    bash wpdbscan.sh /path/to/wordpress [output-file]
#        Reads credentials from that site's wp-config.php.
#
#    bash wpdbscan.sh --db DBNAME [--path /path/to/site] [output-file]
#        Scans a database directly. No WordPress install needed.
#        Requires ~/.my.cnf holding the credentials (see below), so
#        no password is ever typed on the command line.
#
#  Read-only. Runs SELECTs only - never writes to the database.
#
#  ~/.my.cnf format (create it with cPanel File Manager, chmod 600):
#        [client]
#        user=shawamcl_dbuser
#        password=thepassword
#        host=localhost
#
#  v1.2 changes:
#    - --db mode: scan a database with no wp-config.php present
#    - prefix auto-detected from the tables themselves in --db mode
#    - disk-comparison checks skipped cleanly when no path is given
#=====================================================================

SITE=""
DBN=""
OUT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --db)   DBN="$2"; shift 2 ;;
        --path) SITE="$2"; shift 2 ;;
        -h|--help)
            sed -n '3,20p' "$0" | sed 's/^#//'
            exit 0 ;;
        *)
            if [ -z "$DBN" ] && [ -z "$SITE" ]; then SITE="$1"
            else OUT="$1"; fi
            shift ;;
    esac
done

if [ -z "$SITE" ] && [ -z "$DBN" ]; then
    echo "Usage: bash wpdbscan.sh /path/to/wordpress [output-file]"
    echo "   or: bash wpdbscan.sh --db DBNAME [--path /path/to/site] [output-file]"
    exit 1
fi

CFG=""
if [ -n "$SITE" ]; then
    if [ ! -d "$SITE" ]; then
        echo "ERROR: no such directory: $SITE"
        exit 1
    fi
    SITE="$(cd "$SITE" && pwd)"
    [ -f "$SITE/wp-config.php" ] && CFG="$SITE/wp-config.php"
    if [ -z "$CFG" ] && [ -z "$DBN" ]; then
        echo "ERROR: no wp-config.php in $SITE"
        echo "  If you removed it, scan the database directly instead:"
        echo "    bash wpdbscan.sh --db DBNAME"
        echo "  List your databases with:  mysql -e 'SHOW DATABASES;'"
        exit 1
    fi
fi

NAME="${DBN:-$(basename "$SITE")}"
[ -z "$OUT" ] && OUT="$HOME/wpdbscan-${NAME}-$(date +%Y%m%d-%H%M%S).txt"

TMP="$(mktemp -d)"
chmod 700 "$TMP"
trap 'rm -rf "$TMP"' EXIT

#---------------------------------------------------------------------
#  CONNECT
#---------------------------------------------------------------------
cfgval() {
    [ -n "$CFG" ] || return 0
    sed -n "s/^[[:space:]]*define([[:space:]]*['\"]$1['\"][[:space:]]*,[[:space:]]*['\"]\(.*\)['\"][[:space:]]*)[[:space:]]*;.*/\1/p" "$CFG" | head -1
}

ENGINE=""
MYCNF=""
WP=""

if [ -n "$CFG" ]; then
    WP="wp --path=$SITE --allow-root --skip-plugins --skip-themes"
    echo "Connecting to the database for $SITE ..." >&2
    if command -v wp >/dev/null 2>&1 && $WP db check >/dev/null 2>&1; then
        ENGINE="wpcli"
    fi
else
    echo "Connecting directly to database '$DBN' ..." >&2
fi

if [ -z "$ENGINE" ] && command -v mysql >/dev/null 2>&1; then
    if [ -z "$DBN" ]; then
        DBN="$(cfgval DB_NAME)"
        DBU="$(cfgval DB_USER)"
        DBP="$(cfgval DB_PASSWORD)"
        DBH="$(cfgval DB_HOST)"
        [ -z "$DBH" ] && DBH="localhost"
        if [ -n "$DBN" ] && [ -n "$DBU" ]; then
            MYCNF="$TMP/my.cnf"
            ( umask 077
              printf '[client]\nuser=%s\npassword=%s\nhost=%s\n' "$DBU" "$DBP" "$DBH" > "$MYCNF" )
            chmod 600 "$MYCNF"
        fi
    fi
    if [ -n "$MYCNF" ]; then
        mysql --defaults-extra-file="$MYCNF" "$DBN" -e "SELECT 1;" >/dev/null 2>&1 && ENGINE="mysql"
    else
        # no explicit credentials: rely on ~/.my.cnf
        mysql "$DBN" -e "SELECT 1;" >/dev/null 2>&1 && ENGINE="mysql"
    fi
fi

if [ -z "$ENGINE" ]; then
    echo "ERROR: cannot reach the database."
    if [ -n "$DBN" ] && [ -z "$CFG" ]; then
        echo "  Direct mode needs credentials in ~/.my.cnf:"
        echo "      [client]"
        echo "      user=YOUR_DB_USER"
        echo "      password=YOUR_DB_PASSWORD"
        echo "      host=localhost"
        echo "  Create it with cPanel File Manager, then: chmod 600 ~/.my.cnf"
        echo "  Check the database name with:  mysql -e 'SHOW DATABASES;'"
    else
        echo "  - Neither wp-cli nor the mysql client could connect."
        echo "  - Is the DB user/password in wp-config.php still valid?"
        echo "  - Or scan the database directly:  bash wpdbscan.sh --db DBNAME"
    fi
    exit 1
fi

echo "Connected via: $ENGINE" >&2

# q()    - query with column headers
# qraw() - query with no headers, for single-value extraction
if [ "$ENGINE" = "wpcli" ]; then
    q()    { $WP db query "$1" 2>/dev/null; }
    qraw() { $WP db query "$1" --skip-column-names 2>/dev/null; }
elif [ -n "$MYCNF" ]; then
    q()    { mysql --defaults-extra-file="$MYCNF" "$DBN" -e "$1" 2>/dev/null; }
    qraw() { mysql --defaults-extra-file="$MYCNF" -N -B "$DBN" -e "$1" 2>/dev/null; }
else
    q()    { mysql "$DBN" -e "$1" 2>/dev/null; }
    qraw() { mysql -N -B "$DBN" -e "$1" 2>/dev/null; }
fi

#---------------------------------------------------------------------
#  TABLE PREFIX
#  wp-cli -> wp-config.php -> the tables themselves
#---------------------------------------------------------------------
P=""
[ "$ENGINE" = "wpcli" ] && P="$($WP config get table_prefix 2>/dev/null | tr -d '[:space:]')"
if [ -z "$P" ] && [ -n "$CFG" ]; then
    P="$(sed -n "s/^[[:space:]]*\$table_prefix[[:space:]]*=[[:space:]]*['\"]\([^'\"]*\)['\"].*/\1/p" "$CFG" | head -1)"
fi
if [ -z "$P" ]; then
    # shortest table ending in "options" is the core options table
    P="$(qraw "SHOW TABLES LIKE '%options';" \
         | awk '{ print length, $0 }' | sort -n | head -1 | cut -d' ' -f2- \
         | sed 's/options$//')"
fi
[ -z "$P" ] && P="wp_"

# Sanity-check the prefix: a wrong prefix makes every query return
# nothing, which looks exactly like a clean site.
if [ "$(qraw "SELECT COUNT(*) FROM ${P}options;" 2>/dev/null | tr -d '[:space:]')" = "" ]; then
    echo "ERROR: table prefix '${P}' does not match this database."
    echo "  Tables found:"
    qraw "SHOW TABLES;" | head -20 | sed 's/^/    /'
    exit 1
fi

echo "Table prefix : $P" >&2

N=0
META="$TMP/meta"
: > "$META"

reg() {
    N=$((N + 1))
    cp "$3" "$TMP/$N.out"
    printf '%s|%s|%s\n' "$1" "$2" "$4" >> "$META"
}

#---------------------------------------------------------------------
# 1. ADMINISTRATOR ACCOUNTS
#---------------------------------------------------------------------
q "SELECT u.ID, u.user_login, u.user_email, u.user_registered
   FROM ${P}users u
   JOIN ${P}usermeta m ON m.user_id = u.ID
   WHERE m.meta_key = '${P}capabilities'
     AND m.meta_value LIKE '%administrator%'
   ORDER BY u.user_registered DESC;" > "$TMP/w"
reg CRITICAL "Administrator accounts" "$TMP/w" \
    "Every account here has full control of the site. You should recognise all of them. Delete any you do not."

#---------------------------------------------------------------------
# 2. HIDDEN ADMIN CAPABILITY INJECTION
#---------------------------------------------------------------------
q "SELECT u.ID, u.user_login, m.meta_key, LEFT(m.meta_value,120) AS caps
   FROM ${P}users u
   JOIN ${P}usermeta m ON m.user_id = u.ID
   WHERE m.meta_value LIKE '%administrator%'
     AND m.meta_key NOT IN ('${P}capabilities');" > "$TMP/w"
reg CRITICAL "Admin rights outside the normal capabilities key" "$TMP/w" \
    "A classic trick: grant admin via a meta key WordPress does not show in the Users screen, so the account looks like a subscriber."

#---------------------------------------------------------------------
# 3. RECENTLY CREATED USERS
#---------------------------------------------------------------------
q "SELECT ID, user_login, user_email, user_registered
   FROM ${P}users
   WHERE user_registered > DATE_SUB(NOW(), INTERVAL 120 DAY)
   ORDER BY user_registered DESC LIMIT 50;" > "$TMP/w"
reg WARNING "Users created in the last 120 days" "$TMP/w" \
    "Cross-reference with real signups. An account created during the infection window is suspect even if it is not an admin."

#---------------------------------------------------------------------
# 4. CORE SITE SETTINGS
#---------------------------------------------------------------------
q "SELECT option_name, LEFT(option_value,200) AS value FROM ${P}options
   WHERE option_name IN
   ('users_can_register','default_role','siteurl','home','admin_email',
    'new_admin_email','blog_public','template','stylesheet');" > "$TMP/w"
reg CRITICAL "Core site settings" "$TMP/w" \
    "default_role must NOT be administrator. siteurl/home must be your own domain. admin_email must be yours - changing it lets an attacker reset passwords."

#---------------------------------------------------------------------
# 5. MALICIOUS CRON HOOKS
#    v1.0 truncated this at 4000 chars and missed hooks sharing a
#    timestamp with a legitimate hook. Both fixed.
#---------------------------------------------------------------------
qraw "SELECT option_value FROM ${P}options WHERE option_name='cron';" > "$TMP/cron.raw"

grep -aoE '[;{}]s:[0-9]+:"[^"]+";a:[0-9]+:\{s:3[0-9]:"' "$TMP/cron.raw" \
    | sed -E 's/^[;{}]s:[0-9]+:"//; s/";a:[0-9]+:\{s:3[0-9]:"$//' \
    | sort -u > "$TMP/hooks.all"

grep -aiE 'sc_|lumen|backdoor|eval|shell_exec|passthru|guard|fetch|^wp_[a-f0-9]{8,}$|[a-f0-9]{12,}' \
    "$TMP/hooks.all" > "$TMP/w"
reg CRITICAL "Suspicious scheduled hook names" "$TMP/w" \
    "sc_cron_guard and sc_cron_fetch were this malware's self-healing watchdogs. Any random-looking hook name is suspect. Note 'guard' and 'fetch' also appear in some legitimate plugin hooks - check section 6 for context."

#---------------------------------------------------------------------
# 6. FULL CRON LIST
#---------------------------------------------------------------------
{
    echo "-- CRON BLOB SIZE --"
    echo "  $(wc -c < "$TMP/cron.raw") bytes"
    echo "  $(grep -aoE 'i:1[0-9]{9};a:' "$TMP/cron.raw" | wc -l) scheduled timestamp group(s)"
    echo
    echo "-- ALL SCHEDULED HOOKS --"
    sed 's/^/  /' "$TMP/hooks.all"
    if [ "$ENGINE" = "wpcli" ]; then
        echo
        echo "-- wp-cli DETAIL --"
        $WP cron event list --fields=hook,recurrence,next_run_relative 2>/dev/null
    fi
} > "$TMP/w"
reg WARNING "All scheduled events" "$TMP/w" \
    "Every hook should map to a plugin you actually have installed. Unrecognised hooks are the malware rescheduling itself."

#---------------------------------------------------------------------
# 7. PAYLOADS INSIDE OPTIONS
#---------------------------------------------------------------------
q "SELECT option_id, option_name, autoload, LENGTH(option_value) AS len,
          LEFT(option_value,100) AS preview
   FROM ${P}options
   WHERE option_value LIKE '%base64_decode%'
      OR option_value LIKE '%eval(%'
      OR option_value LIKE '%gzinflate%'
      OR option_value LIKE '%SCV:%'
      OR option_value LIKE '%lumen-provider%'
      OR option_value LIKE '%sc_cron%'
      OR option_value LIKE '%FilesMan%'
      OR option_value LIKE '%shell_exec%'
      OR option_value LIKE '%\$_POST[%'
   LIMIT 50;" > "$TMP/w"
reg CRITICAL "Code-like payloads stored in options" "$TMP/w" \
    "Autoloaded options run on every page load. A payload here survives any amount of file cleaning."

#---------------------------------------------------------------------
# 8. OVERSIZED AUTOLOADED OPTIONS
#---------------------------------------------------------------------
q "SELECT option_name, autoload, LENGTH(option_value) AS len
   FROM ${P}options
   WHERE autoload IN ('yes','on') AND LENGTH(option_value) > 100000
   ORDER BY len DESC LIMIT 20;" > "$TMP/w"
reg WARNING "Very large autoloaded options" "$TMP/w" \
    "Usually a bloated cache or transient, but a hidden payload also has to live somewhere. Check anything you do not recognise."

#---------------------------------------------------------------------
# 9. WPCODE / CODE-SNIPPET POSTS
#---------------------------------------------------------------------
q "SELECT ID, post_type, post_status, post_title, LENGTH(post_content) AS len
   FROM ${P}posts
   WHERE post_type IN ('wpcode','snippet','code_snippet','wpcode_snippet')
   LIMIT 50;" > "$TMP/w"
reg CRITICAL "Stored code snippets" "$TMP/w" \
    "WPCode executes PHP stored in the database on every request. Read the body of every snippet here - no file scan can see them."

#---------------------------------------------------------------------
# 10. INJECTED POST CONTENT
#---------------------------------------------------------------------
q "SELECT ID, post_type, post_status, LEFT(post_title,60) AS title
   FROM ${P}posts
   WHERE post_content LIKE '%<script%eval%'
      OR post_content LIKE '%base64_decode%'
      OR post_content LIKE '%<iframe%display:none%'
      OR post_content LIKE '%document.write(unescape%'
      OR post_content LIKE '%SCV:%'
   LIMIT 50;" > "$TMP/w"
reg CRITICAL "Injected content in posts/pages" "$TMP/w" \
    "Hidden iframes and injected scripts are how a hacked site serves spam or malware to your visitors."

#---------------------------------------------------------------------
# 11. SPAM / CLOAKED POSTS
#---------------------------------------------------------------------
q "SELECT post_type, post_status, COUNT(*) AS total
   FROM ${P}posts GROUP BY post_type, post_status ORDER BY total DESC;" > "$TMP/w"
reg WARNING "Post counts by type and status" "$TMP/w" \
    "A sudden mass of posts you never wrote is SEO spam injection. Compare against what you expect."

#---------------------------------------------------------------------
# 12. ACTIVE PLUGINS vs DISK
#---------------------------------------------------------------------
qraw "SELECT option_value FROM ${P}options WHERE option_name='active_plugins';" \
    | tr ';' '\n' | grep -aoE '"[^"]+\.php"' | tr -d '"' | sort -u > "$TMP/plugins.db"
{
    echo "-- ACTIVE PLUGIN ENTRIES --"
    sed 's/^/  /' "$TMP/plugins.db"
    echo
    if [ -n "$SITE" ] && [ -d "$SITE/wp-content/plugins" ]; then
        echo "-- ACTIVE BUT MISSING FROM DISK --"
        while IFS= read -r pl; do
            [ -n "$pl" ] || continue
            [ -f "$SITE/wp-content/plugins/$pl" ] || echo "  MISSING: $pl"
        done < "$TMP/plugins.db"
    else
        echo "-- DISK COMPARISON SKIPPED --"
        echo "  No site path given. Re-run with --path /path/to/site to"
        echo "  cross-check these entries against the plugins on disk."
    fi
} > "$TMP/w"
reg WARNING "Active plugins recorded in the database" "$TMP/w" \
    "A plugin listed active but absent from disk means you deleted the files while the database still expects it - it will be recreated if the malware can write."

#---------------------------------------------------------------------
# 13. MU-PLUGIN / DROPIN / MALWARE-NAMED OPTIONS
#---------------------------------------------------------------------
q "SELECT option_name, LEFT(option_value,200) AS preview FROM ${P}options
   WHERE option_name LIKE '%dropin%' OR option_name LIKE '%mu_plugin%'
      OR option_name LIKE '%must_use%' OR option_name LIKE 'sc\_%'
      OR option_name LIKE '%lumen%'
      OR option_name REGEXP '^[a-f0-9]{16,}$';" > "$TMP/w"
reg CRITICAL "Drop-in and malware-named options" "$TMP/w" \
    "Any option whose name starts with sc_ or mentions lumen belongs to this malware family."

#---------------------------------------------------------------------
# 14. INVENTORY
#---------------------------------------------------------------------
{
    echo "Database    : $DBN"
    echo "Site path   : ${SITE:-(none - database scanned directly)}"
    echo "Table prefix: $P"
    echo "Engine      : $ENGINE"
    echo
    echo "-- ROW COUNTS --"
    q "SELECT 'users' AS tbl, COUNT(*) AS rows_ FROM ${P}users
       UNION ALL SELECT 'posts', COUNT(*) FROM ${P}posts
       UNION ALL SELECT 'options', COUNT(*) FROM ${P}options
       UNION ALL SELECT 'autoloaded options', COUNT(*) FROM ${P}options WHERE autoload IN ('yes','on')
       UNION ALL SELECT 'comments', COUNT(*) FROM ${P}comments;"
} > "$TMP/w"
reg INFO "Inventory" "$TMP/w" "Baseline figures for comparison."

#=====================================================================
#  RENDER
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

VERDICT="REVIEW REQUIRED  --  $CRIT critical section(s) returned rows"
[ "$CRIT" -eq 0 ] && VERDICT="NO OBVIOUS DATABASE MALWARE  --  review warnings"

{
echo "====================================================================="
echo " WordPress DATABASE SCAN REPORT"
echo "====================================================================="
echo " Database : $DBN"
echo " Site     : ${SITE:-(database scanned directly - no WordPress files)}"
echo " Prefix   : $P"
echo " Engine   : $ENGINE"
echo " Host     : $(whoami)@$(hostname 2>/dev/null)"
echo " Date     : $(date)"
echo " Scanner  : wpdbscan.sh v1.2"
echo "---------------------------------------------------------------------"
echo " $VERDICT"
echo "---------------------------------------------------------------------"
echo " NOTE: sections 1, 4, 6 and 12 ALWAYS return rows on a healthy site."
echo "       They need reading, not alarm. Sections 2, 5, 7, 9, 10 and 13"
echo "       should be EMPTY on a clean install."
echo "---------------------------------------------------------------------"
echo " SUMMARY"

i=0
while IFS='|' read -r sev title hint; do
    i=$((i + 1))
    c=$(grep -c . "$TMP/$i.out" 2>/dev/null); c=${c:-0}
    if [ "$c" -eq 0 ]; then mark="  --  "
    elif [ "$sev" = "CRITICAL" ]; then mark=" READ "
    elif [ "$sev" = "WARNING" ]; then mark=" WARN "
    else mark=" info "; fi
    printf "  [%s] %2d. %-46s %s row(s)\n" "$mark" "$i" "$title" "$c"
done < "$META"

echo "====================================================================="
echo

i=0
while IFS='|' read -r sev title hint; do
    i=$((i + 1))
    c=$(grep -c . "$TMP/$i.out" 2>/dev/null); c=${c:-0}
    [ "$c" -eq 0 ] && continue
    echo "---------------------------------------------------------------------"
    echo "[$sev] $i. $title   ($c row(s))"
    echo "---------------------------------------------------------------------"
    echo "WHY THIS MATTERS: $hint"
    echo
    cat "$TMP/$i.out"
    echo
done < "$META"

echo "====================================================================="
echo " END OF REPORT"
echo "====================================================================="
} > "$OUT" 2>&1

echo
echo "Report: $OUT"
echo
grep -E '^  \[' "$OUT"
