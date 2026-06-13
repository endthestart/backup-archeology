#!/usr/bin/env bash
#
# cleanup.sh - Compatibility wrapper around the safer Python CLI.
#
# Usage:
#   ./cleanup.sh /path/to/backups
#   ./cleanup.sh /path/to/backups --plan plan.csv
#   ./cleanup.sh /path/to/backups --quarantine /path/to/quarantine
#   ./cleanup.sh /path/to/backups --delete --yes
#

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <backup-root> [--plan FILE] [--quarantine DIR] [--delete --yes]"
    exit 1
fi

ROOT="$1"
shift

if [[ ! -d "$ROOT" ]]; then
    echo "Error: '$ROOT' is not a directory"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"
DB_PATH="$(mktemp -t backup-archeology)"
trap 'rm -f "$DB_PATH" "$DB_PATH-wal" "$DB_PATH-shm"' EXIT

PLAN=""
QUARANTINE=""
DELETE=false
YES=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --plan)
            PLAN="${2:-}"
            shift 2
            ;;
        --quarantine)
            QUARANTINE="${2:-}"
            shift 2
            ;;
        --delete)
            DELETE=true
            shift
            ;;
        --yes)
            YES=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "Scanning $ROOT"
"$PYTHON" "$SCRIPT_DIR/ba.py" --db "$DB_PATH" scan "$ROOT" --no-progress
"$PYTHON" "$SCRIPT_DIR/ba.py" --db "$DB_PATH" analyze

if [[ -n "$PLAN" ]]; then
    "$PYTHON" "$SCRIPT_DIR/ba.py" --db "$DB_PATH" plan --tier all --format csv --output "$PLAN"
fi

if [[ -n "$QUARANTINE" ]]; then
    "$PYTHON" "$SCRIPT_DIR/ba.py" --db "$DB_PATH" clean --tier safe --quarantine "$QUARANTINE"
elif $DELETE; then
    if ! $YES; then
        echo "Refusing permanent delete without --yes."
        exit 1
    fi
    "$PYTHON" "$SCRIPT_DIR/ba.py" --db "$DB_PATH" clean --tier safe --delete --yes
else
    echo
    echo "Dry-run cleanup summary:"
    "$PYTHON" "$SCRIPT_DIR/ba.py" --db "$DB_PATH" clean --tier safe
fi
