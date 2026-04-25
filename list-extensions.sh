#!/usr/bin/env bash
# List all installed Chrome extensions with their ID, name, and version.

EXT_DIR="$HOME/Library/Application Support/Google/Chrome/Default/Extensions"

if [[ ! -d "$EXT_DIR" ]]; then
  echo "Chrome extensions directory not found: $EXT_DIR" >&2
  exit 1
fi

printf "%-40s %-40s %s\n" "ID" "Name" "Version"
printf "%-40s %-40s %s\n" "$(printf '%0.s-' {1..39})" "$(printf '%0.s-' {1..39})" "-------"

for ext_dir in "$EXT_DIR"/*/; do
  id=$(basename "$ext_dir")
  [[ "$id" == "Temp" ]] && continue

  version_dir=$(ls "$ext_dir" 2>/dev/null | head -1)
  manifest="$ext_dir$version_dir/manifest.json"
  [[ ! -f "$manifest" ]] && continue

  name=$(python3 -c "
import json, sys
try:
    m = json.load(open('$manifest'))
    print(m.get('name', '?'))
except Exception as e:
    print('?')
" 2>/dev/null)

  version=$(python3 -c "
import json
try:
    m = json.load(open('$manifest'))
    print(m.get('version', '?'))
except:
    print('?')
" 2>/dev/null)

  printf "%-40s %-40s %s\n" "$id" "${name:0:39}" "$version"
done
