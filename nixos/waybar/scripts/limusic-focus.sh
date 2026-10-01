#!/usr/bin/env bash
# Focus the limusic window in niri. No-op if limusic isn't open.
id=$(niri msg --json windows \
     | python3 -c "import sys, json; w=[x for x in json.load(sys.stdin) if x.get('app_id')=='Limusic-app']; print(w[0]['id']) if w else None" 2>/dev/null)
[ -n "$id" ] && niri msg action focus-window --id "$id"
