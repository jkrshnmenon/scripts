#!/usr/bin/env bash
# Toggle the mpris-miniplayer floating panel.
if pgrep -x mpris-miniplayer >/dev/null; then
  pkill -x mpris-miniplayer
else
  mpris-miniplayer &
  disown
fi
