#!/usr/bin/env bash
# Waybar custom module source for limusic.
# Streams one JSON object per line via `playerctl --follow`.
# When limusic isn't running, prints an empty-text object so the
# module collapses (combined with CSS .hidden rule).

while true; do
  if pgrep -x limusic-app >/dev/null; then
    playerctl -p limusic -F metadata --format \
      '{"text": "{{markup_escape(emoji(status))}} {{markup_escape(title)}} — {{markup_escape(artist)}}", "tooltip": "{{markup_escape(title)}}\n{{markup_escape(artist)}}\n{{markup_escape(album)}}", "class": "{{lc(status)}}", "alt": "{{lc(status)}}"}' \
      2>/dev/null
  fi
  echo '{"text":"","tooltip":"","class":"hidden","alt":"hidden"}'
  sleep 3
done
