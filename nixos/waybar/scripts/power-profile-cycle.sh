#!/usr/bin/env bash
current=$(powerprofilesctl get)
case $current in
    performance) next="balanced" ;;
    balanced)    next="power-saver" ;;
    power-saver) next="performance" ;;
    *)           next="balanced" ;;
esac
powerprofilesctl set "$next"
