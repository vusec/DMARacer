#!/bin/sh

set -e
setenforce 0
echo "exec gnome-shell" > ~/.xinitrc
DISPLAY=:0 startx 1>/dev/null 2>/dev/null &
sleep 180 # Give some time for gnome to start up.
# start some opengl demos.
DISPLAY=:0 glxgears 1>/dev/null 2>/dev/null &
DISPLAY=:0 glxdemo 1>/dev/null 2>/dev/null &
sleep 100000