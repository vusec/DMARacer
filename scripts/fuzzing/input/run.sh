#!/bin/bash
# Print device list.
echo "IOMEM:"
cat /proc/iomem | grep -v "System RAM" | grep -v ": Reserved" | grep -v ": Kernel"

setenforce 0
echo "exec gnome-shell" > ~/.xinitrc
DISPLAY=:0 startx 1>/dev/null 2>/dev/null &

sleep 10000
