#!/bin/bash

echo "BENCHMARK_KIND: GPU"

# Start an GUI
setenforce 0
echo "exec gnome-shell" > ~/.xinitrc
DISPLAY=:0 startx 1>/dev/null 2>/dev/null &
sleep 100
set -e

# Build glmark2
git clone https://github.com/glmark2/glmark2.git --depth 1
cd glmark2
meson setup build --buildtype=release -Dflavors=x11-gl -Ddata-path=$(pwd)/data
ninja -v -C build -j 1

for run in {1..5}; do
    vblank_mode=0 DISPLAY=:0 ./build/src/glmark2 --off-screen -b effect2d | ts BENCHMARK:
done
echo "BENCHMARK DONE"