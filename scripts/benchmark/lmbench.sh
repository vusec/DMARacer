#!/bin/bash

echo "BENCHMARK_KIND: LMBENCH"
set -e

mkdir /non_ram_tmp
unzip lmbench.zip
ls
cd lm-bench-fixed-master/
sed -i 's/FORCE_UINT/1/g' src/bench.h
cd src
make lmbench
cd ..
bash get_options.sh | make results
cat results/x86_64-linux-gnu/*
echo "BENCHMARK DONE"