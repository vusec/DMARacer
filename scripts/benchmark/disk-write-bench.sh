#!/bin/bash

echo "BENCHMARK_KIND: DISK_WRITE"

set -x

for run in {1..10}; do
  /usr/bin/time -f "BENCH_TIME:%e" sh -c 'dd if=/dev/urandom of=/foo bs=1M count=1000 ; sync ' 2>&1 | ts BENCHMARK:
done

echo "BENCHMARK DONE"