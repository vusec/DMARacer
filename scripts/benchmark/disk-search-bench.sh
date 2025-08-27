#!/bin/bash

echo "BENCHMARK_KIND: DISK_SEARCH"

set -x

for run in {1..10}; do
  /usr/bin/time -f "BENCH_TIME:%e" sh -c 'find / -name does_not_exist' 2>&1 | ts BENCHMARK:
done

echo "BENCHMARK DONE"