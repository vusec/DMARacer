#!/bin/bash

echo "BENCHMARK_KIND: IPERF"

timeout 120 iperf -f k -s -p 5001 | ts BENCHMARK:
echo "BENCHMARK DONE"