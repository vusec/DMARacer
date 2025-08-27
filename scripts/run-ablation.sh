#!/bin/bash

set -e
KDFSAN_ABLATION=$1 task run-one-ablation-benchmark-prep

for run in {1..20}; do
  KDFSAN_ABLATION=$1 task qemu:benchmark-lmbench
done
