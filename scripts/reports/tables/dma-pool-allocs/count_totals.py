#!/usr/bin/env -S python3 -u

import csv

def print_total_counts():
    files = ['entire-kernel-dma-allocs.csv', 'our-kernel-dma-pool-allocs.csv']
    for filename in files:
        total = 0
        with open(filename, 'r') as csvfile:
            reader = csv.reader(csvfile)
            for _, count in reader:
                total += int(count)
        print(f"Total count for {filename}: {total}")

print_total_counts()

