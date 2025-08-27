#!/usr/bin/env python3

import argparse
import os
import json

parser = argparse.ArgumentParser()
parser.add_argument("--input", help="Input to analyze")
parser.add_argument("--database", help="Database to append to")
parser.add_argument("--build-type-file", dest="build_type_file", help="File containing current build type")
args = parser.parse_args()

with open(args.build_type_file, "r") as f:
    build_type = f.read().strip()

database = args.database # type: str

bench_time_marker = "BENCH_TIME:"
kinds = ["IPERF", "DISK_WRITE", "DISK_SEARCH", "GPU", "LMBENCH"]

def get_benchmark_kind(input : str) -> str:
    for kind in kinds:
        if ("BENCHMARK_KIND: " + kind) in input:
            return kind
    assert False, "Could not determine benchmark kind!"

lm_bench_keys = [
  "Simple syscall:",
  "Simple read:",
  "Simple write:",
  "Simple stat:",
  "Simple fstat:",
  "Simple open/close:",
  "Select on 10 fd's:",
  "Select on 100 fd's:",
  "Select on 250 fd's:",
  "Select on 500 fd's:",
  "Select on 10 tcp fd's:",
  "Select on 100 tcp fd's:",
  "Select on 250 tcp fd's:",
  "Select on 500 tcp fd's:",
  "Signal handler installation:",
  "Signal handler overhead:",
  "Protection fault:",
  "Pipe latency:",
  "AF_UNIX sock stream latency:",
  "Process fork+exit:",
  "Process fork+execve:",
  "Process fork+/bin/sh -c:",
  "File /var/tmp/XXX write bandwidth:",
  "Pagefaults on /var/tmp/XXX:",
  "UDP latency using localhost:",
  "TCP latency using localhost:",
  "TCP/IP connection cost to localhost:",
]

lmbench_units = [
    "microseconds",
    "KB/sec",
]

def append_to_db(key : str, data_points : list[float]):
    if len(data_points) == 0:
        return
    existing = {}
    if os.path.exists(database):
        with open(database, "r") as f:
            existing = json.load(f)
    if not build_type in existing:
        existing[build_type] = {}

    build_type_specific_values = existing[build_type]
    if not key in build_type_specific_values:
        build_type_specific_values[key] = []
    build_type_specific_values[key] += data_points

    with open(database, "w") as f:
        f.write(json.dumps(existing, indent=2))

input_lines = []
with open(args.input) as f:
    input_lines = f.readlines()

all_data = {}
def add_data(key : str, value : float):
    print(value)
    if not key in all_data:
        all_data[key] = []
    all_data[key] += [value]

benchmark_kind = get_benchmark_kind("\n".join(input_lines))

for line in input_lines:
    line = line.strip()

    if benchmark_kind == "LMBENCH":
        print(line)
        for key in lm_bench_keys:
            if not line.startswith(key):
                continue

            value = line.split(key)[1]
            for unit in lmbench_units:
                value = value.replace(unit, "")
            add_data("LMBENCH:" + key, float(value))
        continue

    if not line.startswith("BENCHMARK:"):
        continue

    if benchmark_kind == "DISK_WRITE" and bench_time_marker in line:
        time_str = line.split(bench_time_marker)[1].strip()
        data = float(time_str)
        add_data(benchmark_kind, data)

    if benchmark_kind == "DISK_SEARCH" and bench_time_marker in line:
        time_str = line.split(bench_time_marker)[1].strip()
        data = float(time_str)
        add_data(benchmark_kind, data)

    if benchmark_kind == "IPERF" and "Kbits/sec" in line:
        # Example line: [  4] 0.0000-10.0369 sec  2099456 KBytes  1713549 Kbits/se
        mb_per_sec = line.split("KBytes")[1].strip()
        # Should now be: '1659513 Kbits/sec'
        assert mb_per_sec.endswith("Kbits/sec")
        data = float(mb_per_sec[:-len("Kbits/sec")].strip())
        add_data(benchmark_kind, data)
    
    if benchmark_kind == "GPU" and ": FPS:" in line:
        # Example line: [effect2d] <default>: FPS: 215 FrameTime: 4.654 ms
        suffix = line.split("FrameTime: ")[1]
        # rest: 4.654 ms
        assert suffix.endswith(" ms")
        frame_time = suffix.split(" ms")[0].strip()
        add_data(benchmark_kind, float(frame_time))


assert len(all_data) != 0, "Could not find any benchmark data in file?"

kind = get_benchmark_kind("\n".join(input_lines))
for key, data_points in all_data.items():
    # Drop the first benchmark and consider it as a warmup bench.
    if len(data_points) > 1:
        data_points = data_points[1:]
    append_to_db(key=key, data_points=data_points)