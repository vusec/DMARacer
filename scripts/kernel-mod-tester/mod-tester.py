#!/usr/bin/env python3

import subprocess as sp
import sys
import os
import time

to_test = []
for line in open(sys.argv[1], "r").readlines():
    to_test.append(line.strip())

good_drivers = []

output_dir = "driver-test/"
os.makedirs(output_dir, exist_ok=True)
good_file = open(output_dir + "/good", "a")
bad_file = open(output_dir + "/bad", "a")

original_task_src = ""
task_file_path = "taskfiles/TasksKernel.yml"
with open(task_file_path, "r") as f:
    original_task_src = f.read()

task_prefix = "\n      - cd $KERNEL && scripts/config --enable "

report_idx = 0
def try_compile(driver_list) -> bool:
    global report_idx

    new_task_src = original_task_src[:]
    for good in good_drivers:
        new_task_src += task_prefix + good
    for driver in driver_list:
        new_task_src += task_prefix + driver
    new_task_src += "\n"
    with open(task_file_path, "w") as f:
        f.write(new_task_src)

    start = time.time()
    result = sp.run(["task", "kernel:clean", "kernel:config", "kernel:build", "qemu:test"], stdout=sp.PIPE, stderr=sp.STDOUT)
    end = time.time()
    print("Took minutes: " + str(int(end - start) // 60))

    if result.returncode == 0:
        for driver in driver_list:
            good_drivers.append(driver)
            good_file.write(driver + "\n")
            good_file.flush()
        return True

    if len(driver_list) <= 1:
        for driver in driver_list:
            bad_file.write(driver + "\n")
            bad_file.flush()
            report_idx += 1
            with open(output_dir + f"/report_{driver}_{report_idx}", "w") as f:
                try:
                    f.write(result.stdout.decode("utf-8"))
                except:
                    print("Failed to write error for " + driver)

    return False

def try_compile_rec(test_list):
    # Empty lists we can skip.
    if len(test_list) == 0:
        return

    # All drivers work, then we can also skip
    if try_compile(test_list):
        return
    left_list = test_list[:len(test_list)//2]
    right_list = test_list[len(test_list)//2:]
    assert len(left_list) + len(right_list) == len(test_list)
    try_compile_rec(left_list)
    try_compile_rec(right_list)

# Try to compile them in groups
chunk_size = 20

for i in range(0, len(to_test), chunk_size):
    test_list = to_test[i:i + chunk_size]
    try_compile_rec(test_list)
