# DMARacer

This repository provides everything needed to build and run the Linux kernel
with DMARacer.

## Docker Setup ##

1. Requirements: You need to have Docker and Python 3 installed on your system.

2. Start the docker container with `./start`.
This command will build and launch the container and then mount the repository
as a shared folder between host and container.
You can edit files within this folder from outside the container and the
changes will be visible within the container.

3. Run `task build` to build all components of DMARacer.

4. You can start fuzzing using `task qemu:fuzz-all`.

5. The fuzzing reports can be viewed using `task reports:load-current` and then
`task reports:inspect`. If you are just interested in the statistics, you
can run `task results-table`.

6. You can run the performance evaluation usin lm-bench by running `task full-benchmark`.
This evaluation will take up to 24 hours of runtime.

## Non-Docker Setup ##

*This section describes the non-docker setup.*

You should prefer using the docker container, but if that is not possible,
then the steps below describe the manual setup of DMARacer.

To download and install dependencies, including
[go-task](https://taskfile.dev/#/installation) as a task-runner, from the repository, run: `sudo snap install task --classic && task init`.

### Installation ###

Run `task build` to build all parts of DMARacer. You can also run the
individual steps below instead:

1. To create a basic initramfs image and [an image to be used with syzkaller](https://github.com/google/syzkaller/blob/master/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md#image), run: `task initramfs:create syzkaller:create-image`. Note: if `ARCH` is changed in `.env`, then the images will need to be rebuilt.

2. To build [qemu with device fuzzing support](https://github.com/vusec/DMARacer-QEMU), run: `task qemu:config qemu:build`.

3. build [syzkaller with KDFSAN support](https://github.com/vusec/DMARacer-Syzkaller), run: `task syzkaller:build`.

4. configure and build [LLVM with KDFSAN support](https://github.com/vusec/DMARacer-LLVM), run: `task llvm:config llvm:build`.

5. configure and build a [KDFSAN-instrumented kernel](https://github.com/vusec/DMARacer-Linux), run: `task kernel:config kernel:build`.

### Basic Test ###

To test that the instrumented kernel runs correctly, run: `task qemu:test`.
This will: (i) boot the kernel, (ii) enable KDFSAN, (iii) run basic tainting tests, and (iv) run taint policy-specific tests.

For the basic tainting tests, the kernel will panic if a test fails.
For the taint policy-specific tests, manually check in the log that the output matches the expected output (e.g., check that the correct number of reports are printed, if applicable).

Next, to parse the reports into a database and examine them, run: `task reports:load-test`. Finally, to examine the reports, run: `task reports:inspect`.

## Running ##

There are two options for running a network fuzzer on the instrumented kernel:
1. To fuzz every NIC for 10 minutes each, run: `task qemu:fuzz-net`.
2. To fuzz a subset of NICs for 3 minutes each, specify the NICs in the file `scripts/fuzzing/net/host/qemu-nics-x86.test`, then run `task qemu:fuzz-net-prelim`.

Finally, to parse the reports into a database and examine them, run: `task reports:load-current reports:inspect`.

## Performance Evaluation ##

To run the performance benchmarks, run `task full-benchmark`. The measurements can be found in the JSON file: `scripts/reports/out/benchmark.json`.
You can print the benchmark numbers into a LaTeX table by running the command: `python3 scripts/ablation-tex.py`.
