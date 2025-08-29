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

*This section describes the non-docker setup.
You should prefer using the docker container, but if that is not possible,
then the steps below describe the manual setup of DMARacer.*

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

## Basic Test ###

To test that the instrumented kernel runs correctly, run: `task qemu:test`.
This will: (i) boot the kernel, (ii) enable KDFSAN, (iii) run basic tainting tests, and (iv) run taint policy-specific tests.

For the basic tainting tests, the kernel will panic if a test fails.
For the taint policy-specific tests, manually check in the log that the output matches the expected output (e.g., check that the correct number of reports are printed, if applicable).

## Fuzzing ##

Run `task qemu:fuzz-all` to fuzz all devices with QEMU.

## Report Viewer

Run `task reports:load-current` to parse the results of the fuzzing campaign.
To examine the resulting reports, run: `task reports:inspect`.

A TUI will open and show one of the vulnerable operations that
has been found. You can navigate to other reports using the command shown
at the bottom of the TUI.

In the example below, the found operation is a store of size 4 that was
created by the source code found at `libata-sff.c:2533`. The
metadata referencing report IDs describes whether this operation belong
to the same trace as other operations.
The backtrace of this specific store instruction is shown at the
bottom of the TUI.

```
========================================================
Report 13 of 7525...
====================================
Tested device: e1000_82545em
Fuzzing run: 7643539515351078876
Access: {addr: 0xffff88800d800004, data_label: 0, ptr_label: 0, size: 4}
Region: {dev_id: 0, region_addr: 0xd800000, cpu_addr: 0xffff88800d800000, s: 2048}
Instruction type: STORE
Report type: DMA_1F
Report ID: 0
Previous report IDs:          []
Previous DMA-LOAD report IDs: []
Next report IDs:              [1]
Next VULN report IDs:         []
RIP: dfs$ata_bmdma_qc_prep+0x3ea/0x510
File: drivers/ata/libata-sff.c
Line:
 /home/dmaracer/mnt/kdfsan-df-linux/drivers/ata/libata-sff.c:2533:22 -- ata_bmdma_fill_sg
 /home/dmaracer/mnt/kdfsan-df-linux/drivers/ata/libata-sff.c:2617:2  --     (inlined by) dfs$ata_bmdma_qc_prep
Backtrace:
 21. /home/dmaracer/mnt/kdfsan-df-linux/drivers/ata/libata-sff.c:2533:22  -- ata_bmdma_fill_sg
 20. /home/dmaracer/mnt/kdfsan-df-linux/drivers/ata/libata-sff.c:2617:2   --     (inlined by) dfs$ata_bmdma_qc_prep
 [...]
```

## Running ##

There are two options for running a network fuzzer on the instrumented kernel:
1. To fuzz every NIC for 10 minutes each, run: `task qemu:fuzz-net`.
2. To fuzz a subset of NICs for 3 minutes each, specify the NICs in the file `scripts/fuzzing/net/host/qemu-nics-x86.test`, then run `task qemu:fuzz-net-prelim`.

Finally, to parse the reports into a database and examine them, run: `task reports:load-current reports:inspect`.

## Performance Evaluation ##

To run the performance benchmarks, run `task full-benchmark`. The measurements can be found in the JSON file: `scripts/reports/out/benchmark.json`.
You can print the benchmark numbers into a LaTeX table by running the command: `python3 scripts/ablation-tex.py`.
