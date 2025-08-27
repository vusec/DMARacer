#!/usr/bin/env bash

CONTINUE="C"

# Note: Use hbreak in gdb-cmds.txt to set breakpoints (for some reason software
# breakpoints are not being hit when kvm is enabled).
# If a software breakpoint is desired, set 'hbreak start_kernel', then when
# that is hit, set the software breakpoint

${GDB} \
  -q \
  -ex "add-auto-load-safe-path ${KERNEL}" \
  -ex "file ${KERNEL}/vmlinux" \
  -ex "target remote localhost:${GDB_PORT}" \
  -ex "source ${ROOT}/scripts/gdb-cmds.txt" \
  ${CONTINUE:+ -ex "continue"}
