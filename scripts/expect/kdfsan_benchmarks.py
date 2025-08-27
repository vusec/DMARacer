import os
from time import sleep
import subprocess as sp

from common import expect, copy_files

PROMPT = "root@syzkaller:~#"
DONE_MSG = "BENCHMARK DONE"
LMBENCH_PATH = "https://github.com/vusec/lm-bench-fixed/archive/refs/heads/master.zip"

benchmark_kinds = ["net", "disk-write", "disk-search", "gpu", "lmbench"]

def benchmark_kdfsan(qemu, benchmark : str):
    copy_files(f'scripts/benchmark/*.sh')
    sleep(10)
    qemu_args = " -device virtio-vga "
    os.environ["BENCHMARK_QEMU_ARGS"] = qemu_args
    #expect(qemu, PROMPT, timeout=10)
    if benchmark == "net":
        qemu.sendline('./start-iperf.sh')
        expect(qemu, "Server listening on TCP port", timeout=5)
        print("Starting benchmarking with iperf...")
        for _ in range(0, 5):
            sp.check_output(["iperf", "-c", "localhost", "-p", "5001"])
        expect(qemu, DONE_MSG, timeout = 600)
    elif benchmark == "disk-write":
        qemu.sendline('./disk-write-bench.sh')
        expect(qemu, DONE_MSG, timeout = 600)
    elif benchmark == "disk-search":
        qemu.sendline('./disk-search-bench.sh')
        expect(qemu, DONE_MSG, timeout = 600)
    elif benchmark == "gpu":
        qemu.sendline('./gpu-bench.sh')
        expect(qemu, DONE_MSG, timeout = 600)
    elif benchmark == "lmbench":
        benchmark_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "benchmark")
        archive_name = "lmbench.zip"
        archive_path = os.path.join(benchmark_dir, archive_name)
        if not os.path.exists(archive_path):
            sp.check_call(["wget", LMBENCH_PATH, "-O", archive_path])

        copy_files(f'scripts/benchmark/' + archive_name)
        # It can take a while for this to be copied.
        sleep(40)
        qemu.sendline('./lmbench.sh')
        # Don't kill on timeout, as the lmbench copy sometimes fails.
        expect(qemu, DONE_MSG, timeout = 6000, kill_on_timeout = False)
    else:
        assert False, f"Unknown benchmark: {benchmark}"