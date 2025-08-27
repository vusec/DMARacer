import sys
import os
import pexpect
import argparse
from time import sleep
import subprocess as sp

from kdfsan_benchmarks import benchmark_kdfsan, benchmark_kinds

from common import getch, exec_command, snapshot_save, snapshot_load, copy_testcases, expect, get_host_ip, copy_files, start_http_server_proc, init_syzkaller_port, init_qemu_socket

init_syzkaller_port()
init_qemu_socket()

snapshot_name = "tmp_with_testprogs"

parser = argparse.ArgumentParser(description='pexpect run spectrestar with qemu')
parser.add_argument('--target', dest='target', default="syzkaller", type=str)
parser.add_argument('--loadvm', dest='loadvm', default=None, type=str)
parser.add_argument('--testprogs', dest='testprogs', default=None, type=str)
parser.add_argument('--gdb', dest='gdb', action='store_const', const=sum)
parser.add_argument('--interactive', '-i', dest='interactive', action='store_const', const=sum)
parser.add_argument('--whitelist', dest='whitelist', default=None, choices=['t', 'd', 's'], type=str)
parser.add_argument('--fuzz', dest='fuzz', default=None, choices=['net', 'input', 'gpu', 'storage', 'audio'], type=str)
parser.add_argument('--tests', dest='run_tests', action='store_const', const=sum)
parser.add_argument('--early_enable', dest='early_enable', action='store_const', const=sum)
parser.add_argument('--generic_syscall_label', dest='generic_syscall_label', action='store_const', const=sum)
parser.add_argument('--benchmark', dest='benchmark', default=None, choices=benchmark_kinds, type=str)

args = parser.parse_args()
env = os.environ

env['KERNEL_PARAMS'] = ""
if args.run_tests: env['KERNEL_PARAMS']+="kdf_param_run_tests=1 "
if args.early_enable: env['KERNEL_PARAMS']+="kdf_param_early_enable=1 "
if args.whitelist: env['KERNEL_PARAMS']+="kdf_param_whitelist="+args.whitelist+" "
if args.generic_syscall_label: env['KERNEL_PARAMS']+="kdf_param_generic_syscall_label=1 "

print('target: {}'.format(args.target))
if args.target == 'syzkaller':
    PROMPT = "root@syzkaller:~#"
else:
    PROMPT = "/ #"

start_vnc_client = 'QEMU_FUZZER_INPUTS' in env
vnc_tool_name = "vncdotool"
if start_vnc_client:
    vnc_test = sp.run([vnc_tool_name, "--help"], stdout=sp.PIPE, stderr=sp.STDOUT)
    if vnc_test.returncode != 0:
        print(f"Failed to find {vnc_tool_name}:")
        print(vnc_test)
        print(vnc_test.stdout.decode("utf-8"))
        sys.exit(1)

if args.gdb:
    env['ATTACH_GDB'] = '1'
if args.loadvm:
    env['LOADVM'] = args.loadvm

qemu = pexpect.spawn('scripts/run-qemu.sh {}'.format(args.target),
        env=env,
        encoding='utf-8')
qemu.logfile = sys.stdout

# login
if args.target == 'syzkaller':
    expect(qemu, 'syzkaller login:', timeout=None)
    qemu.sendline('root')

# setup
expect(qemu, PROMPT, timeout=None)

if args.target == 'syzkaller' and args.testprogs:
    copy_testcases(args.testprogs)

qemu.sendline('mount -t debugfs none /sys/kernel/debug')
expect(qemu, PROMPT)
sleep(1)

if args.benchmark:
    benchmark_kdfsan(qemu, args.benchmark)

if args.fuzz == 'net':
    copy_files(f'scripts/fuzzing/{args.fuzz}/*')
    qemu.sendline('./fuzz-provision.sh') # Ideally we'd do all provisioning when creating the VM image
    expect(qemu, PROMPT, timeout=150)

if args.fuzz in ['gpu', 'input', 'storage', 'audio']:
    copy_files(f'scripts/fuzzing/{args.fuzz}/*')

if args.interactive:
    qemu.logfile = None
    qemu.interact()
else:
    qemu.sendline('cat /sys/kernel/debug/kdfsan/post_boot')
    expect(qemu, PROMPT)

if args.fuzz == 'net':
    start_http_server_proc(get_host_ip(), 6789, 'out/fuzzing-net-server.log')
    qemu.sendline('python fuzz-http.py --ip ' + get_host_ip() + ' --port 6789 > /dev/null')
    expect(qemu, PROMPT, timeout=None) # Shouldn't ever hit

if args.fuzz in ['gpu', 'input', 'storage', 'audio']:
    qemu.sendline('./run.sh')

# Start the VNC client if needed after letting the target set itself up.
if start_vnc_client:
    # Start a VNC client that does nothing but open the display and wait.
    # Client will close itself when QEMU shuts down.
    vnc_cmd = [vnc_tool_name, "-s", "localhost::5900", "pause", "10000"]
    vnc_client = sp.Popen(vnc_cmd, stdin=sp.PIPE,
                          stdout=sp.PIPE, stderr=sp.STDOUT)

if args.fuzz in ['input', 'gpu', 'storage', 'audio']:
    expect(qemu, PROMPT, timeout=None) # Shouldn't ever hit

print('expect successful!')
