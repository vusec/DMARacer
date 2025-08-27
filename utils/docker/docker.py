#!/usr/bin/env python3

import argparse
import subprocess as sp
import sys
import os
from pathlib import Path

home = Path.home()
script_dir = os.path.dirname(os.path.realpath(__file__))

parser = argparse.ArgumentParser(description="Starts DMARacer docker container.")
parser.add_argument("-s", "--sudo", action="store_true")
parser.add_argument("-a", "--no-ssh", dest="ssh", action="store_false", help="Mount .ssh folder in container")
parser.add_argument("-v", "--verbose", action="store_true")
parser.add_argument("-n", "--nobuild", action="store_true")
parser.add_argument("-r", "--ramdisk", help="Use a ramdisk for programs/inputs. Parameters specified ramdisk size in GB", type=int, default=None)
parser.add_argument("-p", "--parallel", action="store_true", help="Allow other containers to run in parallel.")
parser.add_argument("--no-nethost", dest="nethost", action="store_false")
parser.add_argument("-m", "--memory", type=int, default=None)
parser.add_argument("-l", "--legacy", action="store_true")
parser.add_argument(
    "-u",
    "--ulimit",
    action="store_false",
    help="Don't try to set ulimit to get valgrind working",
)

# Split into: arg1 arg2 -- cmdpart1 cmndpart2
args_to_parse = []
command_to_run = []
in_raw_cmd = False
for arg in sys.argv[1:]:
    if in_raw_cmd:
        command_to_run.append(arg)
        continue
    if arg == "--":
        in_raw_cmd = True
        continue
    args_to_parse.append(arg)

cmd_args = parser.parse_args(args=args_to_parse)
should_build = not cmd_args.nobuild
verbose = cmd_args.verbose
sudo = cmd_args.sudo

docker_cmd = ["docker"] if sudo else ["sudo", "docker"]
image_name = "dma-racer/docker"

parallel = cmd_args.parallel or ("PARALLEL_DOCKER" in os.environ)

# This is kind of a hack, as in theory we should have a graceful
# termination for all evaluation runs.
if not parallel and len(command_to_run):
    container_ls = sp.check_output(["docker", "container", "ls"]).decode("utf-8")
    for line in container_ls.splitlines():
        if image_name in line:
            container_id = line.split(" ")[0]
            print(f"Stopping container: {line}")
            sp.check_call(["docker", "container", "stop", container_id])

# The default dir in the docker container.
docker_home_dir = "/home/dmaracer/mnt/"
# The shell to start in the container.
zombie_collector = "/home/dmaracer/mnt/utils/zombie-reaper-wrapper.py"
shell = "/usr/bin/fish"

# Extra args passed to all docker commands.
docker_extra_args = []
if cmd_args.nethost:
    docker_extra_args += ["--network=host"]

# The path to the docker file.
docker_path = os.path.join(script_dir)

# Use docker's build kit unless disabled by user.
if not cmd_args.legacy:
    os.environ["DOCKER_BUILDKIT"] = "1"

memory_mb_available = None
try:
    import psutil
    memory_mb_available = psutil.virtual_memory().available / 1024 / 1024
    # Leave some buffer memory just because Linux OOM sucks and otherwise
    # the whole machine goes down in flames.
    memory_mb_available = int(memory_mb_available * 0.85)
except Exception as e:
    pass

if cmd_args.memory:
    memory_mb_available = cmd_args.memory * 1024

def build():
    args = docker_cmd + ["build"] + docker_extra_args + ["-t", image_name, docker_path]
    sp.check_call(args)


def start():
    args = docker_cmd[:]
    args += ["run", "-w", docker_home_dir]

    hostname = "DMARacer"
    args += ["--hostname", hostname]
    args += ["--add-host", f"{hostname}:127.0.0.1"]

    args += docker_extra_args
    if memory_mb_available:
        print("Limiting docker memory to " + str(int(memory_mb_available/1024)) + "GiB")
        args += [f"--memory={memory_mb_available}m"]
    # These args allow debugging within the container.
    args += ["--cap-add=SYS_PTRACE"]
    args += ["--cap-add=CAP_SYS_ADMIN"]
    args += ["--cap-add=SYS_ADMIN"]
    args += ["--privileged"]
    args += ["--device", "/dev/loop-control"]
    args += ["--security-opt", "seccomp=unconfined"]
    # Some platforms set a very high fd limit which breaks valgrind.
    if cmd_args.ulimit:
        args += ["--ulimit", "nofile=10000:10000"]
    args += ["--ulimit", "core=0"]
    if cmd_args.ramdisk:
        ramdisk_size = cmd_args.ramdisk
        args += ["--tmpfs", f"/exec-tmp-ram:rw,exec,size={ramdisk_size}g"]
    if cmd_args.ssh:
        args += ["--mount", f"type=bind,source={home}/.ssh,target=/home/dmaracer/.ssh"]
    # Mount the base folder in the container.
    args += ["--mount", f"type=bind,source={script_dir}/../..,target={docker_home_dir}"]
    if len(command_to_run):
        args += ["-t"]
        args += [image_name]
        args += [zombie_collector, shell, "-c", " ".join(command_to_run)]
    else:
        args += ["-it"]
        # Start an interactive shell.
        args += [image_name]
        args += [zombie_collector, shell]
    sp.run(args)

if should_build:
    build()
start()
