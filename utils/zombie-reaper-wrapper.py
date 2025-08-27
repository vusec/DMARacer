#!/usr/bin/env python3

import os
import psutil
import sys
import subprocess
import time

# This script just calls the args it's called with as an argument and acts
# like a fake PID 1 in docker by reaping orphan processes.
# This is needed as the target compiler might randomly crash and leave it's
# child processes behind. This would otherwise slowly flood the system with
# orphans.

shell = subprocess.Popen(sys.argv[1:])

def _should_kill_child(child: psutil.Process):
    # Only kill zombies.
    if child.status() != psutil.STATUS_ZOMBIE:
        return False
    return True


def kill_zombie_children_of_pid(pid: int):
    process = psutil.Process(pid=pid)
    children = process.children(recursive=False)
    for child in children:
        if _should_kill_child(child=child):
            child.kill()
            try:
                child.wait(timeout=1)
                # For debugging only.
                #print("[*] Killed zombie process")
            except psutil.TimeoutExpired as e:
                print("[*] Failed to kill zombie process")


while shell.poll() is None:
    time.sleep(1)
    kill_zombie_children_of_pid(os.getpid())

shell.wait()