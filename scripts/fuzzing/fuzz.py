#!/usr/bin/python3 -u

import argparse, sys, psutil, time, concurrent.futures, subprocess, os
from devs import devs

################################################################################
#### Data ######################################################################

# Knobs for parallel processing
PARALLEL_DELAY_SEC = 10
PARALLEL_MAX_PROCS = None
PARALLEL_MEMFREE_GB = 15

# Set by command-line arguments
fuzz_time_sec = None
out_dir = None

################################################################################
#### Helpers ###################################################################

def available_mem_gb():
    return int(psutil.virtual_memory().available/(1024**3))

def num_running_threads(futures):
    return sum(1 for future in futures if future.running())

def substitute(original_list, target, replacement):
    result = []
    for item in original_list:
        if item == target: result.extend(replacement)
        else: result.append(item)
    return result

################################################################################
#### Core fuzzing code #########################################################

def fuzz(target_dev, status):
    target_dev_type = devs[target_dev]['type']
    print(status + " Fuzzing " + target_dev_type + " device " + target_dev + "...")

    env_addition = {}
    match target_dev_type:
        case 'audio':   env_addition = {"INPUT_DEV": target_dev}
        case 'gpu':     env_addition = {"INPUT_DEV": target_dev, "QEMU_FUZZER_INPUTS": "1"}
        case 'input':   env_addition = {"INPUT_DEV": target_dev, "QEMU_FUZZER_INPUTS": "1"}
        case 'net':     env_addition = {"NICMODEL": target_dev}
        case 'storage': env_addition = {"STORAGE_DEV": target_dev}
        case _: print(status + " Error: Device " + target_dev + " has unknown type " + target_dev_type, file=sys.stderr); return

    # Create a readable output file name from the list of flags.
    output_filename = target_dev.replace(" ", "_").replace("-device", "").replace(",", "_") # type: str
    output_filename = output_filename.replace("-", "_").replace("__", "_")
    output_filename = output_filename.strip("_")

    with open(out_dir+"/dev-"+output_filename+".out", "w") as outfile:
        try:
            subprocess.run(["python3", "scripts/expect/qemu.py", "--whitelist", "d", "--fuzz", target_dev_type, "--early_enable"], stdout=outfile, stderr=subprocess.STDOUT, env={**os.environ, **env_addition}, timeout=fuzz_time_sec) # Should timeout
            print(status + " Error: Fuzzing campaign for " + target_dev_type + " device " + target_dev + " finished before it was supposed to!", file=sys.stderr)
            return
        except subprocess.TimeoutExpired:
            print(status + " Done fuzzing " + target_dev_type + " device " + target_dev + "!")

def parallel_fuzz(target_devs):
    with concurrent.futures.ThreadPoolExecutor(max_workers=PARALLEL_MAX_PROCS) as executor:
        orig_available_mem = available_mem_gb()
        print("Fuzzing with " + str(orig_available_mem) + " GB available memory to start...")
        if orig_available_mem < PARALLEL_MEMFREE_GB: sys.exit("Error: Not enough memory to run 1 VM (minimum " + str(PARALLEL_MEMFREE_GB) + " GB)")
        futures = []
        for i, target_dev in enumerate(target_devs, start=1):
            time.sleep(0.1)
            while orig_available_mem < PARALLEL_MEMFREE_GB * (num_running_threads(futures) + 1): time.sleep(1) # Wait until enough memory _should be_ available
            while available_mem_gb() < PARALLEL_MEMFREE_GB: time.sleep(1) # Wait until enough memory _is_ available
            futures.append(executor.submit(fuzz, target_dev, f"({i}/{len(target_devs)})")) # Submit the fuzz function to be executed in parallel
        concurrent.futures.wait(futures) # Ensure all futures are completed

################################################################################
#### Main ######################################################################

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Fuzz target devices.')
    parser.add_argument('--fuzz_time', required=True, type=int, help="duration of fuzzing in minutes")
    parser.add_argument('--out_dir', required=True, help="directory to output logs")
    parser.add_argument('--target_devs', required=True, nargs='+', help="the target device(s) to fuzz (e.g., 'e1000 tulip vmxnet3', or 'ALL' for all devices, or 'NET INPUT' for all network and input devices)")
    args = parser.parse_args()

    fuzz_time_sec = args.fuzz_time * 60
    out_dir = args.out_dir

    target_devs = args.target_devs
    target_devs = substitute(target_devs, 'ALL', list(devs.keys()))
    target_devs = substitute(target_devs, 'AUDIO', [k for k,v in devs.items() if v['type'] == 'audio'])
    target_devs = substitute(target_devs, 'GPU', [k for k,v in devs.items() if v['type'] == 'gpu'])
    target_devs = substitute(target_devs, 'INPUT', [k for k,v in devs.items() if v['type'] == 'input'])
    target_devs = substitute(target_devs, 'NET', [k for k,v in devs.items() if v['type'] == 'net'])
    target_devs = substitute(target_devs, 'STORAGE', [k for k,v in devs.items() if v['type'] == 'storage'])
    target_devs = [k for k in devs.keys() if k in dict.fromkeys(target_devs)] # Deduplicate and sort it based on the order of devs' keys
    if not all(dev in devs for dev in target_devs): sys.exit("Error: Unknown target_dev specified")

    parallel_fuzz(target_devs)