from db.common import *
import subprocess, os, re, concurrent.futures

# Get the file in the last 'line' of a source line.
# E.g., convert line: "ext4_blocks_count at fs/ext4/ext4.h:3269:9\n(inlined by) dfs$ext4_inode_to_goal_block at fs/ext4/balloc.c:978:15"
#          into file: "fs/ext4/balloc.c"
def line_to_file(line):
    file = line.split('\n')[-1].split(' at ')[-1].split(':')[0]
    return file

def execute(cmd, cwd, env_addition):
    out = ""
    env = os.environ.copy()
    for key in env_addition: env[key] = env_addition[key]
    with subprocess.Popen(cmd, bufsize=1, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=cwd, env=env) as p:
        for line in p.stdout: out += line
        for line in p.stderr: out += "\n" + line + "FILLER-LINE\n"
    if p.returncode != 0: raise subprocess.CalledProcessError(p.returncode, p.args)
    return out

def run_faddr2line(linux_path, addrs):
    # Invoke faddr2line
    cmd = ['scripts/faddr2line', 'vmlinux'] + addrs
    out = execute(cmd, linux_path, {'LLVM':'-14'})

    # Parse faddr2line output
    lines = []
    stanzas = out.split("\n\n") # faddr2line prints an empty line between each result
    for stanza in stanzas:
        if stanza == "": continue # The empty line at the end is okay
        stanza_lines = stanza.splitlines()
        stanza_lines = [s for s in stanza_lines if not s.startswith("skipping ")] # Remove any strings that start with "skipping "

        if len(stanza_lines) < 2:
            print("Warning: Skipping output of faddr2line that has less than 2 lines: " + stanza)
            continue

        if any('no match for ' in l for l in stanza_lines):
            for line in stanza_lines:
                if "no match for " in line:
                    addr = line.split("no match for ")[1]
                    line = UNKNOWN_STR
                    file = UNKNOWN_STR
                    print("Warning: Could not find line for addr '" + addr + "'")
                    break
        else:
            addr = re.sub(':$', '', stanza_lines[0])
            line = '\n'.join(stanza_lines[1:])
            file = line_to_file(line)

        if addr not in addrs: EXIT_ERR("Parsed addr '" + addr + "' from faddr2line was not found in reports' backtraces. faddr2line output: " + out)
        lines += [{"srcaddr": addr, "srcline": line, "srcfile": file}]
    return lines

def add_srclines(linux_path, nproc):
    addrs_r = reports_col.distinct("backtrace")
    addrs_region = reports_col.distinct("region.alloc_backtrace")
    addrs_streaming = reports_col.distinct("streaming_dma_access.last_sync_backtrace")
    addrs = sorted(list(set(addrs_r).union(set(addrs_region), set(addrs_streaming))))
    if "LOG_REGION_ALL" in addrs: addrs.remove("LOG_REGION_ALL")
    if "LOG_REGION_AFF" in addrs: addrs.remove("LOG_REGION_AFF")
    nproc = min(nproc, len(addrs))
    print("Converting " + str(len(addrs)) + " addresses to lines using " + str(nproc) + " processes...")

    addrs_split = [addrs[i*len(addrs)//nproc : (i+1)*len(addrs)//nproc] for i in range(nproc)]
    lines = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=nproc) as executor:
        futures = [executor.submit(run_faddr2line, linux_path, addr_split) for addr_split in addrs_split]
        for future in concurrent.futures.as_completed(futures):
            lines += future.result()

    lines += [{"srcaddr": "LOG_REGION_ALL", "srcline": UNKNOWN_STR, "srcfile": UNKNOWN_STR}]
    lines += [{"srcaddr": "LOG_REGION_AFF", "srcline": UNKNOWN_STR, "srcfile": UNKNOWN_STR}]
    lines_col.insert_many(lines) # Add (addr, line) info to DB

def backup_db():
    print("Backing up DB...")
    subprocess.run('./backup-db.sh')

def analyze_reports(linux_path, nproc):
    print("Analyzing " + str(reports_col.count_documents({})) + " reports...")
    add_srclines(linux_path, nproc)
    backup_db()
