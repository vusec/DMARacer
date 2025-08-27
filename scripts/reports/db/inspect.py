from db.common import *
import re
from tqdm import tqdm

###################################################################
######## Printing reports #########################################

def dec128_to_str(d128):
    return hex(int(d128.to_decimal()))

def get_backtrace_lines(bt, linux_path):
    lines = []
    for l in bt:
        if lines_col.find_one({"srcaddr": l}):
            srclines = lines_col.find_one({"srcaddr": l})['srcline']
            srclines = re.sub('.*:\n', '', srclines)
            srclines = re.sub('\n$', '', srclines)
            srclines = re.sub('\(inlined by\)', '    (inlined by)', srclines)
            for srcline in srclines.splitlines():
                if srcline == UNKNOWN_STR:
                    func,file = UNKNOWN_STR,UNKNOWN_STR
                else:
                    func,file = srcline.split(' at ')
                    file = linux_path + '/' + file
                lines += [{'func':func,'file':file}]
        else: lines += [{'func':'(unknown)', 'file':'(unknown)'}]
    return lines

def get_max_file_len(lines):
    max_file_len = 0
    for line in lines: max_file_len = max(max_file_len, len(line['file']))
    return max_file_len

def get_bt_printed_lines(lines, max_file_len, include_count):
    bt_to_print_lines = []
    for i,line in reversed(list(enumerate(reversed(lines)))):
        if include_count: bt_to_print_lines += [" " + str(i).rjust(2) + ". " + line['file'].ljust(max_file_len) + " -- " + line['func']]
        else: bt_to_print_lines += [" " + line['file'].ljust(max_file_len) + " -- " + line['func']]
    return bt_to_print_lines

def get_bt_printed_lines_diff(tl, pl):
    this_lines = list(reversed(tl))
    prev_lines = list(reversed(pl))
    del_count = 0
    for i,prev_line in enumerate(prev_lines):
        if i < len(this_lines) + del_count and prev_line == this_lines[i-del_count]:
            del this_lines[i-del_count]
            del_count += 1
        else: break
    if del_count > 0: this_lines = [' ... (same as previous backtrace) ...'] + this_lines
    this_lines.reverse()
    return this_lines

def print_backtrace_srclines(bt, linux_path, prev_printed_bt_lines, include_count):
    lines = get_backtrace_lines(bt, linux_path)
    max_file_len = get_max_file_len(lines)
    printed_bt_lines = get_bt_printed_lines(lines, max_file_len, include_count)
    for line in get_bt_printed_lines_diff(printed_bt_lines, prev_printed_bt_lines): print(line)
    return printed_bt_lines

def print_report(r, linux_path, prev_printed_bt_lines):
    print("====================================")
    print("Tested device: " + r['dev'])
    print("Fuzzing run: " + r['fuzzing_run'])
    print("Access: {addr: " + dec128_to_str(r['access']['addr']) + ", data_label: " + str(r['access']['data_label']) + ", ptr_label: " + str(r['access']['ptr_label']) + ", size: " + str(r['access']['size']) + "}")
    if 'region' in r: print("Region: {dev_id: " + str(r['region']['dev_id']) + ", region_addr: " + hex(r['region']['bus_addr']) + ", cpu_addr: " + dec128_to_str(r['region']['cpu_addr']) + ", s: " + str(r['region']['s']) + "}")
    print("Instruction type: " + r['instr_type'])
    print("Report type: " + r['report_type'])
    print("Report ID: " + str(r['report_id']))
    print("Previous report IDs:          " + str(r['prev_reports']))
    print("Previous DMA-LOAD report IDs: " + str(r['prev_reports_dma_load']))
    print("Next report IDs:              " + str(r['next_reports']))
    print("Next VULN report IDs:         " + str(r['next_vuln_reports']))
    print("RIP: " + (r['rip']))
    if lines_col.find_one({"srcaddr": r['rip']}): print("File: " + lines_col.find_one({"srcaddr": r['rip']})['srcfile'])
    else: print("File: (unknown)")
    print("Line:"); print_backtrace_srclines([r['rip']], linux_path, [], False)
    if INSPECT_BT: print("Backtrace:"); return print_backtrace_srclines(r['backtrace'], linux_path, prev_printed_bt_lines, True)
    else: return []

###################################################################
######## Report inspection routines ###############################

def count_rips(rs):
    unique_rips = {r['rip'] for r in rs}
    print("Number of unique RIPs: ", len(unique_rips))

def filter_out_cross_exec_context_prev_reports_get_related_report(r, related_report_id):
    # Return [related_report] if it shares a similar backtrace. Otherwise, return [].
    tmprs = list(reports_col.find(dict(**{"report_id": related_report_id, "dev": r['dev'], "fuzzing_run": r['fuzzing_run']})))
    if len(tmprs) != 1:
        print("Error: Should have found only 1 matching report, but found " + str(len(tmprs)))
        return []
    related_report = tmprs[0]
    return [r] if r['backtrace'][-1] == related_report['backtrace'][-1] and r['backtrace'][-2] == related_report['backtrace'][-2] and r['backtrace'][-3] == related_report['backtrace'][-3] else []

def filter_out_cross_exec_context_prev_reports(rs):
    count_rips(rs)
    filtered_rs = []
    print("Filtering out reports that don't have a related report from the same execution context. "
          "This depends on the report type:\n"
          "- For VULN reports: Check the last 'prev_report'.\n"
          "- For DMA_1F reports: Check the first 'next_report'.\n"
          "- For DMA_2F reports: Check the first 'next_report' AND the last 'prev_report'."
        )
    for r in tqdm(rs):
        if r['report_type'].startswith('VULN_') or r['report_type'] == 'DMA_2F':
            most_recent_report_id = r['prev_reports'][-1]
            filtered_rs = filtered_rs + filter_out_cross_exec_context_prev_reports_get_related_report(r, most_recent_report_id)
        if (r['report_type'] == 'DMA_1F' or r['report_type'] == 'DMA_2F') and len(r['next_reports']) > 0:
            next_report_id = r['next_reports'][0]
            filtered_rs = filtered_rs + filter_out_cross_exec_context_prev_reports_get_related_report(r, next_report_id)

    return filtered_rs

def save_evaluation(r):
    """
    Saves the evaluation into an 'eval' collection.
    The unique key will be a combination of (rip, report_type, instr_type),
    which map to (eval_str, comment, dev, fuzzing_run).

    Flow:
      1) Look up the old entry.
      2) If found, display it.
      3) Ask user whether they want to keep it or overwrite.
      4) If overwrite, prompt for new evaluation/comment and upsert.
    """
    print("\nEvaluating report with (rip, report_type, instr_type) = "
          f"({r['rip']}, {r['report_type']}, {r['instr_type']})...")

    eval_col = db.eval

    unique_key = {"rip": r['rip'], "report_type": r['report_type'], "instr_type": r['instr_type']}

    # 1) Look for an existing entry with this key
    old_entry = eval_col.find_one(unique_key)
    if old_entry:
        # 2) Display the old entry
        print("\nExisting evaluation found for (rip, report_type, instr_type) = "
              f"({r['rip']}, {r['report_type']}, {r['instr_type']}):")
        print(f"  eval_str   = {old_entry.get('eval_str')}")
        print(f"  comment    = {old_entry.get('comment')}")
        print(f"  dev        = {old_entry.get('dev')}")
        print(f"  fuzzing_run= {old_entry.get('fuzzing_run')}")

        # 3) Ask user if they want to keep or overwrite
        choice = input("Press Enter to overwrite or 'k' to keep existing (k)? ").strip().lower()
        if choice == 'k':
            print("Keeping existing record. No changes made.")
            return

    # If no old entry or user wants to overwrite, prompt for new data
    while True:
        eval_input = input("Enter evaluation: 't' (TP), 'f' (FP), 'u' (uncertain), 's' (skip): ").strip().lower()
        if eval_input in ['t', 'f', 'u', 's']: break
        print("Invalid input, please try again. Valid options are t/f/u/s.")

    if eval_input == 's': print("Skipping current evaluation. No changes made."); return
    elif eval_input == 't': eval_str = "TP"
    elif eval_input == 'f': eval_str = "FP"
    else: eval_str = "uncertain"

    comment_str = input("Enter optional comment: ").strip()

    eval_col.update_one(unique_key, {"$set": {"eval_str": eval_str, "comment": comment_str, "dev": r['dev'], "fuzzing_run": r['fuzzing_run']}}, upsert=True)
    print("Evaluation saved/updated!")

###################################################################
######## Report 'find' filter #####################################

def get_reports():
    ####################################################
    #### Old filters used when looking for case studies
    #FILTER = {"report_type": "DMA_2F"}
    #FILTER = {"report_type": "DMA_2F", "rip": {"$regex": "handle_tx_event"}} # DMA_2F reports that have "handle_tx_event" in the rip
    #FILTER = {"report_type": "DMA_2F", "next_vuln_reports": {"$ne": []}, "dev": {"$ne": "i82557b"}} # DMA_2F reports that have a dependent VULN op, that are NOT for the i82557b dev
    #FILTER = {"report_type": "DMA_2F", "next_vuln_reports": {"$ne": []}, "rip": {"$not": {"$regex": "e100"}}} # DMA_2F reports that have a dependent VULN op, that do not have "e100" in their RIP field
    #FILTER = {"report_type": "DMA_1F", "next_reports": {"$eq": []}} # DMA_1F:STOREs without a following DMA_2F
    #FILTER = {"report_type": "DMA_1F", "instr_type": "STORE"} # DMA_1F:STOREs
    #FILTER = {"report_type": "DMA_2F", "prev_reports_dma_load": {"$ne": []}} # TOCTOUs
    #FILTER = {"report_type": "DMA_2F", "prev_reports_dma_load": {"$ne": []}, "next_vuln_reports": {"$ne": []}} # TOCTOUs with a following VULN op
    #FILTER = {"report_type": "DMA_INV", "dev": "vmxnet3"} # DMA_INV reports for target dev "vmxnet3"
    #FILTER = {"report_type": "VULN_STORE", "rip": {"$regex": "uhci_start"}} # VULN_STORE (seemingly Write-What-Where) in UHCI via DMA pool. (Use with sort-by-report_id).
    #FILTER = {"report_type": "VULN_COND", "rip": {"$regex": "swiotlb"}}
    #FILTER = {"report_type": "VULN_STORE", "access.data_label": {"$ne": 0}, "access.ptr_label": {"$ne": 0}, "$expr": {"$ne": ["$access.data_label", "$access.ptr_label"]}} # VULN_STOREs where both the ptr and data are tainted differently
    #dma_pool_alloc

    ####################
    # FP eval filgters
    ##### Streaming DMA - Errant Accesses. (Sort by backtrace). Where the errant access is in the same execution context as the last sync operation AND it's not in a 'ret_from_fork_asm' context (because it seems they can go anywhere)
    #FILTER = {"report_type": "DMA_INV","backtrace.0": {"$exists": True},"streaming_dma_access.last_sync_backtrace.0": {"$exists": True},"$expr": {"$and": [{"$eq": [{"$arrayElemAt": ["$backtrace",{"$subtract": [{"$size": "$backtrace"}, 1]}]},{"$arrayElemAt": ["$streaming_dma_access.last_sync_backtrace",{"$subtract": [{"$size": "$streaming_dma_access.last_sync_backtrace"}, 1]}]}]},{"$ne": [{"$arrayElemAt": ["$backtrace",{"$subtract": [{"$size": "$backtrace"}, 1]}]},"ret_from_fork_asm+0x11/0x20"]}]}}
    ##### Coherent DMA  - Errant Accesses.
    #FILTER = {"$or":[{"report_type":"DMA_1F"},{"report_type":"DMA_2F"}]}
    ##### Coherent DMA  - Vuln. Writes. (Filter out cross execution context previous reports).
    #FILTER = {"report_type": "VULN_STORE"}
    ##### Coherent DMA  - Vuln. Loops.
    #FILTER = {"report_type": "VULN_COND", "instr_type": "COND"}
    ##### Coherent DMA  - Vuln. Asserts.
    #FILTER = {"report_type": "VULN_COND", "instr_type": "BUG"}
    FILTER = None

    if "CASE_STUDY" in os.environ:
        study = os.environ["CASE_STUDY"]
        match study:
            case "VMXNET3":
                FILTER = {"rip": {"$regex": "vmxnet3"}}
            case "swiotlb":
                FILTER = {"report_type": "VULN_COND", "rip": {"$regex": "swiotlb"}}
            case "dmapool":
                FILTER = {"report_type": "VULN_STORE", "rip": {"$regex": "uhci_start"}}

    #rs = sorted(list(reports_col.find(FILTER).clone()), key=lambda d: d['backtrace']) # Sort by backtrace
    #rs = sorted(list(reports_col.find(FILTER).clone()), key=lambda d: d['report_id']) # Sort by report_id
    rs = sorted(list(reports_col.find(FILTER).clone()), key=lambda d: (d['rip'], d['report_id'])) # Primary sort by rip, secondary sort by report_id

    rs = filter_out_cross_exec_context_prev_reports(rs)

    count_rips(rs)
    return rs

###################################################################
######## Main interactive loop ####################################

def inspect(linux_path):
    #inspect_streaming_last_sync_ops(linux_path); return
    rs = get_reports()
    NUM_REPORTS = len(rs)
    print("Found " + str(NUM_REPORTS) + " reports...")
    skip_backtrace = None
    skip_ip = None
    for i, r in enumerate(rs, 1):
        orig_r = r
        prev_printed_bt_lines = []
        if skip_backtrace:
            if r['backtrace'] == skip_backtrace: continue
            else: skip_backtrace = None
        if skip_ip:
            if r['backtrace'][0] == skip_ip: continue
            else: skip_ip = None
        print("========================================================")
        print("Report " + str(i) + " of " + str(NUM_REPORTS) + "...")
        #print(yaml.dump(r))
        prev_printed_bt_lines = print_report(r, linux_path, prev_printed_bt_lines)
        while True:
            print()
            inp = input(
                "Commands:\n"
                "  <Enter>   : continue\n"
                "  s         : skip all reports with this backtrace\n"
                "  S         : skip all reports with this IP\n"
                "  d         : view the region's alloc backtrace\n"
                "  l         : view last sync backtrace (for streaming DMA)\n"
                "  e         : evaluate (TP/FP/uncertain)\n"
                "  <number>  : view another report by ID\n"
                "Enter command: "
            )
            if inp == '': break
            elif inp == 's': skip_backtrace = orig_r['backtrace']; break
            elif inp == 'S': skip_ip = orig_r['backtrace'][0]; break
            elif inp == 'd' and 'region' in r:
                print("Region alloc backtrace:")
                print_backtrace_srclines(r['region']['alloc_backtrace'], linux_path, [], True)
                continue
            elif inp == 'l' and 'streaming_dma_access' in r:
                print("Last sync RIP: "); print_backtrace_srclines([r['streaming_dma_access']['last_sync_rip']], linux_path, [], False)
                print("Last sync backtrace:"); print_backtrace_srclines(r['streaming_dma_access']['last_sync_backtrace'], linux_path, [], True)
                continue
            elif inp == 'e':
                save_evaluation(orig_r)
                continue
            elif inp.isdigit():
                try: report_num = int(inp)
                except: continue
                print("Looking up report with report_num=" + str(report_num) + ", dev='" + r['dev'] + "', and fuzzing_run='" + r['fuzzing_run'] + "'...")
                tmprs = list(reports_col.find(dict(**{"report_id": report_num, "dev": r['dev'], "fuzzing_run": r['fuzzing_run']})))
                if len(tmprs) != 1: print("Error: Should have found only 1 matching report, but found " + str(len(tmprs))); continue
                r = tmprs[0]
                prev_printed_bt_lines = print_report(r, linux_path, prev_printed_bt_lines)

###################################################################
######## Optional: Inspect streaming last-sync ops ###############

def inspect_streaming_last_sync_ops(linux_path):
    pipeline = [
        {'$match': {'report_type': 'DMA_INV'}},
        {'$project': {'last_sync_rip': '$streaming_dma_access.last_sync_rip', 'rip': 1}},
        {'$match': {'last_sync_rip': {'$ne': None}}},
        {'$group': {'_id': '$last_sync_rip', 'unique_rips': {'$addToSet': '$rip'}}},
        {'$project': {'count': {'$size': '$unique_rips'}}},
        {'$sort': {'count': -1}}
    ]
    results = list(db.reports.aggregate(pipeline))
    for result in results:
        srcline = result['_id']
        count = result['count']
        print("Number of unique inconsistent access sites with _this_ as the last sync op: " + str(count))
        print_backtrace_srclines([srcline], linux_path, [], False)
        print()
