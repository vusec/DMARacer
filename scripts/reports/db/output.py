from db.common import *
from tabulate import tabulate
from collections import defaultdict
import csv, textwrap

################################################################################
######## "Debug" tables ########################################################

def print_count_per_rt():
    op_group_rtit = {"$group": {"_id": {"rt": "$report_type", "it": "$instr_type"}, "rips": {"$addToSet": "$rip"}}}
    op_group_rt = {"$group": {"_id": {"rt": "$report_type"}, "rips": {"$addToSet": "$rip"}}}
    op_count_rips = {"$project": {"num_rips": {"$size": "$rips"}}}
    op_sort = {"$sort" : { "_id": 1}}
    ag_rt = reports_col.aggregate([op_group_rt,op_count_rips, op_sort])
    ag_rtit = reports_col.aggregate([op_group_rtit,op_count_rips, op_sort])

    tbl = []
    for r in list(ag_rt): tbl.append(["{rt}".format(rt=r["_id"]["rt"]), r["num_rips"]])
    print(tabulate(tbl, headers=['Report type', 'Count']))
    print()

    tbl = []
    for r in list(ag_rtit): tbl.append(["{rt} ({it})".format(rt=r["_id"]["rt"], it=r["_id"]["it"]), r["num_rips"]])
    print(tabulate(tbl, headers=['Report type (instr type)', 'Count']))
    print()


def print_rt_per_file():
    report_types = sorted(reports_col.distinct("report_type")) # E.g., ['DMA_1F', 'DMA_2F', 'DMA_INV', 'MMIO_1F', 'MMIO_2F', 'VULN_COND', 'VULN_STORE']

    # Aggregate data
    pipeline = [{"$lookup": {"from": "srclines", "localField": "rip", "foreignField": "srcaddr", "as": "source_info"}},
                {"$unwind": "$source_info"},
                {"$group": {"_id": {"srcfile": "$source_info.srcfile", "report_type": "$report_type", "rip": "$rip"},
                            "count": {"$sum": 1}}},
                {"$group": {"_id": {"srcfile": "$_id.srcfile", "report_type": "$_id.report_type"},
                            "total_count": {"$sum": 1}}},
                {"$group": {"_id": "$_id.srcfile",
                            "report_counts": {"$push": {"report_type": "$_id.report_type", "total_count": "$total_count"}},
                            "total": {"$sum": "$total_count"}}}]

    results = list(db.reports.aggregate(pipeline))

    # Prepare table data
    table_data = []
    total_counts = {report_type: 0 for report_type in report_types}
    for result in results:
        srcfile = result["_id"]
        report_counts = {entry["report_type"]: entry["total_count"] for entry in result["report_counts"]}
        table_row = [srcfile]
        for report_type in report_types:
            count = report_counts.get(report_type, 0)
            table_row.append(count if count != 0 else "-")
            total_counts[report_type] += count
        table_data.append(table_row)

    # Sort rows alphabetically by srcfile
    table_data_sorted = sorted(table_data, key=lambda x: x[0])

    # Add total row
    total_row = ["TOTAL"]
    for report_type in report_types:
        total_row.append(total_counts[report_type])
    table_data_sorted.append(total_row)

    # Print table
    headers = ['Source file'] + report_types
    print(tabulate(table_data_sorted, headers=headers))
    print()

def print_rt_per_dev():
    report_types = sorted(reports_col.distinct("report_type")) # E.g., ['DMA_1F', 'DMA_2F', 'DMA_INV', 'VULN_COND', 'VULN_STORE']

    # Aggregate data
    pipeline = [{"$group": {"_id": {"dev": "$dev", "report_type": "$report_type", "rip": "$rip"}, "count": {"$sum": 1}}},
                {"$group": {"_id": {"dev": "$_id.dev", "report_type": "$_id.report_type"}, "total_count": {"$sum": 1}}},
                {"$group": {"_id": "$_id.dev",
                            "report_counts": {"$push": {"report_type": "$_id.report_type", "total_count": "$total_count"}},
                            "total": {"$sum": "$total_count"}}}]

    results = list(db.reports.aggregate(pipeline))

    # Prepare table data
    table_data = []
    total_counts = {report_type: 0 for report_type in report_types}
    for result in results:
        dev = result["_id"]
        report_counts = {entry["report_type"]: entry["total_count"] for entry in result["report_counts"]}
        table_row = [dev]
        for report_type in report_types:
            count = report_counts.get(report_type, 0)
            table_row.append(count if count != 0 else "-")
            total_counts[report_type] += count
        table_data.append(table_row)

    # Sort rows alphabetically by dev
    table_data_sorted = sorted(table_data, key=lambda x: x[0])

    # Print table
    headers = ['Fuzzed device'] + report_types
    print(tabulate(table_data_sorted, headers=headers))
    print()

def print_debug_tables():
    print_count_per_rt()
    print_rt_per_file()
    print_rt_per_dev()

################################################################################
######## "Paper" tables ########################################################
################################################################################
################ Table 1 #######################################################

def print_bugs_per_src():
    # Define the new report types with subcolumns
    report_types = {
        'Streaming DMA': ['Allocs', 'Err. Accesses'],
        'Coherent DMA': ['Allocs', 'Err. Accesses', 'Vuln. Writes', 'Vuln. Loops', 'Vuln. Asserts']
    }

    # Aggregate data for DMA and vulnerability counts
    pipeline = [
        {"$match": {"report_type": {"$ne": "LOG_REGION_ALL"}}},
        {"$lookup": {"from": "srclines", "localField": "rip", "foreignField": "srcaddr", "as": "source_info"}},
        {"$unwind": "$source_info"},
        {"$group": {"_id": {"srcfile": "$source_info.srcfile", "report_type": "$report_type", "instr_type": "$instr_type", "rip": "$rip"}, "count": {"$sum": 1}}},
        {"$group": {"_id": {"srcfile": "$_id.srcfile", "report_type": {"$cond": [{"$or": [{"$eq": ["$_id.report_type", "DMA_1F"]}, {"$eq": ["$_id.report_type", "DMA_2F"]}]}, "DMA_1F_2F", "$_id.report_type"]}, "instr_type": "$_id.instr_type"}, "rips": {"$addToSet": "$_id.rip"}}},
        {"$project": {"_id": 1, "total_count": {"$size": "$rips"}}},
        {"$group": {"_id": "$_id.srcfile", "report_counts": {"$push": {"report_type": "$_id.report_type", "instr_type": "$_id.instr_type", "total_count": "$total_count"}}, "total": {"$sum": "$total_count"}}}
    ]

    # Step 1: Aggregate data for alloc counts
    alloc_pipeline = [
        {"$match": {"region": {"$exists": True}, "report_type": {"$ne": "LOG_REGION_ALL"}}},
        {"$project": {"alloc_rip": "$region.alloc_rip", "alloc_backtrace": "$region.alloc_backtrace", "is_streaming_dma": "$region.is_streaming_dma"}},  # Pass along alloc_rip, alloc_backtrace, and is_streaming_dma
        {"$group": {"_id": {"alloc_rip": "$alloc_rip", "alloc_backtrace": "$alloc_backtrace", "is_streaming_dma": "$is_streaming_dma"}}},  # Group by unique alloc_backtrace and is_streaming_dma
        {"$lookup": {"from": "srclines", "localField": "_id.alloc_rip", "foreignField": "srcaddr", "as": "source_info"}},  # Join with srclines to get the source file from alloc_rip
        {"$unwind": "$source_info"},  # Unwind the source_info array
        {"$group": {"_id": {"srcfile": "$source_info.srcfile", "is_streaming_dma": "$_id.is_streaming_dma"}, "alloc_count": {"$sum": 1}}}  # Group by srcfile and DMA type, count unique alloc_backtrace arrays
    ]

    results = list(db.reports.aggregate(pipeline))
    alloc_results = list(db.reports.aggregate(alloc_pipeline))

    # Step 2: Initialize data structures for storing counts
    dir_file_counts = defaultdict(set)
    dir_data = defaultdict(lambda: {
        'Streaming DMA': {'Allocs': 0, 'Err. Accesses': 0},
        'Coherent DMA': {'Allocs': 0, 'Err. Accesses': 0, 'Vuln. Writes': 0, 'Vuln. Loops': 0, 'Vuln. Asserts': 0}
    })

    # Step 3: Populate report counts
    for result in results:
        srcfile = result["_id"]
        srcdir = os.path.dirname(srcfile)
        dir_file_counts[srcdir].add(os.path.basename(srcfile))
        for entry in result["report_counts"]:
            if   entry['report_type'] == 'DMA_1F_2F': dir_data[srcdir]['Coherent DMA']['Err. Accesses'] += entry['total_count']
            elif entry['report_type'] == 'DMA_INV': dir_data[srcdir]['Streaming DMA']['Err. Accesses'] += entry['total_count']
            elif entry['report_type'] == 'VULN_STORE': dir_data[srcdir]['Coherent DMA']['Vuln. Writes'] += entry['total_count']
            elif entry['report_type'] == 'VULN_COND' and entry['instr_type'] == 'COND': dir_data[srcdir]['Coherent DMA']['Vuln. Loops'] += entry['total_count']
            elif entry['report_type'] == 'VULN_COND' and entry['instr_type'] == 'BUG': dir_data[srcdir]['Coherent DMA']['Vuln. Asserts'] += entry['total_count']
            elif entry['report_type'] == 'LOG_REGION_AFF': continue
            else: print("Warning: Unsupported report_type/instr_type: " + str(entry))

    # Step 4: Populate alloc counts
    for result in alloc_results:
        srcfile = result["_id"]["srcfile"]
        srcdir = os.path.dirname(srcfile)
        dir_file_counts[srcdir].add(os.path.basename(srcfile))  # Ensure this tracks files for allocs too
        is_streaming_dma = result["_id"]["is_streaming_dma"]
        alloc_count = result["alloc_count"]
        if is_streaming_dma: dir_data[srcdir]['Streaming DMA']['Allocs'] += alloc_count
        else: dir_data[srcdir]['Coherent DMA']['Allocs'] += alloc_count

    # Combine directories and subdirectories and decide if we show `/*` or the full file name
    combined_dir_data = defaultdict(lambda: {
        'Streaming DMA': {'Allocs': 0, 'Err. Accesses': 0},
        'Coherent DMA': {'Allocs': 0, 'Err. Accesses': 0, 'Vuln. Writes': 0, 'Vuln. Loops': 0, 'Vuln. Asserts': 0}
    })

    for srcdir, counts in dir_data.items():
        file_count = len(dir_file_counts[srcdir])
        # If multiple files, show as "directory/*", otherwise show the single file name
        if file_count > 1: display_dir = f"{srcdir}/*"
        elif file_count == 1: display_dir = f"{srcdir}/{list(dir_file_counts[srcdir])[0]}"  # Get the single file name
        else: display_dir = srcdir  # Handle case where dir_file_counts[srcdir] is empty: Just show the directory if no files are found
        for category, subcounts in counts.items():
            for subcol, count in subcounts.items():
                combined_dir_data[display_dir][category][subcol] += count

    # Prepare table data
    table_data = []
    total_counts = defaultdict(lambda: defaultdict(int))
    for srcdir, counts in combined_dir_data.items():
        table_row = [srcdir]
        table_row.append("|")  # Empty column before "Streaming DMA"
        for category in report_types:
            for subcol in report_types[category]:
                count = counts[category][subcol]
                table_row.append(count if count != 0 else "-")
                total_counts[category][subcol] += count
            if category == 'Streaming DMA':
                table_row.append("|")  # Empty column before "Coherent DMA"
        table_data.append(table_row)

    # Sort and add totals
    table_data_sorted = sorted(table_data, key=lambda x: x[0])
    total_row = ["TOTAL"]
    total_row.append("|")
    for category in report_types:
        for subcol in report_types[category]:
            total_row.append(total_counts[category][subcol])
        if category == 'Streaming DMA':
            total_row.append("|")
    table_data_sorted.append(total_row)

    # Define headers
    headers = ['Kernel Source', '|\n|', 'Streaming DMA\nAff. Regions', '\nErr. Accesses', '|\n|', 'Coherent DMA\nAff. Regions', '\nErr. Accesses', '\nVuln. Writes', '\nVuln. Loops', '\nVuln. Asserts']

    # Print final table
    print(tabulate(table_data_sorted, headers=headers, colalign=("left", "center", "right", "right", "center", "right", "right", "right", "right", "right")))
    print()

################################################################################
################ Table 2 #######################################################

def print_allocs_per_src_get_grouped_results():
    alloc_pipeline = [
        {"$match": {"region": {"$exists": True}, "report_type": {"$ne": "LOG_REGION_ALL"}}},
        {"$group": {"_id": "$region.alloc_rip"}},
        {"$lookup": {"from": "srclines", "localField": "_id", "foreignField": "srcaddr", "as": "source_info"}},
        {"$unwind": "$source_info"},
        {"$group": {"_id": "$source_info.srcfile", "unique_alloc_rips": {"$sum": 1}}}
    ]
    alloc_results = db.reports.aggregate(alloc_pipeline)
    grouped_results = defaultdict(lambda: {'aff_allocs_covered': 0})
    for result in alloc_results:
        srcfile = result["_id"]
        second_level_dir = "/".join(srcfile.split("/")[:2]) + "/" if "/" in srcfile else srcfile + "/"
        grouped_results[second_level_dir]['aff_allocs_covered'] += result["unique_alloc_rips"]
    return grouped_results

def print_allocs_per_src_get_allocs_covered():
    alloc_pipeline = [
        {"$match": {"region": {"$exists": True}, "report_type": "LOG_REGION_ALL"}},
        {"$group": {"_id": "$region.alloc_rip"}},
        {"$lookup": {"from": "srclines", "localField": "_id", "foreignField": "srcaddr", "as": "source_info"}},
        {"$unwind": "$source_info"},
        {"$group": {"_id": "$source_info.srcfile", "unique_alloc_rips": {"$sum": 1}}}
    ]
    alloc_results = db.reports.aggregate(alloc_pipeline)
    grouped_results = defaultdict(lambda: {'allocs_covered': 0})
    for result in alloc_results:
        srcfile = result["_id"]
        second_level_dir = "/".join(srcfile.split("/")[:2]) + "/" if "/" in srcfile else srcfile + "/"
        grouped_results[second_level_dir]['allocs_covered'] += result["unique_alloc_rips"]
    return grouped_results

def print_allocs_per_src_read_csv_allocs(filename):
    kernel_allocs = defaultdict(int)
    with open(filename, 'r') as csvfile:
        for object_file, count in csv.reader(csvfile):
            second_level_dir = "/".join(object_file.split("/")[:2]) + "/" if "/" in object_file else object_file + "/"
            kernel_allocs[second_level_dir] += int(count)
    return kernel_allocs

def print_allocs_per_src():
    grouped_results = print_allocs_per_src_get_grouped_results()
    allocs_covered_results = print_allocs_per_src_get_allocs_covered()
    second_level_dirs_with_aff_allocs = set(grouped_results.keys())
    top_level_dirs_with_aff_allocs = set(dir.split('/')[0] + '/' for dir in second_level_dirs_with_aff_allocs)

    table_rows = {}
    for dir, counts in grouped_results.items():
        table_rows[dir] = {
            'Kernel Source': dir,
            'Entire Kernel Allocs': '-',
            'Allocs Covered': 0,
            'Aff. Allocs Covered': counts['aff_allocs_covered']
        }

    entire_kernel_allocs = print_allocs_per_src_read_csv_allocs('tables/allocs/entire-kernel-allocs.csv')

    table_rows['/ (other dirs.)'] = {
        'Kernel Source': '/ (other dirs.)',
        'Entire Kernel Allocs': 0,
        'Allocs Covered': 0,
        'Aff. Allocs Covered': 0
    }

    all_alloc_dirs = set(entire_kernel_allocs)
    for dir in all_alloc_dirs:
        count_entire = entire_kernel_allocs.get(dir, 0)
        if dir in table_rows:
            row = table_rows[dir]
            row['Entire Kernel Allocs'] = count_entire or '-'
        else:
            top_level_dir = dir.split('/')[0] + '/'
            row_key = f'{top_level_dir} (other dirs.)' if top_level_dir in top_level_dirs_with_aff_allocs else '/ (other dirs.)'
            if row_key not in table_rows:
                table_rows[row_key] = {
                    'Kernel Source': row_key,
                    'Entire Kernel Allocs': 0,
                    'Allocs Covered': 0,
                    'Aff. Allocs Covered': '-' if 'other dirs.' in row_key else 0
                }
            row = table_rows[row_key]
            row['Entire Kernel Allocs'] += count_entire

    for dir, counts in allocs_covered_results.items():
        allocs_covered = counts['allocs_covered']
        if dir in table_rows and table_rows[dir]['Aff. Allocs Covered'] != '-':
            table_rows[dir]['Allocs Covered'] += allocs_covered
        else:
            top_level_dir = dir.split('/')[0] + '/'
            row_key = f'{top_level_dir} (other dirs.)' if top_level_dir in top_level_dirs_with_aff_allocs else '/ (other dirs.)'
            if row_key not in table_rows:
                table_rows[row_key] = {
                    'Kernel Source': row_key,
                    'Entire Kernel Allocs': 0,
                    'Allocs Covered': 0,
                    'Aff. Allocs Covered': '-' if 'other dirs.' in row_key else 0
                }
            table_rows[row_key]['Allocs Covered'] += allocs_covered

    for row in table_rows.values():
        if row['Aff. Allocs Covered'] == 0: row['Aff. Allocs Covered'] = '-'
        if row['Allocs Covered'] == 0: row['Allocs Covered'] = '-'

    table_data = []
    total_entire_allocs = total_aff_covered = total_allocs_covered = 0

    def sort_key(row):
        ks = row['Kernel Source']
        if ks == 'TOTAL': return ('zzzz',)
        if ks == '/ (other dirs.)': return ('zzz',)
        top_level = ks.split('/')[0] + '/'
        is_other = 1 if ' (other dirs.)' in ks else 0
        return (top_level, is_other, ks)

    for row in sorted(table_rows.values(), key=sort_key):
        entire_allocs = row['Entire Kernel Allocs']
        allocs_covered = row['Allocs Covered']
        aff_allocs_covered = row['Aff. Allocs Covered']

        if isinstance(entire_allocs, int):
            total_entire_allocs += entire_allocs
            entire_allocs = entire_allocs or '-'
        if isinstance(allocs_covered, int):
            total_allocs_covered += allocs_covered
            allocs_covered = allocs_covered or '-'
        if isinstance(aff_allocs_covered, int):
            total_aff_covered += aff_allocs_covered
            aff_allocs_covered = aff_allocs_covered or '-'

        table_data.append([row['Kernel Source'], '|', entire_allocs, '|', allocs_covered, aff_allocs_covered])

    total_row = ['TOTAL', '|', total_entire_allocs or '-', '|', total_allocs_covered or '-', total_aff_covered or '-']
    table_data.append(total_row)

    headers = ['Kernel Source', '|\n|', 'Entire Kernel\nAllocs', '|\n|', 'Our Kernel\nAllocs Covered', '\nAff. Allocs Covered']

    print(tabulate(table_data, headers=headers, colalign=("left", "center", "right", "center", "right", "right")))
    print()

################################################################################
################ Table 3 #######################################################

def print_toctou_vs_toitou_bugs():
    toctou_count = len(list(db.reports.aggregate([
        {'$match': {'report_type': 'DMA_2F', 'prev_reports_dma_load.0': {'$exists': True}}},
        {'$group': {'_id': '$rip'}}
    ])))
    toitou_covered_count = len(list(db.reports.aggregate([
        {'$match': {'report_type': 'DMA_2F', 'prev_reports_dma_store.0': {'$exists': True}}},
        {'$group': {'_id': '$rip'}}
    ])))
    toitou_noncovered_count = len(list(db.reports.aggregate([
        {'$match': {'report_type': 'DMA_1F', 'instr_type': 'STORE', 'next_reports.0': {'$exists': False}}},
        {'$group': {'_id': '$rip'}}
    ])))
    total_count = toctou_count + toitou_covered_count + toitou_noncovered_count
    print(f"TOCTOU bug count: {toctou_count}")
    print(f"TOITOU covered bug count: {toitou_covered_count}")
    print(f"TOITOU non-covered bug count: {toitou_noncovered_count}")
    print(f"Total bug count: {total_count}" )
    print(textwrap.fill("Note: This total count does not equal the total count from the 'race conditions' table, because that counts both the first and second accesses; this only counts pairs of accesses. (Or, in the case of non-covered TOITOU bugs, a single access).", 85))


def print_toctou_vs_toitou_vulns():
    toctou_rips = set(r['_id'] for r in db.reports.aggregate([
        {'$match': {'report_type': {'$in': ['VULN_COND', 'VULN_STORE']}, 'is_toctou': True}},
        {'$group': {'_id': '$rip'}}
    ]))

    toitou_rips = set(r['_id'] for r in db.reports.aggregate([
        {'$match': {'report_type': {'$in': ['VULN_COND', 'VULN_STORE']}, 'is_toitou': True}},
        {'$group': {'_id': '$rip'}}
    ]))

    toctou_vuln_count = len(toctou_rips)
    toitou_vuln_count = len(toitou_rips)
    total_count = len(toctou_rips.union(toitou_rips))

    total_count = toctou_vuln_count + toitou_vuln_count
    print(f"TOCTOU-based vulnerability count: {toctou_vuln_count}")
    print(f"TOITOU-based vulnerability count: {toitou_vuln_count}")
    print(f"Total vulnerability count: {total_count}")
    print(textwrap.fill("Note: This total count does not equal the total count from the 'race conditions' table, because it counts a vuln. op once, whereas we can count it as a TOITOU- *and* a TOCTOU-based vuln.", 85))


def print_toctou_vs_toitou():
    print("*******************************************************************")
    print_toctou_vs_toitou_bugs()
    print()
    print_toctou_vs_toitou_vulns()
    print("*******************************************************************")

################################################################################
################ Table 4 #######################################################

eval_col = db.eval

def count_fp_tp(d):
    fp = sum(doc.get("eval_str")=="FP" for doc in d)
    tot= sum(doc.get("eval_str") in ["FP","TP"] for doc in d)
    return fp,tot

def get_coherent_errant_docs():
    ds=list(eval_col.find({"report_type":{"$in":["DMA_1F","DMA_2F"]}})); m={}
    for d in ds:
        r=d["rip"]; e=d.get("eval_str")
        if r not in m: m[r]=d
        else:
            e0=m[r].get("eval_str")
            if e0==e:
                if d["report_type"]=="DMA_2F": m[r]=d
            else:
                if e=="TP": m[r]=d
    return list(m.values())

def get_docs(rt=None,it=None):
    q={}
    if isinstance(rt,list): q["report_type"]={"$in":rt}
    elif rt: q["report_type"]=rt
    if it: q["instr_type"]=it
    return list(eval_col.find(q))

def print_fp_eval():
    lines=[]

    # --- Errant Accesses ---
    ds=get_docs("DMA_INV"); fp1,tot1=count_fp_tp(ds)
    ds=get_coherent_errant_docs(); fp2,tot2=count_fp_tp(ds)
    lines.append(("Errant Accesses","Streaming DMA",fp1,tot1))
    lines.append(("Errant Accesses","Coherent DMA",fp2,tot2))
    lines.append(("Errant Accesses","**All**",fp1+fp2,tot1+tot2))

    # --- Vuln. Operations ---
    ds=get_docs("VULN_STORE");       fp,tot=count_fp_tp(ds); lines.append(("Vuln. Operations","Writes",fp,tot))
    ds=get_docs("VULN_COND","COND"); fp,tot=count_fp_tp(ds); lines.append(("Vuln. Operations","Loops",fp,tot))
    ds=get_docs("VULN_COND","BUG");  fp,tot=count_fp_tp(ds); lines.append(("Vuln. Operations","Asserts",fp,tot))
    ds=get_docs(["VULN_STORE","VULN_COND"]); fp,tot=count_fp_tp(ds); lines.append(("Vuln. Operations","**All**",fp,tot))

    w1=max(len(x[0]) for x in lines)
    w2=max(len(x[1]) for x in lines)
    print("FP eval:")
    if not any(x[3]>0 for x in lines):
        print("- (No evaluations found.)")
        return
    for a,b,f,t in lines:
        pct=100*f/t if t else 0
        print(f"- {a.ljust(w1)}: {b.ljust(w2)}: {f} FPs / {t} total = {pct:.0f}% FP")

################################################################################
################ Interface #####################################################

def print_paper_tables():
    print_bugs_per_src()
    print_allocs_per_src()
    print_toctou_vs_toitou()