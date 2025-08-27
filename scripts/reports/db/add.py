from db.common import *
import json, operator
from decimal import Decimal
from bson.decimal128 import Decimal128

cleanup_backtrace_non_runtime_warnings = []
def cleanup_backtrace_non_runtime_warning(bt_rip):
    global cleanup_backtrace_non_runtime_warnings
    if bt_rip in cleanup_backtrace_non_runtime_warnings: return # Don't print duplicate warnings
    print("Warning: Discarding a part of backtrace that is NOT in the KDFSAN runtime: " + bt_rip)
    cleanup_backtrace_non_runtime_warnings += [bt_rip]

FUNCS_KDF_RT = ('kdfsan_', 'kdf_', '__dfsan_', 'dfsan_', '__dfsw_')
FUNCS_DMA_RT = ('dfs$dma_alloc_', 'dfs$dma_map_', 'dfs$dma_sync_', 'dfs$dma_pool_alloc', 'dfs$__dma_map_', 'dfs$dmam_alloc_')

def cleanup_backtrace(bt, rip, funcs_clean):
    if rip not in bt: EXIT_ERR("Error: Reported RIP not in backtrace! rip = " + rip + ", bt = " + str(bt))
    # Remove the KDFSAN runtime from the top of the callstack
    before_rip = True
    while before_rip or bt[0].startswith(funcs_clean):
        if before_rip and bt[0] == rip:
            before_rip = False
            continue
        if not bt[0].startswith(funcs_clean): cleanup_backtrace_non_runtime_warning(bt[0])
        bt.pop(0)
    return bt,bt[0]

def add_reports(reports_path):
    print("Adding reports from file '" + reports_path + "'...")
    with open(reports_path, "r") as stream: rs = json.load(stream)
    rs.sort(key=lambda x: (x['dev'], x['fuzzing_run'], x['report_id']))
    for r in rs:
        # Because Mongo (i.e., BSON) can't handle unsigned 64-bit ints
        r['access']['addr'] = Decimal128(Decimal(r['access']['addr']))
        if 'region' in r:
            r['region']['cpu_addr'] = Decimal128(Decimal(r['region']['cpu_addr']))
            r['region']['alloc_backtrace'],r['region']['alloc_rip'] = cleanup_backtrace(r['region']['alloc_backtrace'], r['region']['alloc_rip'], FUNCS_KDF_RT+FUNCS_DMA_RT)
        if 'streaming_dma_access' in r:
            r['streaming_dma_access']['last_sync_backtrace'],r['streaming_dma_access']['last_sync_rip'] = cleanup_backtrace(r['streaming_dma_access']['last_sync_backtrace'], r['streaming_dma_access']['last_sync_rip'], FUNCS_KDF_RT+FUNCS_DMA_RT)
        r['backtrace'],r['rip'] = cleanup_backtrace(r['backtrace'], r['rip'], FUNCS_KDF_RT)
        r['next_reports'] = []
        r['next_vuln_reports'] = []
        r['prev_reports_dma_load'] = []
        r['prev_reports_dma_store'] = []
        r['is_toctou'] = False
        r['is_toitou'] = False
        for rtmp in rs:
            if r['dev'] == rtmp['dev'] and r['fuzzing_run'] == rtmp['fuzzing_run']:
                if r['report_id'] in rtmp['prev_reports']:
                    r['next_reports'] += [rtmp['report_id']]
                    if rtmp['report_type'].startswith("VULN_"): r['next_vuln_reports'] += [rtmp['report_id']]
                if rtmp['report_id'] in r['prev_reports']:
                    if rtmp['instr_type'] == 'LOAD':
                        r['prev_reports_dma_load'] += [rtmp['report_id']]
                        if r['report_type'] == 'DMA_2F': r['is_toctou'] = True
                    if rtmp['instr_type'] == 'STORE':
                        r['prev_reports_dma_store'] += [rtmp['report_id']]
                        if r['report_type'] == 'DMA_2F': r['is_toitou'] = True
                    if rtmp['is_toctou']: r['is_toctou'] = True
                    if rtmp['is_toitou']: r['is_toitou'] = True
    #for r in rs: print(yaml.dump(r))
    reports_col.insert_many(rs)

def delete_reports():
    print("Deleting reports collection...")
    reports_col.drop()

def delete_lines():
    print("Deleting lines collection...")
    lines_col.drop()
