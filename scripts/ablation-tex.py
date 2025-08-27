import json
from statistics import geometric_mean, mean
import os
import sys

script_dir = os.path.dirname(os.path.realpath(__file__))

configs = {
    "1_with_kdfsan" : "+ KDFSan (Taint Tracking)",
    "2_with_dma_region_tracking" : "+ DMA Region Tracking",
    "3_with_memory_access_monitor_load" : "+ Load Monitoring",
    "4_with_memory_access_monitor_store" : "+ Store Monitoring",
    "5_with_memory_access_monitor_cmp" : "+ Compare Monitoring",
    "6_with_taint_aka_dmaracer" : "+ Reporting (DMARacer)",
}
baseline = "0_baseline"
full_version = "6_with_taint_aka_dmaracer"
# Number of samples we need.
expected_size = 20

bins = configs.values()

with open(os.path.join(script_dir, "reports/out/benchmark.json"), "r") as f:
    data = json.load(f)

def get_abs_overhead(config, func):
    benchmarks = data[config]
    means_of_benchmarks = []
    for bench, datapoints in benchmarks.items():
        assert len(datapoints) >= expected_size, f"{bench}:{len(datapoints)}"
        means_of_benchmarks += [func(datapoints[:expected_size])]

    return func(means_of_benchmarks)

def get_geomean_overhead(config):
    return get_abs_overhead(config,func=geometric_mean) / get_abs_overhead(baseline,func=geometric_mean) - 1

def get_mean_overhead(config):
    return get_abs_overhead(config,func=mean) / get_abs_overhead(baseline,func=mean) - 1


def make_table_contents(f):
    last_geomean = 0
    last_mean = 0
    for config in configs.keys():
        if config == baseline:
            continue
        geo_m = get_geomean_overhead(config) * 100
        geo_change = geo_m - last_geomean
        last_geomean = geo_m

        normal_mean = get_mean_overhead(config) * 100
        mean_change = normal_mean - last_mean
        last_mean = normal_mean

        row = str(configs[config]).ljust(30)
        row += f" & {normal_mean:.0f}\\% & {mean_change:+.0f}\\% ".ljust(20)
        row += f" & {geo_m:.0f}\\% & {geo_change:+.0f}\\% ".ljust(20)
        row += "\\\\ \n"
        roughly_none = "$\\approx$ 0\\%"
        row = row.replace("-0\\%", roughly_none)
        row = row.replace("+0\\%", roughly_none)
        f.write(row)

prefix = r"""
\begin{table}[t]
\small
\begin{center}
\caption{Runtime Overhead of \n{}'s components}\label{table:ablation}
\begin{tabular}{l | r r | r r}
    \toprule
    \thead{Enabled Component} & \thead{Mean} & $\Delta$ & \thead{Geomean} & $\Delta$ \\
    \midrule
    Default Kernel (Baseline) & 0\% &   & 0\% &  \\ 
"""
suffix = r"""
    \bottomrule
\end{tabular}
\end{center}
\end{table}
"""

#with open(os.path.join(script_dir, "..", "tables", "ablation.tex"), "w") as f:
#    f.write(prefix)
print("################ ABLATION ###################")
make_table_contents(sys.stdout)
#    f.write(suffix)


def get_abs_time_for_specific_bench(config, bench):
    benchmarks = data[config]
    datapoints = benchmarks[bench]
    assert len(datapoints) >= expected_size, f"{bench}:{len(datapoints)}"
    return mean(datapoints[:expected_size])
    
def make_bench_name(bench):
    bench = bench.replace("LMBENCH:", "")
    bench = bench.replace(":", "")
    bench = bench.replace("AF_UNIX", "UNIX")
    bench = bench.replace("to localhost", "")
    bench = bench.replace("using localhost", "")
    return bench

def get_bench_metric(bench):
    return "$\\mu$s"

def make_table_contents_full(f):
    benchmarks = data[baseline].keys()

    for bench in benchmarks:
        base_time = get_abs_time_for_specific_bench(baseline, bench)
        our_time = get_abs_time_for_specific_bench(full_version, bench)
        delta = our_time - base_time
        delta_percent = 100 * delta / base_time
        bench_name = make_bench_name(bench)
        bench_metric = get_bench_metric(bench)
        row = f"{bench_name} & {base_time:.2f}{bench_metric} & {our_time:.2f}{bench_metric} & {delta:.2f}{bench_metric} & +{delta_percent:.0f}\\% \\\\\n"
        f.write(row)

prefix = r"""
\begin{table}[h]
\small
\begin{center}
\caption{Runtime Overhead of \n{}}\label{table:ablation:full}
\begin{tabular}{l | r | r | r | r}
    \toprule
    \thead{\multirow{2}{*}{\vspace{-0.5em}Benchmark}} & \thead{\multirow{ 2}{*}{Baseline}} & \multicolumn{3}{c}{\thead{\n{}}} \\
    & \thead{Time} & \thead{Time} & \thead{Overhead} & \thead{Increase} \\
    \midrule
"""
suffix = r"""
    \bottomrule
\end{tabular}
\end{center}
\end{table}
"""

print("################ FULL TABLE ###################")
make_table_contents_full(sys.stdout)
