#!/usr/bin/env -S python3 -u

from db.add import add_reports, delete_lines, delete_reports
from db.analyze import analyze_reports
from db.inspect import inspect
from db.output import print_debug_tables, print_paper_tables
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process Fetch Detector reports.')
    parser.add_argument('action', choices=['add_reports', 'analyze_reports', 'inspect', 'delete_lines', 'delete_reports', 'print_debug_tables', 'print_paper_tables'], help='action to perform')
    parser.add_argument('--json_path', metavar='path', help="the path to the JSON reports file")
    parser.add_argument('--linux_path', metavar='path', help="the path to the Linux directory")
    parser.add_argument('--nproc', metavar='nproc', type=int, default=1, help="the number of processes to use (default = 1)")
    args = parser.parse_args()
    if args.action == 'add_reports' and args.json_path is None:
        parser.error("Argument --json_pathis required.")
    if (args.action == 'analyze_reports' or args.action == 'inspect') and args.linux_path is None:
        parser.error("Argument --linux_path is required.")

    match args.action:
        case 'add_reports': add_reports(args.json_path)
        case 'analyze_reports': analyze_reports(args.linux_path, args.nproc)
        case 'inspect': inspect(args.linux_path)
        case 'delete_lines': delete_lines()
        case 'delete_reports': delete_reports()
        case 'print_debug_tables': print_debug_tables()
        case 'print_paper_tables': print_paper_tables()