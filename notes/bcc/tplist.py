"""
显示内核跟踪点和 USDT 探测
"""

from bcc import USDT
import argparse
import fnmatch
import os
import re
import sys


trace_root = "/sys/kernel/debug/tracing"
event_root = os.path.join(trace_root, "events")

parser = argparse.ArgumentParser(
    description="显示内核跟踪点或 USDT 探针",
    formatter_class=argparse.RawDescriptionHelpFormatter,
)

parser.add_argument(
    "-p",
    "--pid",
    type=int,
    default=None,
    help="列出指定进程中的 USDT 探针",
)

parser.add_argument(
    "-l",
    "--lib",
    default="",
    help="列出指定库或可执行文件中的 USDT 探针",
)

parser.add_argument(
    "-v",
    dest="verbosity",
    action="count",
    default=0,
    help="增加详细程度(打印变量、参数等)",
)

parser.add_argument(
    dest="filter",
    nargs="?",
    help="指定要打印哪些探针/跟踪点的过滤器",
)

args = parser.parse_args()


def print_tpoint_format(category, event):
    fmt = open(os.path.join(event_root, category, event, "format")).readlines()

    for line in fmt:
        match = re.search(r"field:([^;]*);", line)

        if match is None:
            continue

        parts = match.group(1).split()
        field_name = parts[-1:][0]
        field_type = " ".join(parts[:-1])

        if field_name.startswith("common_"):
            continue

        print(f"    {field_type} {field_name};")


def print_tpoint(category, event):
    tpoint = f"{category}:{event}"

    if not args.filter or fnmatch.fnmatch(tpoint, args.filter):
        print(tpoint)

        if args.verbosity > 0:
            print_tpoint_format(category, event)


# 打印 /sys/kernel/debug/tracing/events 下的跟踪点
def print_tracepoints():
    for category in os.listdir(event_root):
        cat_dir = os.path.join(event_root, category)

        if not os.path.isdir(cat_dir):
            continue

        for event in os.listdir(cat_dir):
            evt_dir = os.path.join(cat_dir, event)

            if os.path.isdir(evt_dir):
                print_tpoint(category, event)


def print_usdt_argument_details(location):
    for idx in range(0, location.num_arguments):
        arg = location.get_argument(idx)
        print(f"    argument #{idx + 1} {arg}")


def print_usdt_details(probe):
    if args.verbosity > 0:
        print(probe)

        if args.verbosity > 1:
            for idx in range(0, probe.num_locations):
                loc = probe.get_location(idx)
                print(f"  location #{idx + 1} {loc}")
                print_usdt_argument_details(loc)
        else:
            print(f"  {probe.num_locations} location(s)")
            print(f"  {probe.num_arguments} argument(s)")
    else:
        print(f"{probe.bin_path.decode()} {probe.short_name()}")


def print_usdt(pid, lib):
    reader = USDT(path=lib, pid=pid)
    probes_seen = []  # 记录访问过的探针

    for probe in reader.enumerate_probes():
        probe_name = probe.short_name()

        if not args.filter or fnmatch.fnmatch(probe_name, args.filter):
            # 不存在 filter 或者 filter 匹配探针名
            if probe_name in probes_seen:
                continue

            probes_seen.append(probe_name)

            # 打印 usdt 详细信息
            print_usdt_details(probe)


if __name__ == "__main__":
    try:
        if args.pid or args.lib != "":
            # 指定 pid 或者 lib 时输出 usdt
            print_usdt(args.pid, args.lib)
        else:
            print_tracepoints()
    except:
        if sys.exc_info()[0] is not SystemExit:
            print(sys.exc_info()[1])
