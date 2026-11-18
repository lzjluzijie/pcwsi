#!/usr/bin/env python3
"""Summarizes the rows of scripts/campaign.sh as Markdown tables in the layout of the paper's tables.

Usage: scripts/report.py [dir] (default data)

Every value is the median over the runs of a configuration. Times are in seconds, with the first run in parentheses
where it can differ (the parties' JVMs warm up during it). Communication is in MiB, counts sent and received bytes for
a party, and counts each transmission once for a total.
- Reductions: computation is the wall time minus blocking receives. Runtime is the latest party's wall time. In the
  tree, P_i forwards to P_floor(i/2), so internal nodes are 2 <= i <= n/2 and leaves are i > n/2. Computation and
  communication come from the rows labelled record if there are any (the parties computed one at a time), otherwise
  from the LAN rows; runtime comes from the rows labelled with a network.
- Two-party protocols: online time is the latest party's wall time after its offline phase. For PFA-WSI it is the
  server's time, and its communication is Total - MqRPMT_Recv, because both threads add their mqRPMT bytes to the
  same counters, so MqRPMT_Send and MqRPMT_Recv each already hold both directions. With two parties WAN-N equals
  WAN-L, so LOOKUP and PFA-WSI have no WAN-N runs.
"""
import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path

MIB = 1 << 20


def read(path):
    with open(path, newline="") as f:
        return [row for row in csv.DictReader(f) if row["label"] != "label"]


def runs(rows):
    """Groups party rows by configuration, then by run."""
    groups = defaultdict(lambda: defaultdict(dict))
    for row in rows:
        config = (row["label"], row["topology"], int(row["parties"]), int(row["size"]))
        groups[config][int(row["rep"])][int(row["party"])] = row
    return groups


def median_first(values):
    return statistics.median(values), values[0]


def fmt(value, first=None):
    if value is None:
        return "—"
    return f"{value:.2f}" if first is None else f"{value:.2f} ({first:.2f})"


def per_run(config_runs, metric):
    """Applies the metric to each run, in run order."""
    return [metric(parties) for _, parties in sorted(config_runs.items())]


def f(row, column):
    return float(row[column])


def comm(row, point):
    return (f(row, f"{point}_sent_bytes") + f(row, f"{point}_recv_bytes")) / MIB


def largest(parties, ids, metric):
    values = [metric(parties[i]) for i in ids if i in parties]
    return max(values) if values else None


def tree_roles(n):
    internal = [i for i in range(2, n + 1) if 2 * i <= n]
    leaves = [i for i in range(2, n + 1) if 2 * i > n]
    return internal, leaves


def multi(groups):
    compute = "record" if any(c[0] == "record" for c in groups) else "LAN"
    configs = sorted({(c[2], c[3]) for c in groups if c[0] == compute}, key=lambda c: (c[1], c[0]))
    print(f"## Reductions, {compute}: star computation (s) and communication (MiB)\n")
    print("| m | n | P1 | P2 | P[3,n] | Total | Star P1 | Star P2 | Star P[3,n] | Ring P1 | Ring P2 | Ring P[3,n] "
          "| Tree P1 | Tree internal | Tree leaf |")
    print("|" + "---|" * 15)
    for n, m in configs:
        cells = [f"2^{m.bit_length() - 1}", str(n)]
        star = groups.get((compute, "STAR", n, m))
        others = list(range(3, n + 1))
        for metric in (lambda p: f(p[1], "reduce_compute_ms") / 1000,
                       lambda p: f(p[2], "reduce_compute_ms") / 1000,
                       lambda p: largest(p, others, lambda r: f(r, "reduce_compute_ms") / 1000)):
            cells.append(fmt(*median_first(per_run(star, metric))) if star else "—")
        total = per_run(star, lambda p: sum(f(r, "reduce_sent_bytes") for r in p.values()) / MIB) if star else None
        cells.append(fmt(statistics.median(total)) if total else "—")
        internal, leaves = tree_roles(n)
        for topology, roles in (("STAR", ([1], [2], others)), ("RING", ([1], [2], others)),
                                ("TREE", ([1], internal, leaves))):
            config = groups.get((compute, topology, n, m))
            for ids in roles:
                values = per_run(config, lambda p: largest(p, ids, lambda r: comm(r, "reduce"))) if config else [None]
                cells.append(fmt(None if None in values else statistics.median(values)))
        print("| " + " | ".join(cells) + " |")

    print("\n## Reductions: runtime (s)\n")
    print("| network | m | n | Star | Ring | Tree |")
    print("|---|---|---|---|---|---|")
    networks = {c[0:1] + c[2:] for c in groups if c[0] != "record"}
    for net, n, m in sorted(networks, key=lambda c: (c[0] != "LAN", c[0], c[2], c[1])):
        cells = [net, f"2^{m.bit_length() - 1}", str(n)]
        for topology in ("STAR", "RING", "TREE"):
            config = groups.get((net, topology, n, m))
            runtime = lambda p: max(f(r, "reduce_wall_ms") for r in p.values()) / 1000
            cells.append(fmt(*median_first(per_run(config, runtime))) if config else "—")
        print("| " + " | ".join(cells) + " |")


def two(groups, pfa_dir):
    print("\n## Two-party protocols: communication (MiB) and time (s)\n")
    print("| protocol | m | offline comm | online comm | offline LAN | offline WAN-L | online LAN | online WAN-L "
          "| online WAN-N |")
    print("|" + "---|" * 9)
    pfa = defaultdict(lambda: defaultdict(list))
    for net in ("LAN", "WAN"):
        path = pfa_dir / f"pfa-{net}" / "benchmark_results.csv"
        if path.exists():
            with open(path, newline="") as file:
                for row in csv.DictReader(file):
                    pfa[int(row["N1"])][net].append(row)
    for m in sorted(pfa):
        cells = ["PFA-WSI", f"2^{m.bit_length() - 1}", "—"]
        rows = pfa[m]["LAN"] or pfa[m]["WAN"]
        cells.append(fmt(statistics.median((f(r, "Total(Bytes)") - f(r, "MqRPMT_Recv")) / MIB for r in rows)))
        cells += ["—", "—"]
        for net in ("LAN", "WAN"):
            times = [f(r, "Time(ms)") / 1000 for r in pfa[m][net]]
            cells.append(fmt(statistics.median(times)) if times else "—")
        cells.append("—")
        print("| " + " | ".join(cells) + " |")
    for topology, parties in (("LOOKUP", 2), ("AIDED", 3)):
        for m in sorted({c[3] for c in groups if c[1] == topology}):
            configs = {net: groups.get((net, topology, parties, m)) for net in ("LAN", "WAN-L", "WAN-N")}
            some = next(config for config in configs.values() if config)
            offline = per_run(some, lambda p: sum(f(r, "offline_sent_bytes") for r in p.values()) / MIB)
            online = per_run(some, lambda p: sum(f(r, "total_sent_bytes") - f(r, "offline_sent_bytes")
                                                 for r in p.values()) / MIB)
            cells = [topology, f"2^{m.bit_length() - 1}",
                     fmt(statistics.median(offline)) if topology == "LOOKUP" else "—",
                     fmt(statistics.median(online))]
            if topology == "AIDED":
                server = per_run(some, lambda p: comm(p[3], "total"))
                cells[-1] += f" (P_s: {statistics.median(server):.2f})"
            for point, nets in (("offline", ("LAN", "WAN-L")), ("online", ("LAN", "WAN-L", "WAN-N"))):
                for net in nets:
                    config = configs[net]
                    if config is None or (point == "offline" and topology == "AIDED"):
                        cells.append("—")
                        continue
                    if point == "offline":
                        metric = lambda p: max(f(r, "offline_wall_ms") for r in p.values()) / 1000
                    else:
                        metric = lambda p: max(f(r, "total_wall_ms") - f(r, "offline_wall_ms")
                                               for r in p.values()) / 1000
                    cells.append(fmt(*median_first(per_run(config, metric))))
            checks = {r["check"] for c in configs.values() if c for p in c.values() for r in p.values() if r["check"]}
            if checks != {"PASS"}:
                cells[0] += f" [check: {','.join(sorted(checks)) or 'none'}]"
            print("| " + " | ".join(cells) + " |")


def main():
    base = Path(sys.argv[1] if len(sys.argv) > 1 else "data")
    if (base / "multi.csv").exists():
        multi(runs(read(base / "multi.csv")))
    two(runs(read(base / "two.csv")) if (base / "two.csv").exists() else {}, base)


if __name__ == "__main__":
    main()
