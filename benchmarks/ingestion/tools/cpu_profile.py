"""Summarize a V8 .cpuprofile: where the CPU time goes, by area and by function.

Self time is the time spent in a function's own code; inclusive time adds everything it calls.
Areas group frames by origin: a platform source file, a dependency (node_modules/<package>), Node.js
internals, or V8 itself (garbage collector, idle, program).

Usage: python tools/cpu_profile.py <file.cpuprofile> [--top 25]
"""

import argparse
import json
import re
from collections import defaultdict


def area_of(frame):
    url = frame.get("url") or ""
    name = frame.get("functionName") or ""
    if not url:
        if name in ("(garbage collector)", "(idle)", "(program)", "(root)"):
            return name
        return "(native: " + (name or "anonymous") + ")"
    match = re.search(r"node_modules/((?:@[^/]+/)?[^/]+)", url)
    if match:
        return "dependency " + match.group(1)
    match = re.search(r"opencti-graphql/(src/.+|tests/.+)$", url)
    if match:
        return match.group(1).split("?")[0]
    if url.startswith("node:"):
        return "node " + url[5:].split("/")[0]
    return url


def label_of(frame):
    name = frame.get("functionName") or "(anonymous)"
    return f"{name} [{area_of(frame)}:{frame.get('lineNumber', 0) + 1}]"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("profile")
    parser.add_argument("--top", type=int, default=25)
    args = parser.parse_args()
    profile = json.load(open(args.profile, encoding="utf-8"))
    nodes = {n["id"]: n for n in profile["nodes"]}
    parent = {}
    for node in profile["nodes"]:
        for child in node.get("children", []):
            parent[child] = node["id"]
    samples, deltas = profile["samples"], profile["timeDeltas"]
    total = sum(deltas) / 1000

    self_area = defaultdict(float)
    self_fn = defaultdict(float)
    incl_fn = defaultdict(float)
    for sample, delta in zip(samples, deltas):
        ms = delta / 1000
        frame = nodes[sample]["callFrame"]
        self_area[area_of(frame)] += ms
        self_fn[label_of(frame)] += ms
        seen = set()
        current = sample
        while current is not None:
            label = label_of(nodes[current]["callFrame"])
            if label not in seen:
                seen.add(label)
                incl_fn[label] += ms
            current = parent.get(current)

    idle = self_area.get("(idle)", 0)
    busy = total - idle
    print(
        f"{args.profile}: {total:.0f} ms profiled, {busy:.0f} ms on CPU ({busy / total * 100:.0f}%), {idle:.0f} ms idle"
    )
    print("\nSelf time by area (share of CPU time)")
    for area, ms in sorted(self_area.items(), key=lambda kv: -kv[1])[: args.top]:
        if area != "(idle)":
            print(f"  {ms / busy * 100:5.1f}%  {ms:8.0f} ms  {area}")
    print("\nSelf time by function")
    for label, ms in sorted(self_fn.items(), key=lambda kv: -kv[1])[: args.top]:
        if not label.startswith("(idle)"):
            print(f"  {ms / busy * 100:5.1f}%  {label}")
    print("\nInclusive time of platform and prototype functions")
    platform = {k: v for k, v in incl_fn.items() if "[src/" in k or "[tests/bench" in k}
    for label, ms in sorted(platform.items(), key=lambda kv: -kv[1])[: args.top]:
        print(f"  {ms / busy * 100:5.1f}%  {label}")


if __name__ == "__main__":
    main()
