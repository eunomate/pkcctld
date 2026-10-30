#!/usr/bin/env python3
"""Bulk DNSSEC status check for a domain list.

Classifies each domain via a validating resolver:
  secure          DS in parent + DNSKEY, chain validates (AD bit)   <- "fully signed"
  bogus           signed but validation fails (SERVFAIL, OK with CD)
  signed_no_ds    DNSKEY published but no DS at parent (island, not validated)
  ds_no_dnskey    DS at parent but zone serves no DNSKEY (broken)
  insecure_chain  DS + DNSKEY present but no AD (a parent in the chain is unsigned)
  unsigned        no DS, no DNSKEY
  nxdomain        domain does not exist
  unreachable     SERVFAIL even with CD (lame / dead nameservers)
  error           timeouts after retries

Resumable: re-running with the same --out skips domains already written.

Usage:
  pip install dnspython        # or: uv run --with dnspython ...
  python3 dnssec_bulk_check.py pk.txt --out pk_dnssec.csv
  python3 dnssec_bulk_check.py pk.txt --resolver 127.0.0.1:5353 -c 500
"""

import argparse
import asyncio
import csv
import itertools
import os
import sys
import time
from collections import Counter, defaultdict

import dns.asyncquery
import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype

STATUSES = [
    "secure",
    "bogus",
    "signed_no_ds",
    "ds_no_dnskey",
    "insecure_chain",
    "unsigned",
    "nxdomain",
    "unreachable",
    "error",
]


class Resolvers:
    def __init__(self, specs):
        self.addrs = []
        for s in specs:
            host, _, port = s.partition(":") if s.count(":") == 1 else (s, "", "")
            self.addrs.append((host, int(port) if port else 53))
        self._cycle = itertools.cycle(self.addrs)

    def next(self):
        return next(self._cycle)


async def query(res, name, rdtype, cd, timeout, retries):
    msg = dns.message.make_query(name, rdtype, want_dnssec=True, payload=1232)
    msg.flags |= dns.flags.RD
    if cd:
        msg.flags |= dns.flags.CD
    last = None
    for _ in range(retries + 1):
        host, port = res.next()
        try:
            resp, _ = await dns.asyncquery.udp_with_fallback(
                msg, host, timeout=timeout, port=port
            )
            return resp
        except (dns.exception.Timeout, OSError, dns.exception.DNSException) as e:
            last = e
    raise last


def has_rr(resp, rdtype):
    return any(rr.rdtype == rdtype for rr in resp.answer)


def ad(resp):
    return bool(resp.flags & dns.flags.AD)


async def check(domain, res, timeout, retries):
    try:
        ds, key = await asyncio.gather(
            query(res, domain, dns.rdatatype.DS, False, timeout, retries),
            query(res, domain, dns.rdatatype.DNSKEY, False, timeout, retries),
        )
    except Exception as e:
        return "error", "", "", f"{type(e).__name__}"

    key_rc, ds_rc = key.rcode(), ds.rcode()
    has_ds, has_key = has_rr(ds, dns.rdatatype.DS), has_rr(key, dns.rdatatype.DNSKEY)

    if key_rc == dns.rcode.NOERROR and has_key and ad(key):
        return "secure", has_ds, True, ""

    if dns.rcode.SERVFAIL in (key_rc, ds_rc):
        # Re-ask with validation disabled to separate bogus from dead.
        try:
            ds_cd, key_cd = await asyncio.gather(
                query(res, domain, dns.rdatatype.DS, True, timeout, retries),
                query(res, domain, dns.rdatatype.DNSKEY, True, timeout, retries),
            )
        except Exception as e:
            return "error", "", "", f"cd:{type(e).__name__}"
        has_ds = has_ds or has_rr(ds_cd, dns.rdatatype.DS)
        has_key = has_key or has_rr(key_cd, dns.rdatatype.DNSKEY)
        # Without a DS the zone is insecure, so a SERVFAIL there is transient,
        # not a validation failure.
        if key_cd.rcode() == dns.rcode.NOERROR and has_ds:
            return "bogus", has_ds, has_key, "servfail_without_cd"
        if key_cd.rcode() == dns.rcode.NOERROR and has_key:
            return "signed_no_ds", False, True, "transient_servfail"
        if has_ds:
            return "ds_no_dnskey", True, False, "ns_unreachable"
        return "unreachable", has_ds, has_key, dns.rcode.to_text(key_cd.rcode())

    if dns.rcode.NXDOMAIN in (key_rc, ds_rc):
        return "nxdomain", False, False, ""

    if has_key and not has_ds:
        return "signed_no_ds", False, True, ""
    if has_ds and not has_key:
        return "ds_no_dnskey", True, False, ""
    if has_ds and has_key:
        return "insecure_chain", True, True, f"ds_ad={ad(ds)}"
    if key_rc != dns.rcode.NOERROR:
        return "error", has_ds, has_key, dns.rcode.to_text(key_rc)
    return "unsigned", False, False, ""


def load_done(path):
    if not os.path.exists(path):
        return set()
    with open(path, newline="") as f:
        return {row["domain"] for row in csv.DictReader(f)}


def suffix(domain):
    parts = domain.split(".")
    return ".".join(parts[1:]) if len(parts) > 2 else parts[-1]


def summarize(path):
    total, per_suffix = Counter(), defaultdict(Counter)
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            total[row["status"]] += 1
            per_suffix[suffix(row["domain"])][row["status"]] += 1
    n = sum(total.values())
    print(f"\n=== Summary ({n} domains) ===")
    for s in STATUSES:
        if total[s]:
            print(f"  {s:15} {total[s]:8}  {100 * total[s] / n:6.2f}%")
    print("\n=== Per suffix (secure / total) ===")
    for suf, c in sorted(per_suffix.items(), key=lambda kv: -sum(kv[1].values())):
        t = sum(c.values())
        extra = ", ".join(f"{k}={v}" for k, v in c.items() if k != "secure" and v)
        print(f"  {suf:10} {c['secure']:7} / {t:<7} {extra}")


async def run(args):
    res = Resolvers(args.resolver)
    with open(args.input) as f:
        domains = list(
            dict.fromkeys(
                d.strip().lower().rstrip(".") for d in f if d.strip() and d[0] != "#"
            )
        )
    done = load_done(args.out)
    todo = [d for d in domains if d not in done]
    print(
        f"{len(domains)} domains, {len(done)} already done, {len(todo)} to check "
        f"via {', '.join(f'{h}:{p}' for h, p in res.addrs)}",
        file=sys.stderr,
    )

    new_file = not os.path.exists(args.out)
    out = open(args.out, "a", newline="")
    w = csv.writer(out)
    if new_file:
        w.writerow(["domain", "status", "has_ds", "has_dnskey", "detail"])

    queue = asyncio.Queue()
    for d in todo:
        queue.put_nowait(d)
    counts, start = Counter(), time.monotonic()

    async def worker():
        while True:
            try:
                d = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            status, hds, hkey, detail = await check(d, res, args.timeout, args.retries)
            w.writerow([d, status, hds, hkey, detail])
            counts[status] += 1

    async def progress():
        while True:
            await asyncio.sleep(10)
            n = sum(counts.values())
            rate = n / (time.monotonic() - start)
            eta = (len(todo) - n) / rate if rate else 0
            out.flush()
            print(
                f"[{n}/{len(todo)}] {rate:.0f}/s eta {eta / 60:.1f}m "
                f"secure={counts['secure']} bogus={counts['bogus']} "
                f"error={counts['error']}",
                file=sys.stderr,
            )

    prog = asyncio.create_task(progress())
    await asyncio.gather(*(worker() for _ in range(args.concurrency)))
    prog.cancel()
    out.close()
    summarize(args.out)


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("input", help="file with one domain per line")
    p.add_argument("--out", default="dnssec_results.csv")
    p.add_argument(
        "--resolver",
        action="append",
        help="validating resolver ip[:port], repeatable "
        "(default: 1.1.1.1, 8.8.8.8, 9.9.9.9)",
    )
    p.add_argument("-c", "--concurrency", type=int, default=200)
    p.add_argument("--timeout", type=float, default=4.0)
    p.add_argument("--retries", type=int, default=2)
    p.add_argument("--summary-only", action="store_true")
    args = p.parse_args()
    args.resolver = args.resolver or ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    if args.summary_only:
        summarize(args.out)
        return
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
