#!/usr/bin/env python3
"""Bulk DNSSEC status check for a list of .pk domains.

DS and existence come straight from the .pk registry nameservers (authoritative,
no resolver cache). DNSKEY comes from public resolvers. Each domain lands in one
bucket:

  secure        DS in .pk + DNSKEY, and a resolver validated it (AD bit)
  bogus         DS in .pk + DNSKEY, but validation fails
  signed_no_ds  DNSKEY published, but no DS in .pk, so nothing validates it
  ds_no_dnskey  DS in .pk, but the zone answers with no DNSKEY (broken)
  unsigned      no DS, no DNSKEY
  nxdomain      not delegated in .pk
  unreachable   the domain's nameservers fail (SERVFAIL on every resolver, or REFUSED)
  error         no reply after retries

Usage:
  uv run --with dnspython dnssec_check.py pk.txt
  uv run --with dnspython dnssec_check.py pk.txt --out results.csv -c 100
"""

import argparse
import asyncio
import csv
import random
import socket
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

import dns.asyncquery
import dns.exception
import dns.flags
import dns.message
import dns.rcode
from dns.rdatatype import DNSKEY, DS, RRSIG

PARENT_NS = ["root-c1.pknic.pk", "root-c2.pknic.pk", "root-e.pknic.pk", "root-s.pknic.pk"]
RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
STATUSES = ["secure", "bogus", "signed_no_ds", "ds_no_dnskey", "unsigned",
            "nxdomain", "unreachable", "error"]
SERVFAIL, NXDOMAIN = dns.rcode.SERVFAIL, dns.rcode.NXDOMAIN


async def query(name, rdtype, servers, rd=True, cd=False, tries=3, timeout=10.0):
    """Ask a different random server on each timeout or SERVFAIL; return the last reply."""
    # Resolvers take up to ~10 s to give up on dead nameservers; a shorter timeout
    # reports those as "error" instead of "unreachable".
    msg = dns.message.make_query(name, rdtype, want_dnssec=True)
    if not rd:
        msg.flags &= ~dns.flags.RD
    if cd:
        msg.flags |= dns.flags.CD  # skip validation: see the records even if broken
    resp = None
    for server in random.sample(servers, len(servers)) * tries:
        try:
            resp, _ = await dns.asyncquery.udp_with_fallback(msg, server, timeout=timeout)
            if resp.rcode() != SERVFAIL:
                return resp
        except (dns.exception.DNSException, OSError):
            pass
    if resp is None:
        raise dns.exception.Timeout
    return resp


def algos(resp, rdtype):
    """Algorithms in the answer, e.g. "13" for DNSKEY or "13/2" (alg/digest) for DS."""
    found = {f"{rr.algorithm}/{rr.digest_type}" if rdtype == DS else str(rr.algorithm)
             for rrset in resp.answer if rrset.rdtype == rdtype for rr in rrset}
    return " ".join(sorted(found))


def classify(has_ds, key_rcode, has_key, validated):
    """validated: True/False after a validating DNSKEY query, None if not asked."""
    if has_ds and has_key:
        return "secure" if validated else "bogus"
    if key_rcode != dns.rcode.NOERROR:  # dead, refusing or denying its own name
        return "unreachable"
    if has_ds:
        return "ds_no_dnskey"
    return "signed_no_ds" if has_key else "unsigned"


async def validates(domain, resolver):
    """Flaky nameservers make one resolver fail now and then, so ask each one."""
    try:
        resp = await query(domain, DNSKEY, [resolver], tries=2)
        return bool(resp.flags & dns.flags.AD)
    except dns.exception.DNSException:
        return False


async def check(domain, parent, resolvers):
    """Return (status, ds_algorithms, dnskey_algorithms); "" means none."""
    try:
        ds = await query(domain, DS, parent, rd=False)
        if ds.rcode() == NXDOMAIN:
            return "nxdomain", "", ""
        if ds.rcode() != dns.rcode.NOERROR:  # registry refused us: DS state unknown
            return "error", "", ""
        ds_alg = algos(ds, DS)
        key = await query(domain, DNSKEY, resolvers, cd=True)
        key_alg = algos(key, DNSKEY)
        validated = None
        if ds_alg and key_alg:  # only ~10 domains, so the extra queries are cheap
            validated = any([await validates(domain, r) for r in resolvers])
    except (dns.exception.DNSException, OSError):
        return "error", "", ""
    return classify(bool(ds_alg), key.rcode(), bool(key_alg), validated), ds_alg, key_alg


def suffix(domain):
    parts = domain.split(".")
    return ".".join(parts[1:]) if len(parts) > 2 else parts[-1]


def print_summary(rows):
    total = Counter(r[1] for r in rows)
    by_suffix = defaultdict(Counter)
    for r in rows:
        by_suffix[suffix(r[0])][r[1]] += 1

    print(f"\n=== Summary ({len(rows)} domains) ===")
    for s in STATUSES:
        if total[s]:
            print(f"  {s:15} {total[s]:8}  {100 * total[s] / len(rows):6.2f}%")

    print("\n=== Per suffix (secure / total) ===")
    for suf, c in sorted(by_suffix.items(), key=lambda kv: -sum(kv[1].values())):
        others = ", ".join(f"{k}={v}" for k, v in c.items() if k != "secure")
        print(f"  {suf:10} {c['secure']:7} / {sum(c.values()):<7} {others}")

    print("\n=== DNSKEY algorithms of signed domains ===")
    for alg, n in Counter(r[3] for r in rows if r[3]).most_common():
        print(f"  {alg:10} {n:8}")


async def reachable(resolver):
    """Some networks block a public resolver; every query sent to it would time out."""
    try:
        await query("pk.", DNSKEY, [resolver], tries=1, timeout=2)
        return True
    except dns.exception.DNSException:
        print(f"Skipping {resolver}: no answer", file=sys.stderr)
        return False


async def print_pk_expiry(parent):
    """The .pk DNSKEY signature: if it lapses, every .pk domain fails validation."""
    resp = await query("pk.", DNSKEY, parent, rd=False)
    for rrset in resp.answer:
        if rrset.rdtype == RRSIG:
            for sig in rrset:
                exp = datetime.fromtimestamp(sig.expiration, timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                print(f"pk. DNSKEY RRSIG expires {exp:%Y-%m-%d %H:%M} UTC ({days} days)",
                      file=sys.stderr)


async def main():
    p = argparse.ArgumentParser(description="Bulk DNSSEC status check")
    p.add_argument("input", help="file with one domain per line")
    p.add_argument("--out", default="dnssec_results.csv")
    p.add_argument("-c", "--concurrency", type=int, default=200,
                   help="parallel domains (lower it if you see many errors)")
    args = p.parse_args()

    with open(args.input) as f:
        lines = (line.strip().lower().rstrip(".") for line in f)
        domains = list(dict.fromkeys(d for d in lines if d and not d.startswith("#")))
    parent = [socket.gethostbyname(ns) for ns in PARENT_NS]
    resolvers = [r for r in RESOLVERS if await reachable(r)]
    if not resolvers:
        sys.exit("No resolver answers; check the network.")
    print(f"Checking {len(domains)} domains: DS via {', '.join(PARENT_NS)}, "
          f"DNSKEY via {', '.join(resolvers)}", file=sys.stderr)
    await print_pk_expiry(parent)

    limit = asyncio.Semaphore(args.concurrency)
    rows = []

    async def run_one(domain):
        async with limit:
            rows.append((domain, *await check(domain, parent, resolvers)))
            if len(rows) % 5000 == 0:
                print(f"  {len(rows)}/{len(domains)} done", file=sys.stderr)

    await asyncio.gather(*(run_one(d) for d in domains))

    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["domain", "status", "ds", "dnskey_alg"])
        w.writerows(rows)
    print(f"Results written to {args.out}", file=sys.stderr)
    print_summary(rows)


if __name__ == "__main__":
    asyncio.run(main())
