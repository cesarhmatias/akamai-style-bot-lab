# `botnet_cluster`: fingerprint clustering across IPs (LOW, flag-gated)

Category: network · Module: `api/app/modules/botnet_cluster.py` · Protected URL: `/protected/botnet_cluster`
· Default: **off** (module disabled and flag `botnet_cluster` off) · Module tier: **LOW**

## What it is

One automation framework driven from many IPs presents the same transport fingerprint everywhere (TLS JA4, HTTP/2
string, header order). Grouping requests by that tuple reveals a distributed bot; once the group is known to be
abusive, every new IP that joins it is suspect without further evidence.

## How real Akamai uses it

Akamai's analytics have a "Botnet ID" dimension and its product brief describes a "catapult algorithm" that shares a
newly detected bot across all customers "within minutes" (report §2.14, [P]). The clustering features, thresholds and
propagation are **not public**. This module is an unverified lab approximation of that network effect on a single
server.

## Confidence

Tier **LOW** (report §2.14, §3.1). Unverified, vendor-sourced detail; gated by the flag `botnet_cluster` (default off)
and the module is also disabled by default. With the flag off, `evaluate()` returns SKIP "Flag botnet_cluster is off
(LOW confidence, unverified)".

## How the lab simulates it

With the flag on and the module enabled:

- Cluster key = `sha256(JA4 | H2 fingerprint | lower-cased header order)[:16]`.
- `cluster:ips:{key}` keeps the distinct client IPs of the last `LAB_CLUSTER_WINDOW_MIN` minutes (default 10, at most 50
  tracked).
- `cluster:hits:{key}:{minute}` counts hits; at `LAB_CLUSTER_BAD_RATE` hits in one minute (default 60) from any IPs the
  cluster is marked bad (`cluster:bad:{key}`).
- A request in a bad cluster that spans at least `LAB_CLUSTER_MIN_IPS` distinct IPs (default 3) is FAIL 70 "Inherits
  botnet cluster flag". A bad cluster with fewer IPs, or an unflagged cluster, passes with 0. No fingerprint to cluster
  on is SKIP.

## How a scraper passes it

Do not share one fingerprint across many IPs at a high rate, or vary the fingerprint per exit IP. Real browsers of one
release also share a fingerprint, so a real deployment needs more features (for example a canvas hash); here the
high-rate gate is the only protection against that false positive.

## Observed results

Not in the matrix: one container IP cannot form a multi-IP cluster, so `RESULTS.md` lists it under "Off by default
(LOW confidence), excluded from the matrix". Behaviour is covered by `api/tests/test_botnet_cluster.py`.

## Limits and caveats

- Unverified approximation; see [KNOWN_GAPS](../KNOWN_GAPS.md) (low-confidence items).
- A single-server memory of clusters, not a cross-customer network effect.
