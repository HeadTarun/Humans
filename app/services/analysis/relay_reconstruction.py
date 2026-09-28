"""
services/analysis/relay_reconstruction.py
 
Reconstructs a best-effort mail relay path from the Received-header chain
already parsed by services/ingestion/parser.py, and surfaces STRUCTURAL
anomalies in that chain (timestamp ordering, hop count).
 
This module produces FACTS ONLY (per PS 26106 §6 — see header_heuristics.py
for the same convention). It never labels an email suspicious/phishing; it
only describes what the chain looks like. The decision engine, not this
module, decides what an anomaly means.
 
Input/output contract:
    reconstruct_relay_path(received_hops: list[ReceivedHop]) -> RelayPath
 
`ReceivedHop` (contracts/headers.py) is what the real parser populates —
it has `from_ip` / `by_ip` (two separate optional IPs), not the single
`ip_address` field that the older, still-unused `RelayHop` contract
(contracts/relay.py) has. This function is the bridge between the two:
it reads ReceivedHop and produces RelayHop/RelayPath.
 
Hop ordering assumption (this matters — get it backwards and origin_ip
will be wrong):
    Received headers are prepended by each server as a message transits,
    so the header nearest the TOP of the message is the MOST RECENT hop
    (closest to final delivery), and the header nearest the BOTTOM is the
    OLDEST hop (closest to the true origin). services/ingestion/parser.py
    assigns hop_index in the order headers are read from the message
    top-to-bottom, so:
        hop_index 0        == most recent hop (last leg to recipient)
        hop_index max       == oldest hop (first leg from origin)
    Timestamps should therefore be monotonically NON-INCREASING as
    hop_index increases. A violation of that is a `timestamp_regression`
    anomaly.
"""
 
from __future__ import annotations
 
from typing import Optional
 
from app.contracts.headers import ReceivedHop
from app.contracts.relay import RelayHop, RelayPath
 
# Clock skew tolerance for timestamp-ordering checks. Real mail servers'
# clocks are not perfectly synchronized; without tolerance, ordinary NTP
# drift between two legitimate relays would be misreported as an anomaly.
_CLOCK_SKEW_TOLERANCE_SECONDS = 120
 
# IP classifications (see services/ingestion/parser.classify_ip) that mean
# "not a real internet-routable endpoint" for the purposes of picking an
# origin IP. Internal routing IDs (e.g. Gmail's 2002:-prefixed hop IDs)
# fall under "private" per Python's ipaddress module and must not be
# reported as the message's origin.
_NON_ROUTABLE_CLASSIFICATIONS = {
    "private", "loopback", "link_local", "multicast", "reserved", "unspecified", "unknown", None,
}
 
 
def _to_relay_hop(hop: ReceivedHop) -> RelayHop:
    """Map a ReceivedHop (headers.py, has from_ip/by_ip) onto a RelayHop
    (relay.py, has one ip_address). Prefer from_ip: it identifies the
    sending endpoint of this hop, which is what matters for tracing a
    chain back toward the origin. by_ip is a fallback only."""
    ip_address = hop.from_ip or hop.by_ip
    is_internal: Optional[bool] = None
    if hop.ip_classification is not None:
        is_internal = hop.ip_classification in _NON_ROUTABLE_CLASSIFICATIONS
 
    return RelayHop(
        hop_index=hop.hop_index,
        received_from=hop.from_host,
        received_by=hop.by_host,
        timestamp=hop.timestamp,
        ip_address=ip_address,
        is_internal=is_internal,
    )
 
 
def _find_origin_ip(hops: list[RelayHop], original: list[ReceivedHop]) -> Optional[str]:
    """
    The origin candidate is the from_ip of the hop with the HIGHEST
    hop_index (oldest, closest to the true sender) that has a "public"
    ip_classification. We deliberately do NOT just take the last hop's
    ip_address unconditionally — per the module docstring, internal
    routing IDs must not be reported as the origin.
 
    Falls back to the highest-index hop with ANY ip_address if no hop is
    classified "public" (e.g. classification was unavailable) rather than
    returning None outright, but this fallback is lower-confidence and
    callers should treat it as such if they need to distinguish.
    """
    if not original:
        return None
 
    by_index = sorted(original, key=lambda h: h.hop_index, reverse=True)
 
    for hop in by_index:
        if hop.ip_classification == "public" and (hop.from_ip or hop.by_ip):
            return hop.from_ip or hop.by_ip
 
    for hop in by_index:
        if hop.from_ip or hop.by_ip:
            return hop.from_ip or hop.by_ip
 
    return None
 
 
def _detect_timestamp_regressions(original: list[ReceivedHop]) -> list[str]:
    """
    Returns a list of anomaly strings, one per detected regression, in the
    form: "timestamp_regression:hop_<i>_after_hop_<i-1>"
 
    A regression is when the hop further from the recipient (higher
    hop_index, i.e. chronologically earlier) has a timestamp LATER than
    the hop before it (lower hop_index, chronologically later) by more
    than the clock-skew tolerance. That is backwards — an earlier leg of
    the journey cannot have happened after a later leg — and is either a
    forged/backdated header or a real clock-sync problem on a relay.
    Either way it is worth surfacing as a fact; this function does not
    decide which cause it is.
    """
    anomalies: list[str] = []
    by_index = sorted(
        [h for h in original if h.timestamp is not None],
        key=lambda h: h.hop_index,
    )
    for i in range(1, len(by_index)):
        earlier_leg = by_index[i]      # higher hop_index = chronologically earlier
        later_leg = by_index[i - 1]    # lower hop_index = chronologically later
        delta = (earlier_leg.timestamp - later_leg.timestamp).total_seconds()
        if delta > _CLOCK_SKEW_TOLERANCE_SECONDS:
            anomalies.append(
                f"timestamp_regression:hop_{earlier_leg.hop_index}_after_hop_{later_leg.hop_index}"
            )
    return anomalies
 
 
def reconstruct_relay_path(received_hops: list[ReceivedHop]) -> RelayPath:
    """Build a RelayPath from the parser's ReceivedHop list. Never raises —
    malformed/empty input yields an empty-but-valid RelayPath, because a
    forensic pipeline must degrade gracefully rather than crash the whole
    analysis over one unparseable email."""
    if not received_hops:
        return RelayPath(hops=[], hop_count=0, origin_ip=None, anomalies=[])
 
    try:
        relay_hops = [_to_relay_hop(h) for h in received_hops]
        origin_ip = _find_origin_ip(relay_hops, received_hops)
        anomalies = _detect_timestamp_regressions(received_hops)
 
        if len(received_hops) < 2:
            anomalies.append("too_few_hops")
 
        return RelayPath(
            hops=relay_hops,
            hop_count=len(relay_hops),
            origin_ip=origin_ip,
            anomalies=anomalies,
        )
    except Exception:
        # Forensic pipeline rule: a malformed hop must not crash the whole
        # analysis. Degrade to an empty-but-valid result and let the
        # missing data speak for itself downstream.
        return RelayPath(hops=[], hop_count=0, origin_ip=None, anomalies=["relay_reconstruction_failed"])
