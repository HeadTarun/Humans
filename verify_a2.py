from app.contracts.headers import ReceivedHop
from app.services.analysis.relay_reconstruction import reconstruct_relay_path
from datetime import datetime, timedelta

t0 = datetime(2026, 8, 31, 9, 42, 6)
t1 = t0 - timedelta(seconds=5)

hops = [
    ReceivedHop(hop_index=0, by_host="mx.internal", by_ip="10.0.0.5",
                ip_classification="private", raw_line="x", timestamp=t0),
    ReceivedHop(hop_index=1, from_host="mail-sor-f69.google.com", from_ip="209.85.220.69",
                by_host="mx.google.com", ip_classification="public", raw_line="y", timestamp=t1),
]

path = reconstruct_relay_path(hops)
assert path.origin_ip == "209.85.220.69", f"expected 209.85.220.69, got {path.origin_ip}"
assert path.hop_count == 2
print("PASS:", path.origin_ip, path.anomalies)

# Test 2
# Only one hop -> "too_few_hops"
single = [ReceivedHop(hop_index=0, from_host="a.com", raw_line="x")]
path2 = reconstruct_relay_path(single)
assert "too_few_hops" in path2.anomalies, path2.anomalies

# Backwards timestamps -> regression flagged
t0_2 = datetime(2026, 8, 31, 9, 42, 6)
backwards = [
    ReceivedHop(hop_index=0, by_host="a", raw_line="x", timestamp=t0_2),
    ReceivedHop(hop_index=1, from_host="b", raw_line="y", timestamp=t0_2 + timedelta(minutes=10)),
]
path3 = reconstruct_relay_path(backwards)
assert any(a.startswith("timestamp_regression") for a in path3.anomalies), path3.anomalies

# Empty input -> valid empty result, no crash
path4 = reconstruct_relay_path([])
assert path4.hop_count == 0 and path4.origin_ip is None and path4.anomalies == []

print("ALL PASS")
