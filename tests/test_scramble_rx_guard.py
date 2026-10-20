"""Regression: both scramble merge writes must reject overlap with registered RX rings."""
from pathlib import Path

src = (Path(__file__).resolve().parents[1] / "agent/relay_hook_linux.js").read_text()
assert "function overlapsRecvRing(at, length)" in src
assert "at.compare(ringEnd) < 0 && end.compare(base) > 0" in src
assert "if (!overlapsRecvRing(f0.at, 1))" in src
assert "if (overlapsRecvRing(bodyp, body.length))" in src
assert src.index("if (overlapsRecvRing(bodyp, body.length))") < src.index("bodyp.writeByteArray(body)")
assert src.index("if (!overlapsRecvRing(f0.at, 1))") < src.index("f0.at.writeU8")
print("scramble RX ring guard contract ok")
