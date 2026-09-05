"""Local smoke helpers for live interface discovery / capture (no attacks)."""
from __future__ import annotations

import json
import sys
import time

from app.live.capture import list_interfaces
from app.live.live_manager import LiveManager


def main() -> int:
    ifaces = list_interfaces()
    print("IFACE_COUNT", len(ifaces))
    for i in ifaces[:15]:
        print(
            " ",
            "up=" + str(i.get("is_up")),
            "ipv4=" + str(i.get("ipv4")),
            "name=" + repr(i.get("name")),
            "display=" + repr(i.get("display_name")),
        )
    up = [
        i
        for i in ifaces
        if i.get("is_up")
        and i.get("ipv4")
        and not str(i.get("ipv4")).startswith("127.")
    ]
    print("UP_WITH_IP", len(up))
    if not up:
        print("NO_UP_IFACE")
        return 2

    primary = up[0]["name"]
    print("PRIMARY", primary)
    print("PRIMARY_DISPLAY", up[0].get("display_name"))
    print("PRIMARY_IPV4", up[0].get("ipv4"))

    if "--capture" not in sys.argv:
        return 0

    mgr = LiveManager()
    try:
        st = mgr.start(primary, window_seconds=5)
        print("START", json.dumps({k: st.get(k) for k in ("running", "status", "interface", "error", "message")}, default=str))
    except Exception as exc:
        print("START_FAILED", type(exc).__name__, str(exc))
        return 3

    # Harmless traffic: DNS / ICMP via stdlib only
    try:
        import socket
        import urllib.request

        socket.getaddrinfo("example.com", 80)
        urllib.request.urlopen("https://example.com", timeout=5).read(64)
    except Exception as exc:
        print("TRAFFIC_NOTE", str(exc))

    time.sleep(6)
    st2 = mgr.status()
    stats = st2.get("stats") or {}
    snap = st2.get("snapshot") or {}
    pred = st2.get("prediction")
    print(
        "STATUS",
        json.dumps(
            {
                "running": st2.get("running"),
                "status": st2.get("status"),
                "packets": stats.get("packets"),
                "flows": stats.get("flows"),
                "nodes": stats.get("active_nodes"),
                "edges": stats.get("connections"),
                "threats": stats.get("threats"),
                "prediction": None
                if not pred
                else {
                    "attack_type": pred.get("attack_type"),
                    "confidence": pred.get("confidence"),
                    "is_unknown": pred.get("is_unknown"),
                    "detection": pred.get("detection"),
                    "next_window": pred.get("next_window_prediction"),
                },
                "snap_nodes": snap.get("node_count"),
                "error": st2.get("error"),
                "message": st2.get("message"),
            },
            default=str,
        ),
    )
    stopped = mgr.stop()
    print("STOP", stopped.get("running"), stopped.get("status"))

    # Restart cleanly
    try:
        st3 = mgr.start(primary, window_seconds=5)
        print("RESTART", st3.get("running"), st3.get("status"))
        mgr.stop()
        print("RESTOP_OK")
    except Exception as exc:
        print("RESTART_FAILED", str(exc))
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
