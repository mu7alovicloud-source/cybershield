"""Defensive local network visibility and explainable heuristics."""
from __future__ import annotations

import ipaddress
import socket
from typing import Any

import psutil


def get_local_network_info():
    host = socket.gethostname()
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        ip = "Unknown"
    interfaces = []
    for name, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET:
                interfaces.append({"interface": name, "ip": a.address, "netmask": a.netmask or ""})
    return {"hostname": host, "ip": ip, "interfaces": interfaces}


def _endpoint(addr):
    if not addr:
        return "-"
    try:
        return f"{addr.ip}:{addr.port}"
    except AttributeError:
        try:
            return f"{addr[0]}:{addr[1]}"
        except Exception:
            return "-"


def _ip_risk(remote: str) -> tuple[int, list[str]]:
    if not remote or remote == "-":
        return 0, []
    host = remote.rsplit(":", 1)[0].strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return 5, ["non_literal_remote_endpoint"]
    if ip.is_loopback or ip.is_private or ip.is_link_local:
        return 0, []
    return 5, ["external_remote_endpoint"]


def get_connections(limit=100):
    result = []
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        return result
    for c in conns:
        if len(result) >= max(1, int(limit)):
            break
        remote = _endpoint(c.raddr)
        risk, reasons = _ip_risk(remote)
        process_name = executable = None
        if c.pid:
            try:
                proc = psutil.Process(c.pid)
                process_name = proc.name()
                try:
                    executable = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
                    pass
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
                pass
        local = _endpoint(c.laddr)
        result.append({
            "pid": c.pid or "-",
            "family": str(c.family).split(".")[-1],
            "type": str(c.type).split(".")[-1],
            "local": local,
            "remote": remote,
            "status": c.status,
            "process_name": process_name or "-",
            "executable": executable or "-",
            "risk": risk,
            "reasons": reasons,
            "category": "network",
        })
    return result


def connection_evidence(connections: list[dict]) -> list[dict[str, Any]]:
    evidence = []
    for c in connections:
        if c.get("risk", 0) <= 0:
            continue
        evidence.append({
            "source": "network_monitor",
            "category": "network",
            "indicator": f"{c.get('process_name', '-') } -> {c.get('remote', '-')}",
            "score": c.get("risk", 0),
            "confidence": 0.55,
            "reason": "; ".join(c.get("reasons", [])) or "network anomaly",
            "metadata": {"pid": c.get("pid"), "executable": c.get("executable")},
        })
    return evidence
