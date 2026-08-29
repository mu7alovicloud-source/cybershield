import os
import psutil


def _normalized_cpu(proc, raw_cpu):
    """Return process CPU as a share of total machine capacity (0..100).

    psutil's per-process cpu_percent can exceed 100% on multi-core Windows.
    CyberShield's UI uses a total-machine scale, so normalize by logical CPUs.
    The Windows System Idle Process is excluded from threat ranking because its
    CPU number is an inverse idle metric rather than useful process workload.
    """
    name = (proc.info.get("name") or "").strip().lower()
    if name in {"system idle process", "idle"}:
        return 0.0
    cores = max(1, os.cpu_count() or 1)
    return round(min(100.0, max(0.0, float(raw_cpu or 0.0)) / cores), 1)


def get_processes(limit=100):
    rows = []
    for proc in psutil.process_iter(["pid", "name", "username", "status", "cpu_percent", "memory_percent", "exe"]):
        try:
            i = proc.info
            cpu = _normalized_cpu(proc, i.get("cpu_percent"))
            mem = round(i.get("memory_percent") or 0, 1)
            rows.append({
                "pid": i.get("pid"),
                "name": i.get("name") or "Unknown",
                "user": i.get("username") or "",
                "status": i.get("status") or "",
                "cpu": cpu,
                "memory": mem,
                "exe": i.get("exe") or "",
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    rows.sort(key=lambda x: x["cpu"], reverse=True)
    return rows[:limit]


class ProcessMonitor:
    """Small compatibility facade over the read-only process telemetry API."""
    def snapshot(self, limit=100):
        return get_processes(limit)

    def get_processes(self, limit=100):
        return get_processes(limit)
