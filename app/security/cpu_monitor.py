import psutil

def get_cpu_snapshot(limit=25):
    rows = []
    for proc in psutil.process_iter(["pid","name","username","status","cpu_percent","memory_percent","exe"]):
        try:
            i = proc.info
            cpu = round(i.get("cpu_percent") or 0, 1)
            mem = round(i.get("memory_percent") or 0, 1)
            rows.append({
                "pid": i.get("pid"),
                "name": i.get("name") or "Unknown",
                "user": i.get("username") or "",
                "status": i.get("status") or "",
                "cpu": cpu,
                "memory": mem,
                "exe": i.get("exe") or "",
                "suspicious_cpu": cpu >= 85.0
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    rows.sort(key=lambda x: x["cpu"], reverse=True)
    return {
        "total_cpu": round(psutil.cpu_percent(interval=0.15), 1),
        "cores": psutil.cpu_count(logical=True) or 0,
        "processes": rows[:limit]
    }
