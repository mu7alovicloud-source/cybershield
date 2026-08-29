import os, platform, psutil, socket
from app.security.cpu_monitor import get_cpu_snapshot
from app.security.process_monitor import get_processes
from app.security.network_monitor import get_connections

def collect_host_snapshot():
    vm = psutil.virtual_memory()
    # os.sep resolves to the correct filesystem root on both Windows
    # ("C:\\") and POSIX ("/"); '/' alone is not guaranteed to be a valid
    # drive path on Windows, which is this app's primary deployment target.
    disk = psutil.disk_usage(os.path.abspath(os.sep))
    return {
        "os": platform.platform(), "hostname": socket.gethostname(),
        "cpu": get_cpu_snapshot(15),
        "memory": {"percent": vm.percent, "available": vm.available, "total": vm.total},
        "disk": {"percent": disk.percent, "free": disk.free, "total": disk.total},
        "processes": get_processes(30), "connections": get_connections(50),
    }
