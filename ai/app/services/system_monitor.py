"""Host system monitoring for the Admin Panel (Phase 13).

Reports CPU, memory, disk and GPU utilisation. Uses psutil when available;
falls back to lightweight estimates so the health endpoint never fails.
"""

from __future__ import annotations

import os
import shutil
import sys
from typing import Any

import torch


def _psutil_metrics() -> dict[str, Any]:
    try:
        import psutil  # noqa: PLC0415
    except ImportError:
        return {}

    cpu_percent = float(psutil.cpu_percent(interval=0.1))
    vm = psutil.virtual_memory()
    disk = shutil.disk_usage(os.path.expanduser("~"))
    return {
        "cpu_percent": round(cpu_percent, 1),
        "cpu_count": psutil.cpu_count(logical=True) or 1,
        "memory_total_bytes": int(vm.total),
        "memory_used_bytes": int(vm.used),
        "memory_percent": round(float(vm.percent), 1),
        "disk_total_bytes": int(disk.total),
        "disk_used_bytes": int(disk.used),
        "disk_percent": round(disk.used / max(disk.total, 1) * 100, 1),
    }


def _gpu_metrics() -> dict[str, Any]:
    if not torch.cuda.is_available():
        return {"gpu_available": False}

    out: dict[str, Any] = {
        "gpu_available": True,
        "gpu_count": torch.cuda.device_count(),
        "gpu_name": torch.cuda.get_device_name(0) if torch.cuda.device_count() else None,
    }
    try:
        free, total = torch.cuda.mem_get_info(0)
        used = total - free
        out["gpu_memory_total_bytes"] = int(total)
        out["gpu_memory_used_bytes"] = int(used)
        out["gpu_memory_percent"] = round(used / max(total, 1) * 100, 1)
    except Exception:
        pass
    try:
        out["gpu_utilization"] = round(float(torch.cuda.utilization(0)), 1)
    except Exception:
        out["gpu_utilization"] = None
    return out


def snapshot() -> dict[str, Any]:
    """Current host + GPU resource snapshot."""
    base = _psutil_metrics()
    gpu = _gpu_metrics()
    return {
        **base,
        **gpu,
        "platform": os.name,
        "python_version": sys.version.split()[0],
    }
