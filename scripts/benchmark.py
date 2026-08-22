#!/usr/bin/env python3
"""Bounded discovery comparison. Run only against an authorized lab target."""
import argparse
import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None

def run(command):
    started = time.perf_counter()
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as captured_out, tempfile.TemporaryFile(mode="w+", encoding="utf-8") as captured_err:
        process = subprocess.Popen(command, text=True, stdout=captured_out, stderr=captured_err)
        max_rss = None
        cpu_seconds = None
        measured = psutil.Process(process.pid) if psutil else None
        while process.poll() is None:
            if measured:
                try:
                    max_rss = max(max_rss or 0, measured.memory_info().rss)
                    cpu = measured.cpu_times()
                    cpu_seconds = cpu.user + cpu.system
                except psutil.Error:
                    pass
            time.sleep(0.05)
        captured_out.seek(0); stdout = captured_out.read()
        captured_err.seek(0); stderr = captured_err.read()
    return {
        "command": command,
        "elapsed_seconds": round(time.perf_counter()-started, 3),
        "cpu_seconds": round(cpu_seconds, 3) if cpu_seconds is not None else None,
        "peak_rss_bytes": max_rss,
        "measurement_note": None if psutil else "install psutil for CPU/RAM metrics",
        "exit_code": process.returncode,
        "stdout": stdout,
        "stderr": stderr,
    }

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--scanner", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--ports", default="1-65535")
    parser.add_argument("--scan-mode", choices=("connect","syn"), default="connect")
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="surface-bench-") as directory:
        result_path=Path(directory)/"scanner.jsonl"
        scanner=run([args.scanner,"--scan-mode",args.scan_mode,"-p",args.ports,"-o",str(result_path),args.target])
        scanner["open_ports"]=[]
        if result_path.exists():
            for line in result_path.read_text(encoding="utf-8").splitlines():
                host=json.loads(line); scanner["open_ports"].extend(s["port"] for s in host.get("services",[]))
        report={"surface_scan":{k:v for k,v in scanner.items() if k not in ("stdout","stderr")}}
        if shutil.which("nmap"):
            nmap=run(["nmap","-Pn",f"-p{args.ports}","--open",args.target])
            nmap_ports=sorted({int(port) for port in re.findall(r"(?m)^(\d+)/tcp\s+open\b",nmap["stdout"])})
            scanner_ports=set(scanner["open_ports"]); reference=set(nmap_ports)
            report["nmap"]={k:v for k,v in nmap.items() if k not in ("stdout","stderr")}
            report["nmap"]["open_ports"]=nmap_ports
            report["comparison"]={
                "open_port_recall": (len(scanner_ports & reference)/len(reference)) if reference else None,
                "scanner_only_ports": sorted(scanner_ports-reference),
                "nmap_only_ports": sorted(reference-scanner_ports),
                "note": "HTTP detection recall requires labelled fixture results and is not inferred from nmap service versions",
            }
        else: report["nmap"]={"skipped":"nmap not found"}
        print(json.dumps(report,indent=2))

if __name__ == "__main__": main()
