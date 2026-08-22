#!/usr/bin/env python3
"""Bounded discovery comparison. Run only against an authorized lab target."""
import argparse
import json
import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
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
        cpu_by_pid = {}
        while process.poll() is None:
            if measured:
                try:
                    process_tree = [measured, *measured.children(recursive=True)]
                    current_rss = 0
                    for member in process_tree:
                        try:
                            current_rss += member.memory_info().rss
                            cpu = member.cpu_times()
                            cpu_by_pid[member.pid] = max(
                                cpu_by_pid.get(member.pid, 0), cpu.user + cpu.system
                            )
                        except psutil.Error:
                            pass
                    max_rss = max(max_rss or 0, current_rss)
                    cpu_seconds = sum(cpu_by_pid.values())
                except psutil.Error:
                    pass
            time.sleep(0.05)
        captured_out.seek(0); stdout = captured_out.read()
        captured_err.seek(0); stderr = captured_err.read()
    return {
        "command": command,
        "elapsed_seconds": round(time.perf_counter()-started, 3),
        "cpu_seconds": round(cpu_seconds, 3) if cpu_seconds is not None else None,
        "peak_process_tree_rss_bytes": max_rss,
        "measurement_note": None if psutil else "install psutil for CPU/RAM metrics",
        "exit_code": process.returncode,
        "stdout": stdout,
        "stderr": stderr,
    }

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--scanner", required=True)
    parser.add_argument("--target", action="append", required=True)
    parser.add_argument("--ports", default="1-65535")
    parser.add_argument("--scan-mode", choices=("connect","syn"), default="connect")
    parser.add_argument("--processes", type=int, default=1)
    parser.add_argument("--worker-threads", type=int)
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="surface-bench-") as directory:
        result_path=Path(directory)/"scanner.jsonl"
        scanner_command=[args.scanner,"--scan-mode",args.scan_mode,"--processes",str(args.processes),"-p",args.ports,"-o",str(result_path),*args.target]
        if args.worker_threads is not None:
            scanner_command[3:3] = ["--worker-threads", str(args.worker_threads)]
        scanner=run(scanner_command)
        scanner["open_ports_by_host"]={}
        if result_path.exists():
            for line in result_path.read_text(encoding="utf-8").splitlines():
                host=json.loads(line)
                scanner["open_ports_by_host"][host["ip"]]=sorted(s["port"] for s in host.get("services",[]))
        report={"surface_scan":{k:v for k,v in scanner.items() if k not in ("stdout","stderr")}}
        if shutil.which("nmap"):
            nmap=run(["nmap","-Pn",f"-p{args.ports}","--open","-oX","-",*args.target])
            nmap_ports={}
            report["nmap"]={k:v for k,v in nmap.items() if k not in ("stdout","stderr")}
            if nmap["exit_code"] != 0:
                report["nmap"]["parse_error"]="nmap exited unsuccessfully; XML comparison skipped"
                print(json.dumps(report,indent=2))
                return
            try:
                root=ET.fromstring(nmap["stdout"])
            except ET.ParseError as error:
                report["nmap"]["parse_error"]=f"invalid nmap XML: {error}"
                print(json.dumps(report,indent=2))
                return
            for host in root.findall("host"):
                address=host.find("address")
                if address is None: continue
                nmap_ports[address.attrib["addr"]]=sorted(
                    int(port.attrib["portid"])
                    for port in host.findall("./ports/port")
                    if port.find("state") is not None and port.find("state").attrib.get("state")=="open"
                )
            report["nmap"]["open_ports_by_host"]=nmap_ports
            report["comparison"]={}
            for target in sorted(set(scanner["open_ports_by_host"]) | set(nmap_ports)):
                scanner_ports=set(scanner["open_ports_by_host"].get(target,[])); reference=set(nmap_ports.get(target,[]))
                report["comparison"][target]={
                    "open_port_recall": (len(scanner_ports & reference)/len(reference)) if reference else None,
                    "scanner_only_ports": sorted(scanner_ports-reference),
                    "nmap_only_ports": sorted(reference-scanner_ports),
                }
            report["comparison_note"]="HTTP detection recall requires labelled fixture results and is not inferred from nmap service versions"
        else: report["nmap"]={"skipped":"nmap not found"}
        print(json.dumps(report,indent=2))

if __name__ == "__main__": main()
