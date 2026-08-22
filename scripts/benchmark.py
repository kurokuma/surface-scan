#!/usr/bin/env python3
"""Bounded discovery comparison. Run only against an authorized lab target."""
import argparse
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

def run(command):
    started = time.perf_counter()
    process = subprocess.run(command, text=True, capture_output=True, check=False)
    return {"command": command, "elapsed_seconds": round(time.perf_counter()-started, 3), "exit_code": process.returncode, "stdout": process.stdout, "stderr": process.stderr}

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
            report["nmap"]={k:v for k,v in nmap.items() if k != "stderr"}
        else: report["nmap"]={"skipped":"nmap not found"}
        print(json.dumps(report,indent=2))

if __name__ == "__main__": main()

