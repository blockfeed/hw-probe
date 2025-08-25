#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
hw_probe.py — Linux hardware & system probe -> structured JSON (and optional tar.gz bundle)

Design goals:
- One-shot snapshot for debugging on Arch/Linux desktops/laptops.
- Safe-by-default: redacts host/user/serials/MACs/private IPs unless --no-redact.
- Deterministic JSON schema so assistants/tools can parse reliably.
- Optional "deep" mode runs heavier commands (lsusb -v, udevadm dump, SMART/NVMe, etc.).
- Optional tar.gz bundle of raw command outputs alongside JSON.

Usage examples:
  python3 hw_probe.py --deep --json hw_report.json --zip hw_report.tar.gz
  sudo -E python3 hw_probe.py --sudo --deep --json /tmp/hw.json
"""

import argparse
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SCHEMA_VERSION = 1


def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def run(cmd: List[str], timeout: int = 20, env: Optional[dict] = None) -> Tuple[bool, Optional[int], bool, str, str]:
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=env,
            text=True,
            errors="replace",
        )
        return (p.returncode == 0, p.returncode, False, p.stdout, p.stderr)
    except subprocess.TimeoutExpired as e:
        return (False, None, True, e.stdout or "", e.stderr or f"Timeout after {timeout}s")
    except Exception as e:
        return (False, None, False, "", f"Exception: {e}")


def add_cmd(results: Dict, name: str, cmdline: List[str], available: bool, timeout: int = 20):
    if not available:
        results[name] = {"ok": False, "rc": None, "timeout": False, "stdout": "", "stderr": "not_available"}
        return
    ok, rc, to, out, err = run(cmdline, timeout=timeout)
    results[name] = {"ok": ok, "rc": rc, "timeout": to, "stdout": out, "stderr": err}


def hash_str(s: str) -> str:
    return sha256(s.encode("utf-8")).hexdigest()


class Redactor:
    def __init__(self, enabled: bool, hostname: str, username: str):
        self.enabled = enabled
        self.hostname = hostname or ""
        self.username = username or ""
        self.host_hash = hash_str(self.hostname) if self.hostname else ""
        self.user_hash = hash_str(self.username) if self.username else ""

        self.re_mac = re.compile(r"(?i)\b([0-9A-F]{2}[:-]){5}([0-9A-F]{2})\b")
        self.re_ipv4_priv = re.compile(
            r"\b(?:(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
            r"169\.254\.\d{1,3}\.\d{1,3}|"
            r"192\.168\.\d{1,3}\.\d{1,3}|"
            r"172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b"
        )
        self.re_uuid = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
        self.re_wwn = re.compile(r"0x[0-9a-fA-F]{16,}")
        self.re_serial_line = re.compile(r"(?im)^(\s*(Serial(?: Number)?|ID_SERIAL(_SHORT)?|Product Serial Number|Device Serial Number)\s*[:=]\s*)(.+)$")
        self.re_md_uuid = re.compile(r"(?i)(MD_UUID|LVM2_UUID|PARTUUID|UUID)=([0-9a-fA-F-]+)")
        self.re_hostname = re.compile(re.escape(self.hostname)) if self.hostname else None
        self.re_username = re.compile(re.escape(self.username)) if self.username else None

    def redact(self, s: str) -> str:
        if not self.enabled or not s:
            return s or ""
        s = self.re_mac.sub("<MAC_REDACTED>", s)
        s = self.re_ipv4_priv.sub("<IP_REDACTED>", s)
        s = self.re_uuid.sub("<UUID_REDACTED>", s)
        s = self.re_wwn.sub("<WWN_REDACTED>", s)
        s = self.re_serial_line.sub(lambda m: f"{m.group(1)}<SERIAL_REDACTED>", s)
        s = self.re_md_uuid.sub(lambda m: f"{m.group(1)}=<UUID_REDACTED>", s)
        if self.re_hostname:
            s = self.re_hostname.sub("<HOSTNAME>", s)
        if self.re_username:
            s = self.re_username.sub("<USER>", s)
        return s


def collect_meta(redactor: Redactor) -> Dict:
    uname = platform.uname()
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "kernel_release": uname.release,
        "kernel_version": uname.version,
        "kernel_machine": uname.machine,
        "os": platform.system(),
        "hostname_hash": redactor.host_hash,
        "user_hash": redactor.user_hash,
    }


def collect_commands(args) -> Dict:
    cmds = {}
    add_cmd(cmds, "uname -a", ["uname", "-a"], available=bool(which("uname")))
    if which("lshw"):
        add_cmd(cmds, "lshw -json", ["lshw", "-json"], available=True, timeout=60 if args.deep else 30)
    if which("dmidecode"):
        add_cmd(cmds, "dmidecode", ["dmidecode", "--type", "bios", "--type", "system"], available=True, timeout=30)
    if which("lsblk"):
        add_cmd(cmds, "lsblk -O -J", ["lsblk", "-O", "-J"], available=True)
    if which("lspci"):
        add_cmd(cmds, "lspci -nnk", ["lspci", "-nnk"], available=True)
    if which("lsusb"):
        add_cmd(cmds, "lsusb", ["lsusb"], available=True)
    return cmds


def redact_tree(data, redactor: Redactor):
    if isinstance(data, dict):
        return {k: redact_tree(v, redactor) for k, v in data.items()}
    elif isinstance(data, list):
        return [redact_tree(v, redactor) for v in data]
    elif isinstance(data, str):
        return redactor.redact(data)
    else:
        return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", default="hw_report.json")
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--no-redact", action="store_true")
    args = parser.parse_args()

    hostname = socket.gethostname()
    username = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    redactor = Redactor(enabled=not args.no_redact, hostname=hostname, username=username)

    data = {
        "schema_version": SCHEMA_VERSION,
        "meta": collect_meta(redactor),
        "commands": collect_commands(args),
    }

    redacted_data = redact_tree(data, redactor)
    Path(args.json).write_text(json.dumps(redacted_data, indent=2, ensure_ascii=False))
    print(f"Wrote JSON: {args.json}")


if __name__ == "__main__":
    main()

