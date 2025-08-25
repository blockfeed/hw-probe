# hw_probe

Hardware & system probe for Linux (Arch-focused).

## Features

- Collects detailed hardware/software info (CPU, GPU, firmware, drivers, etc.).
- Outputs deterministic JSON schema (safe by default with redaction of host/user/serial/MAC/private IP).
- Optional `--deep` mode: `lsusb -v`, `udevadm dump`, SMART/NVMe details, etc.
- Optional `--zip` tarball with raw command outputs alongside JSON.
- Arch-specific package probe (`pacman -Q`) for kernel, mesa, firmware, audio, etc.

## Usage

```bash
# Minimal probe
python3 hw_probe.py --json hw_report.json

# Deep probe (heavier commands)
python3 hw_probe.py --deep --json hw_report.json --zip hw_report.tar.gz

# With sudo (for dmidecode), still redacts identifiers by default
sudo -E python3 hw_probe.py --sudo --deep --json /tmp/hw.json
```

## JSON Schema (v1)

```jsonc
{
  "schema_version": 1,
  "meta": {...},
  "env": {...},
  "files": {...},
  "packages": {...},
  "commands": {
     "<cmd string>": {
       "ok": true/false,
       "rc": <int or null>,
       "timeout": false,
       "stdout": "<string>",
       "stderr": "<string>"
     }
  },
  "notes": [ "...", ... ]
}
```

## License

MIT
