# MedDefense Perimeter Defense

This project builds and validates local network controls and produces structured
JSON evidence for the MedDefense Module 3 analyst handoff.

## Task 0 — Network Baseline

`0-network_baseline.sh` captures the hardened endpoint's current local network
view without modifying network or system state. It records active interfaces,
routes, neighbors, listening sockets, established TCP connections and DNS
resolver configuration in `network_baseline.json`.

### Dependencies

- Bash
- iproute2 (`ip` and `ss`)
- jq
- systemd tools (`systemctl` and `resolvectl`) when `systemd-resolved` is used

### Usage

```bash
chmod +x 0-network_baseline.sh
sudo ./0-network_baseline.sh
jq . network_baseline.json
```

Run the script with `sudo` so that `ss -p` can resolve process names and PIDs
for sockets owned by other users. The optional first argument changes the output
path:

```bash
sudo ./0-network_baseline.sh evidence/network_baseline.json
```

---

