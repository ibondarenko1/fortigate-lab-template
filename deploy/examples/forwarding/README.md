# Forward Traffic evidence

## Observed on FortiGate-VM

On 2026-11-26 UTC, a LAN client sent three TCP probes toward a DMZ fixture on an activated FortiGate-VM. Both HTTP listeners returned the expected body from inside the DMZ before the LAN probes. For the third probe, a separate listener accepted a local connection, was closed, and returned connection refused on the next local check.

| Firmware and deployment | LAN destination | What the client and firewall recorded |
| --- | --- | --- |
| FortiOS 7.6.8 build 3744, KVM on Linux under WSL 2 | TCP/80 | HTTP 200 with the expected body. Forward Traffic recorded `close` under policy 2 for the same connection. |
| Same VM | TCP/8080 | The LAN probe timed out. Five matching `deny` records identified policy 3. |
| Same VM | TCP/18081 | The local listener had stopped. The LAN probe timed out and the export contained no matching record. The firewall decision is unknown. |

The capture preserves timestamps, source and destination ports, actions, policy IDs, version and build. Both endpoint addresses were replaced with documentation addresses. These policy IDs belong to this VM. [Recorded probes](fortios-7.6.8/probes.jsonl) · [Forward Traffic rows](fortios-7.6.8/forward-traffic.json) · [Example report](fortios-7.6.8/report.json)

Rebuild the report from the repository root with Python 3.11 or newer.

```sh
python deploy/scripts/forwarding_evidence.py report --probes deploy/examples/forwarding/fortios-7.6.8/probes.jsonl --logs deploy/examples/forwarding/fortios-7.6.8/forward-traffic.json --output report.json
```

## Synthetic exercises

The adjacent `probes.jsonl`, `forward-logs.jsonl` and `fortios-forward-response.json` are synthetic fixtures. They also cover an implicit deny under policy ID 0. Use them to teach the difference between an explicit deny, an implicit deny and a stopped listener.
