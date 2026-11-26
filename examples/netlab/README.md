# Generate the LAN to DMZ topology

This netlab example connects a Linux client to FortiOS `port2` and a DMZ web server to `port3`. Management uses `port1`. The LAN address pool covers both data subnets so each Linux host gets a route to its peer through the firewall.

Copy `topology.yml` to a new working directory on a host with netlab installed. From that directory, generate the containerlab files and expanded model.

```sh
netlab create topology.yml
netlab create topology.yml -o yaml=expanded.yml
```

With netlab 26.11, `clab.yml` was generated and the expanded model contained the following routes.

| Node | Destination | Gateway |
| --- | --- | --- |
| client | 10.231.0.0/16 | 10.231.31.1 |
| web | 10.231.0.0/16 | 10.231.32.1 |

These commands verify configuration generation. The Docker/KVM lab has a separate traffic check with two listeners and Forward Traffic evidence. Running the netlab topology requires your own authorized appliance image and activation. [Native lab guide](../../deploy/README.md) · [Original topology and discussion](https://github.com/ipspace/netlab/discussions/4098)
