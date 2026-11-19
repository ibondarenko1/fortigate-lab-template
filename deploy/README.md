# Standalone FortiGate-VM lab

This deployment runs official FortiOS in QEMU/KVM inside a Docker container. Docker Compose creates management, LAN, and DMZ networks. A practice client and an HTTP server sit on separate internal networks; FortiOS controls traffic between them.

## Requirements

Use a dedicated Linux x86-64 or WSL 2 lab host with access to `/dev/kvm` and `/dev/net/tun`, Python 3, Git, Docker Engine 28 or later, and Docker Compose 2.36 or later. Reserve at least 3 GB of RAM for the appliance and enough disk space for the firmware, local Docker image, build context, and persistent VM disk. The appliance container runs privileged to create interfaces and support management passthrough.

Obtain the **FortiGate-VM64 for KVM** package you are authorized to use from Fortinet Support. Extract the original standalone `fortios.qcow2` into a local directory. This template targets FortiOS 7.6.8. See the [Fortinet KVM deployment guide](https://docs.fortinet.com/document/fortigate-private-cloud/7.6.0/kvm-administration-guide/659352/deploying-the-fortigate-vm).

## Configure and start

Run these commands from the repository root on the lab host:

```bash
cd deploy
cp -n .env.example .env
```

Review `.env` before the first start. For each additional instance, choose a unique `COMPOSE_PROJECT_NAME`, local `FORTIGATE_IMAGE` tag, unused subnets, and four unused host ports. Leave `FORTIGATE_UUID` empty for the first start; the startup script generates it once and reuses it for that appliance.

`LAB_MGMT_GUEST_IP` and `LAB_MGMT_LINK_IP` must match for management passthrough. On LAN and DMZ, the guest, container link, and Docker bridge gateway must use distinct addresses. The example uses guest `.1`, container link `.2`, fixture `.10`, and bridge gateway `.254`. Choose the network layout before initial provisioning: the generated startup configuration is preserved on later starts.

The default host bindings are all restricted to `127.0.0.1`:

| Environment variable | Host port | Appliance port | Purpose |
| --- | --- | --- | --- |
| `LAB_GUI_PORT` | 18843 | 443 | HTTPS administration |
| `LAB_HTTP_PORT` | 18880 | 80 | Reserved HTTP mapping; HTTP administration is not enabled by the startup template |
| `LAB_SSH_PORT` | 18222 | 22 | SSH administration |
| `LAB_SERIAL_PORT` | 18500 | 5000 | Serial console |

Create the private administrator password, build the local appliance image, and start the lab:

```bash
(
  umask 077
  mkdir -p secrets
  if [ ! -e secrets/admin-password ]; then
    python3 -c 'import secrets; print(secrets.token_hex(20) + "Aa9!")' > secrets/admin-password
  fi
)
bash scripts/build-fortigate.sh /absolute/path/to/fortios.qcow2
bash scripts/start.sh
bash scripts/status.sh
```

The build script checks that the supplied disk is a standalone QCOW2 image and uses a pinned vrnetlab adapter commit. It retains the build context under `.build/`. Keep the firmware, build context, and resulting Docker image private; do not publish an image containing Fortinet firmware.

The appliance stores its persistent disk under `state/vm`. The initial configuration is generated once from `config/startup.conf.template` and stored in `state/startup.conf`. Secrets, runtime state, and build directories are excluded from Git.

## Sign in and activate

`scripts/start.sh` waits for the containers and then for the FortiOS HTTPS login page. Open `https://127.0.0.1:18843/` on the lab host, adjusting the port if you changed `LAB_GUI_PORT`.

To connect from another computer, forward the HTTPS port through SSH. Replace `my-lab-host` with your configured SSH destination and adjust both ports if necessary:

```sh
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:18843:127.0.0.1:18843 my-lab-host
```

Open the same localhost HTTPS URL on that computer. Sign in as `admin` using the password in the local `secrets/admin-password` file. Configure a trusted certificate or establish trust in your lab certificate for regular use.

Complete the VM activation permitted by your entitlement; consult [Fortinet's permanent trial documentation](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/441460/permanent-trial-mode-for-fortigate-vm). The native dashboard and available features depend on the installed FortiOS version and license. This template does not remove licensing restrictions.

## Verify policy enforcement

A fresh lab creates `LAB-LAN-NET` and `LAB-DMZ-NET` from the subnets in `.env`. Under **Policy & Objects > Firewall Policy**:

- Policy 1, `LAB-LAN-DMZ-HTTP`, permits HTTP on TCP port 80.
- Policy 2, `LAB-LAN-DMZ-DENY-8080`, denies TCP port 8080.

The DMZ fixture serves HTTP on both ports. After activation, run this command from `deploy`:

```bash
bash scripts/verify-forwarding.sh
```

The script first confirms that both services respond from within the server container. It then checks that the LAN client reaches port 80 and cannot reach port 8080. Confirm the matching policy events in **Log & Report > Forward Traffic**; an unreachable port alone does not establish which component blocked it. Traffic logs are stored in FortiOS memory.

### Docker bridge filtering

On hosts with Docker `DOCKER-INTERNAL` filtering, packets destined for the server may be dropped on the LAN bridge before reaching FortiOS. If this affects the lab, set `LAB_FIXTURE_BRIDGE=1` in `.env` and run `bash scripts/start.sh` again. The account running the script must have permission to modify the host's `DOCKER-USER` chain. This helper requires Docker's iptables integration and the `physdev` match.

The helper discovers the current Compose client and server, then installs four narrowly scoped rules for their exact addresses, TCP ports 80 and 8080, and frames bridged within each of the two internal networks. FortiOS still controls forwarding between LAN and DMZ. The helper does not enable additional service ports.

After restarting the Docker service, restore these rules from `deploy`:

```bash
python3 scripts/fixture-bridge.py apply
```

The normal `scripts/stop.sh` command removes the fixture rules before stopping the containers when `LAB_FIXTURE_BRIDGE=1` and both fixtures are running.

## Stop, restart, and preserve work

From `deploy`, use:

```bash
bash scripts/stop.sh
bash scripts/start.sh
```

These commands preserve the VM disk and native configuration. If you change the `admin` password in FortiOS, update the private password file before restarting. Back up the running appliance through the native FortiOS menu and store the backup outside Git.

For a separate clean lab, start with a new template directory, a fresh official disk, unique instance settings, and a separate authorized activation. Do not reuse the existing appliance UUID or persistent VM disk for a new instance.
