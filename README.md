# FortiGate Policy Lab

A restricted client can reach a DMZ web server because a broad allow rule comes first. Move the exception, compare the two configurations, and see which client loses access and which rule now handles its connection. On a FortiGate-VM, trace a real request from the LAN and match it to the firewall's Forward Traffic log.

**Start in your browser.** Diagnose three synthetic connection failures using listener checks, LAN results and log evidence. The exercise opens directly on GitHub Pages. [Try the troubleshooting lesson](https://ibondarenko1.github.io/fortigate-lab-template/lesson.html)

| Start here | What you can practice | What you need |
| --- | --- | --- |
| Local worksheet or CLI | Compare two policy snippets, inspect changed flows and address or service definitions, and grade a repair. | Python 3.11+ or Docker with Compose |
| Native firewall lab | Verify listeners and traffic across the firewall, then export the evidence for a particular policy decision. | A KVM-capable Linux or WSL 2 host, an authorized FortiOS 7.6.8 KVM image, and an activated VM |
| Company profile | Explore a populated directory, inspect department membership, and authenticate a test user through FortiGate. | The native lab and its company-profile service |

## Try the worksheet

Clone the repository or create your own copy with **Use this template**. Run the commands below from its root. [Create a copy](https://github.com/ibondarenko1/fortigate-lab-template/generate)

With Python, start the local worksheet with `python training/server.py`. With Docker, run `docker compose -p fortigate-worksheet -f training/compose.yaml up -d --build`. Open the worksheet and choose **Ordered exception before broad allow**. [Local worksheet](http://127.0.0.1:18846/training/)

Move policy 10 above policy 20 and compare the starter with your draft. For the restricted client on TCP/80, the first matching policy changes from 20 (allow) to 10 (deny). The regular client still reaches the server. Grade the draft to check the required rule identity and the networks and ports behind its objects. Drafts stay in your browser.

If port 18846 is in use, run `python training/server.py --port 28846` or set the Compose environment variable `WORKSHEET_PORT=28846` before starting the service. Open the same URL with the chosen port.

## Check changes from the command line

The CLI and local worksheet use the same offline IPv4/TCP evaluator. Run the included before-and-after example with Python.

```sh
python training/policy_cli.py compare ordered-exception training/scenarios/ordered-exception/starter.conf training/scenarios/ordered-exception/reference.conf
```

The JSON result identifies each tested flow, its first matching rule before and after the change, and changes to object definitions. Add `--fail-on-change` to use a comparison as a CI check. The exercise files declare the sampled flows. Coverage includes first-match IPv4 policies, subnet objects and TCP services. Unsupported configuration produces a diagnostic. [Scenario files](training/scenarios/) · [Add a teaching scenario](CONTRIBUTING.md)

## Run the native FortiGate lab

Follow the deployment guide to build the appliance from your own Fortinet KVM image, start the two test hosts, and activate the VM. The default FortiOS sign-in address on the Docker host is `https://127.0.0.1:18843/`. The guide also covers access from a separate browser PC over SSH. [Deployment guide](deploy/README.md) · [Fortinet VM evaluation terms and limits](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/441460/permanent-trial-mode-for-fortigate-vm)

For a first exercise, open **Policy & Objects → Firewall Policy** and find `LAB-LAN-DMZ-HTTP` and `LAB-LAN-DMZ-DENY-8080`. Run the traffic check from the repository root.

```sh
bash deploy/scripts/verify-forwarding.sh
```

Both ports have a listener on the DMZ server. On FortiOS 7.6.8 build 3744, the LAN client received HTTP 200 on port 80, and Forward Traffic identified the explicit deny on port 8080. A separate stopped-listener control shows what can be concluded when a log is missing. You can reproduce all three report results offline. [Native capture guide](deploy/README.md) · [Verified firmware, redacted capture and example report](deploy/examples/forwarding/)

For netlab users, the same three-interface layout is available as a containerlab topology. [netlab example](examples/netlab/)

## Load a company into FortiOS

**LABCO** is a fictional company with 12 local users across HR, Finance, Engineering, and Operations. Its profile adds six user groups, one RADIUS server, six IPv4 address objects, and three address groups. The objects appear in the native FortiOS tables and can be edited there.

On the Docker host, connect the worksheet to your running appliance. Supply the active deployment directory, an unused IP on its DMZ, and the verified public HTTPS certificate for that VM in PEM format. The certificate must cover the appliance management IP. The following example uses the default DMZ subnet.

```sh
NATIVE_GUI_URL=https://127.0.0.1:18843/ WORKSHEET_PROJECT=fortigate-worksheet \
  bash training/start-company.sh "$PWD/deploy" 10.231.32.30 /path/to/verified-fortigate-gui.pem
```

1. Open **Company Infrastructure** in the worksheet and select **Load company profile**. [Open the local company profile](http://practice.localhost:18846/training/#company)
2. Open **User Groups** in FortiOS and inspect `LABCO-GRP-FIN` to see its three members.
3. Select **Test RADIUS** in the worksheet. FortiGate authenticates `labco.radius.student` against the FreeRADIUS service on the lab DMZ. The fixture guide also covers testing a wrong password in FortiOS. [RADIUS fixture guide](training/radius/README.md)

**Remove profile** removes the objects created by the preset, including edits you made to those objects. Remove references from any policies you created before clearing the profile. The two starter firewall policies belong to the base lab.

If the browser runs on a different computer, forward both the native GUI port and worksheet port 18846. Set `NATIVE_GUI_URL` to the address reachable from that browser. Existing deployments that provide a local sign-in bridge can use the Windows tunnel helper. [Windows access helper](scripts/Open-NativeFortiGate.ps1)

## Audit the appliance with Ansible

The read-only playbook uses Fortinet's `fortinet.fortios` Ansible collection to report firmware version, build, and policy count. The lab pins the upstream Git commit for release 2.6.0. Run the playbook from a machine that can reach the appliance. [Fortinet release on GitHub](https://github.com/fortinet-ansible-dev/ansible-galaxy-fortios-collection/releases/tag/2.6.0) · [Ansible Galaxy](https://galaxy.ansible.com/ui/repo/published/fortinet/fortios/) · [Pinned dependencies](automation/requirements.yml) · [Audit playbook](automation/audit.yml)

```sh
bash automation/install.sh
source .venv/bin/activate
cd automation
cp inventory.example.yml inventory.local.yml
```

Set the HTTPS host and port in `inventory.local.yml`, configure trust for the appliance certificate, and supply a read-only API administrator token through the local `FORTIOS_ACCESS_TOKEN` environment variable. Run the playbook with that inventory.

```sh
ANSIBLE_CONFIG="$PWD/ansible.cfg" ansible-playbook -i inventory.local.yml audit.yml
```

For a lab with an existing loopback authentication bridge, the alternative is `bash audit-loopback.sh PORT /path/to/local-password-file` from the `automation` directory. Keep inventories and credentials local.

## License

The original lab code and training materials are available under the MIT License. FortiOS firmware is supplied separately by Fortinet under its own terms. Third-party dependencies retain their respective licenses. [MIT License](LICENSE)

This is an independent training project. FortiGate and FortiOS are Fortinet products.
