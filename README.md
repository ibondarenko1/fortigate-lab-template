# FortiGate Lab Template

A hands-on lab for network administrators, students, and instructors learning FortiOS. Trace a connection from a LAN client through a FortiGate-VM to a DMZ web server, find the matching policy in the traffic log, and test an employee login against FreeRADIUS. The lab runs on your own host and uses the native FortiOS interface.

See the project guide for a preview of the populated FortiOS user directory and the prerequisites for each setup. [FortiGate homelab guide](https://ibondarenko1.github.io/fortigate-lab-template/)

| Start here | What you can practice | What you need |
| --- | --- | --- |
| Browser worksheet | Repair three FortiOS CLI configurations and check which rule matches each sample flow. | Docker and the Compose plugin |
| Native firewall lab | Edit policies in FortiOS, send real traffic, and inspect Forward Traffic logs. | A KVM-capable Linux or WSL 2 host, an authorized FortiOS 7.6.8 KVM image, and an activated VM |
| Company profile | Explore a populated directory, inspect department membership, and authenticate a test user through FortiGate. | The native lab and its company-profile service |

## Try the worksheet

Select **Use this template** on GitHub, clone your copy, and run the following command from the repository root. [Create a repository from this template](https://github.com/ibondarenko1/fortigate-lab-template/generate)

```sh
docker compose -p fortigate-worksheet -f training/compose.yaml up -d --build
```

Open [the local worksheet](http://practice.localhost:18846/training/). Choose an exercise, edit its CLI configuration, and select **Check configuration**. The three exercises cover a host-specific HTTP rule, an exception shadowed by a broader rule, and a custom TCP service with the wrong port. Each check shows the expected rule and the rule that actually matched. Drafts stay in your browser. This mode works without a FortiOS image or account.

## Run the native FortiGate lab

Follow the deployment guide to build the appliance from your own Fortinet KVM image, start the two test hosts, and activate the VM. The default FortiOS sign-in address on the Docker host is `https://127.0.0.1:18843/`. The guide also covers access from a separate browser PC over SSH. [Deployment guide](deploy/README.md) · [Fortinet VM evaluation terms and limits](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/441460/permanent-trial-mode-for-fortigate-vm)

For a first exercise, open **Policy & Objects → Firewall Policy** and find `LAB-LAN-DMZ-HTTP` and `LAB-LAN-DMZ-DENY-8080`. Run the traffic check from the repository root.

```sh
bash deploy/scripts/verify-forwarding.sh
```

Both ports have a listener on the DMZ server. The LAN client should reach TCP 80 and be denied on TCP 8080. In **Log & Report → Forward Traffic**, look for policy IDs 1 and 2 and compare their actions.

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
