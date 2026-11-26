# Contribute a policy exercise

An exercise starts with a broken FortiOS CLI snippet, a working reference and a set of traffic expectations. Both the browser worksheet and the CLI load the scenario from disk. A useful exercise gives the learner one decision to repair and includes at least one connection that would expose an overly broad fix.

## Build a scenario

1. Copy `training/scenarios/custom-tcp-port/` to a directory with a new lowercase, hyphenated ID. Set the same `id` in `scenario.json`. Use schema version 1.
2. Write the intended configuration in `reference.conf`. Derive `starter.conf` by introducing the mistake. Use synthetic addresses, object names and users. The supported subset covers IPv4 subnet objects, custom TCP destination ports, and ordered IPv4 firewall policies on an always-on schedule.
3. In `scenario.json`, describe the symptom, task and repair criteria. Give every flow a unique ID, source and destination addresses, incoming and outgoing interfaces, protocol and destination port. In `cases`, specify the expected outcome and rule ID. In `flows`, add boundary checks, such as an adjacent port or a second client outside the permitted subnet. An expected policy of `null` tests implicit deny.
4. Keep the setup within the three-policy budget used by the exercises. Give the intended solution, a plausible wrong solution and the observation that distinguishes them in your pull request. Include the version and build if you verified it on FortiOS.

## Check the contribution

```sh
python training/policy_cli.py list
python training/policy_cli.py grade custom-tcp-port training/scenarios/custom-tcp-port/starter.conf
python training/policy_cli.py grade custom-tcp-port training/scenarios/custom-tcp-port/reference.conf
python training/policy_cli.py compare custom-tcp-port training/scenarios/custom-tcp-port/starter.conf training/scenarios/custom-tcp-port/reference.conf
python -m pytest -q training
```

Substitute your new ID and paths. A valid reference passes and the broken starter exits with 1. Inspect the comparison for the intended change in first-match policy, action or scope. CI also builds the worksheet, calls the API on every packaged scenario, and runs the isolated FreeRADIUS checks.

## Instructor handout

| Before the exercise | Student deliverable |
| --- | --- |
| Give the student the starter, topology or interface pair, and a symptom. | Predict which policy handles one allowed flow and one denied flow. |
| Ask for the smallest edit that satisfies the traffic requirements. | Submit the repaired snippet and the before/after comparison. Identify a neighboring address or port that must stay blocked. |
| Provide the synthetic evidence lesson or an activated lab. | Correlate one request to a Forward Traffic record by time and TCP five-tuple. Identify the action and policy ID, or explain which observation is missing. |

When sharing results, label the source as offline evaluation, synthetic example, or VM observation. Use the redacted forwarding report for a VM observation. The repository accepts original teaching material under its MIT license. [Interactive lesson](https://ibondarenko1.github.io/fortigate-lab-template/lesson.html) · [Native verification guide](deploy/README.md)
