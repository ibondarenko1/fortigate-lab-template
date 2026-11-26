# Scenario bundles

Each directory is one offline FortiOS exercise. The directory name and the
`id` in `scenario.json` must match. Keep the two snapshots in the fixed files
`starter.conf` and `reference.conf`.

`scenario.json` contains `schema_version: 1`, learner-facing text, graded
`cases`, and optional `flows`. A case with an integer `expected_policy` points
to that policy ID in `reference.conf`. A null `expected_policy` means an
implicit default deny is required. The engine validates the declared outcome
against the trusted reference policy and checks effective networks and TCP
port ranges after parsing.

Run the collection locally with:

```sh
python training/policy_cli.py list
python training/policy_cli.py grade ordered-exception training/scenarios/ordered-exception/starter.conf
python training/policy_cli.py compare ordered-exception \
  training/scenarios/ordered-exception/starter.conf \
  training/scenarios/ordered-exception/reference.conf \
  --fail-on-change
```

Set `--scenario-dir ../my-scenarios` to validate a separate collection. The
same fixed filenames and schema are used by the browser worksheet and CLI.

The CLI uses exit code `0` for a passing grade (or a valid comparison with no
requested failure), `1` for a valid non-passing grade or a comparison rejected
by `--fail-on-change`, and `2` for an unknown scenario, malformed snapshot, or
other invalid input.
