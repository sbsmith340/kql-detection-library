# KQL Detection Library

> 13 Microsoft Sentinel / Defender XDR detections written as code. Each one is mapped to MITRE ATT&CK, documents its tuning and false positives, and includes a lab test procedure. One command validates every rule and builds a Sentinel ARM template.

![ci](https://github.com/sbsmith340/kql-detection-library/actions/workflows/ci.yml/badge.svg)
![detections](https://img.shields.io/badge/detections-13-blue)
![status](https://img.shields.io/badge/lab%20validation-pending-yellow)

## Problem
Detection rules written straight into the Sentinel portal tend to drift. Nobody remembers why a threshold was chosen, what the known false positives are, or how to prove the rule still fires. And a typo in a query only shows up when the rule silently stops working.

## What I built
- **13 detections** across identity, endpoint, email, and cloud. Each is a YAML file holding the KQL plus the context an analyst needs: ATT&CK mapping, entity mappings, tuning guidance, known false positives, and a step-by-step lab test.
- **Validator** (`tools/build.py`) that fails the build when:
  - a field is missing, or an ATT&CK tactic or technique ID is malformed
  - a declared data source isn't used, or an entity column doesn't appear in the query
  - parentheses are unbalanced, or the lookback is shorter than the run frequency (which leaves gaps)
- **Generators** for a [detection index with ATT&CK coverage](docs/INDEX.md) and a **Sentinel ARM template** ([`deploy/analytics-rules.json`](deploy/analytics-rules.json)) that deploys every rule as a scheduled analytics rule. Rules deploy **disabled** so they're reviewed first.
- **CI**: GitHub Actions validates every rule and checks the generated files are current on every push.

## Detections

| Area | Detection | ATT&CK |
|---|---|---|
| Identity | Password spray against Entra ID | T1110.003 |
| Identity | Successful sign-ins from two countries within a short window | T1078.004 |
| Identity | MFA fatigue: repeated denials followed by approval | T1621 |
| Identity | Privileged Entra ID role assigned outside PIM | T1098.003 |
| Identity | User consent to OAuth app with high-risk permissions | T1528 |
| Endpoint | PowerShell with encoded command (auto-decodes the payload) | T1059.001, T1027 |
| Endpoint | LSASS dump via comsvcs.dll or known credential tools | T1003.001 |
| Endpoint | Office app spawns a script interpreter or LOLBin | T1204.002, T1566.001 |
| Endpoint | Brute-force network logons followed by success | T1110.001, T1021.001 |
| Email | User clicked through a malicious URL | T1566.002, T1204.001 |
| Email | Inbox rule forwards mail externally or hides messages | T1114.003 |
| Cloud | Mass deletion of Azure resources by one identity | T1485 |
| Cloud | NSG rule opens a management port to the internet | T1562.007, T1133 |

Full table with severity and data sources: [docs/INDEX.md](docs/INDEX.md)

## Anatomy of a detection

```yaml
name: MFA fatigue - repeated push denials followed by approval
severity: High
status: lab-test-pending          # lab-test-pending -> lab-tested -> production
tactics: [CredentialAccess]
techniques: [T1621]
data_sources: [SigninLogs]
query_frequency: PT30M
query_period: PT1H
query: |
  ...KQL...
entity_mappings: [...]            # Account + IP so incidents correlate
tuning: Raise minDenied if users routinely miss prompts.
false_positives: A user who missed several prompts on a new phone, then approved.
test: Trigger and deny four push prompts for a lab account, then approve the fifth.
```

## How to use it

**Validate and build**
```bash
pip install pyyaml pytest
python tools/build.py          # validates, regenerates docs/INDEX.md and deploy/analytics-rules.json
pytest -q tests
```

**Hunt with a single query.** Copy the `query` block into Sentinel Logs or Defender Advanced Hunting. Device and Email tables come from the Defender XDR connector, `SigninLogs` and `AuditLogs` from the Entra ID connector, `OfficeActivity` from the Office 365 connector, and `AzureActivity` from the Azure Activity connector.

**Deploy all rules to a lab workspace**
```bash
az deployment group create -g <sentinel-rg> \
  --template-file deploy/analytics-rules.json \
  --parameters workspace=<workspace-name> enableRules=false
```
Review each rule in **Sentinel → Analytics**, then enable it after running its lab test.

## Validation status
The validator and tests check structure, schema, and internal consistency. They **cannot execute KQL**. Every rule is marked `lab-test-pending` until its `test` procedure has been run in a lab workspace and the rule has fired. That status is updated in the YAML as each one is proven, and the index shows the current state.

## Design choices
- **Threshold-based rules come with their thresholds as `let` variables** at the top, so tuning is a one-line change with a visible diff.
- **Entity mappings on every rule** so Sentinel groups related alerts into one incident instead of many.
- **Preventive control named alongside the detection** wherever one exists (ASR rules, consent restrictions, auto-forward blocking, Azure Policy). A detection is the backstop, not the fix.

## Limitations & what's next
- Run every lab test, flip statuses to `lab-tested`, and record the lab alert screenshots in `docs/evidence/`
- Add a KQL syntax check in CI using the Kusto.Language parser
- Add UEBA-backed variants (e.g. first-time country for this user) once a baseline exists
- Add an AWS CloudTrail pack

## Repo layout
```
detections/<area>/*.yaml    one file per detection
tools/build.py              validator + generators
docs/INDEX.md               generated index and ATT&CK coverage
deploy/analytics-rules.json generated Sentinel ARM template
tests/                      validator tests
```

---
All examples use fictional domains (contoso.com). Built by [Shawn Smith](https://sbsmith340.github.io).
