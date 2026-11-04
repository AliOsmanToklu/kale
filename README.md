# kale

**[English](README.md) · [Türkçe](README.tr.md)**

One command line and one result format for many security tools.

kale is a modular security toolkit. Each tool plugs in as a **module** that takes an
**observable** (a file, domain, URL, IP, hash, ...) and returns **findings** plus new
observables. Every module's output follows the same schema, so results can be compared,
stored, chained into other modules and served by an API or GUI later.

Existing tools join through thin adapters and stay independent projects:

| Module | Wraps | Accepts | Mode |
|---|---|---|---|
| `logs.auth` | [log-analyzer](https://github.com/AliOsmanToklu/log-analyzer): brute force, account compromise and username scanning in SSH / Windows logon logs | file | passive |
| `malware.static` | [malware-static-analyzer](https://github.com/AliOsmanToklu/malware-static-analyzer): PE imports and sections, suspicious strings, hashes and a heuristic risk score, analyzed in an isolated process | file | passive |
| `web.scan` | [Kalkan](https://github.com/AliOsmanToklu/KALKAN): TLS, headers, exposed files, ports, outdated software, SPF/DMARC/DKIM, DNS | domain, URL, IP | active |

## Installation

Requires Python 3.12+. The wrapped tools are installed from their own repositories,
next to this one:

```bash
git clone https://github.com/AliOsmanToklu/kale.git
git clone https://github.com/AliOsmanToklu/log-analyzer.git
git clone https://github.com/AliOsmanToklu/KALKAN.git kalkan
git clone https://github.com/AliOsmanToklu/malware-static-analyzer.git
cd kale
uv venv .venv
uv pip install -e ../log-analyzer -e ../kalkan -e ../malware-static-analyzer -e ".[dev]"
```

A module whose tool is not installed shows up as unavailable in `kale modules`; the rest
keep working. The tools are deliberately not declared as package dependencies: they are not
on PyPI, and an unpinned name there could resolve to someone else's package.

## Usage

```bash
kale modules                                  # list modules
kale modules logs.auth                        # accepted input, options, defaults
kale run logs.auth /var/log/auth.log          # text report
kale run logs.auth logons.csv -f json -o report.json
kale run logs.auth auth.log --set threshold=5 --set window=120
kale run web.scan example.com --scope example.com --lang tr
kale run logs.auth auth.log --fail-on high    # exit 1 if a high or critical finding (CI)
kale schema                                   # JSON schema of the result format
```

The target's kind is guessed from its form (an existing path is a file, `https://...` a URL,
and so on); `--kind` overrides the guess.

Exit codes: `0` done, `1` a finding reached `--fail-on`, `2` usage error, `3` the module
could not run (the report says why).

### Authorization and scope

Active modules send traffic to their target. Scanning systems without the owner's
permission can be illegal, so active modules refuse to run unless the target is listed in
a scope:

```bash
kale run web.scan shop.example.com --scope example.com       # subdomains included
kale run web.scan 198.51.100.7 --scope 198.51.100.0/24
kale run web.scan intranet.local --scope-file scope.txt --allow-private
```

A scope file holds one domain or CIDR per line; `#` starts a comment. Private and reserved
addresses also need `--allow-private`.

## Result format

Every run produces a `ModuleResult` ([schema](schemas/result.v1.json)):

```json
{
  "schema_version": "1",
  "module": "logs.auth",
  "module_version": "0.1.0",
  "target": {"kind": "file", "value": "auth.log", "source": ""},
  "findings": [
    {
      "rule_id": "logs.auth.brute_force",
      "severity": "high",
      "title": "Brute force from 203.0.113.45",
      "recommendation": "Block the address at the firewall, ...",
      "evidence": {"ip": "203.0.113.45", "total_failed": 40, "max_in_window": 21},
      "observables": [{"kind": "ip", "value": "203.0.113.45", "source": "logs.auth"}],
      "references": ["https://attack.mitre.org/techniques/T1110/"]
    }
  ],
  "observables": [{"kind": "ip", "value": "203.0.113.45", "source": "logs.auth"}],
  "summary": {"total_events": 66},
  "error": null
}
```

- `rule_id` is stable across versions, so findings can be tracked, suppressed or compared.
- `severity` is one of `critical`, `high`, `medium`, `low`, `info`.
- `observables` are facts other modules can take as input (an attacker IP for a reputation
  lookup, a software version for a CVE lookup).
- Failures never crash a run: they appear in `error` with a code (`invalid_input`,
  `out_of_scope`, `missing_secret`, `timeout`, `failed`).

## Writing a module

A module is a class with a `spec` and an async `run`:

```python
from typing import ClassVar

from kale.core import (
    Category, Finding, Kind, ModuleOutput, ModuleSpec, Observable, Option, RunContext, Severity,
)


class HashLookup:
    spec: ClassVar[ModuleSpec] = ModuleSpec(
        name="intel.hash",
        version="0.1.0",
        summary="Look up a file hash in a threat intelligence feed",
        category=Category.THREAT_INTEL,
        accepts=frozenset({Kind.HASH}),
        secrets=frozenset({"FEED_API_KEY"}),
        options={"timeout": Option("float", 10.0, "request timeout, seconds", minimum=1)},
    )

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        ...  # raise InvalidInputError for bad input; anything else is reported as a failure
        return ModuleOutput(findings=(Finding(rule_id="intel.hash.known_bad", ...),))
```

Register it in the plugin's `pyproject.toml`:

```toml
[project.entry-points."kale.modules"]
"intel.hash" = "my_plugin:HashLookup"
```

Loading a plugin runs its code, so third-party plugins load only when allow-listed:
`KALE_PLUGINS=intel.hash`. The engine handles the rest: input kind, scope, secrets, option
parsing, timeouts and error reporting. `tests/test_contract.py` checks every registered
module against the rules automatically.

## Architecture

```
src/kale/
├── core/            # the contract; knows nothing about the CLI or HTTP
│   ├── models.py    # Severity, Kind, Observable, Finding, ModuleResult (pydantic)
│   ├── module.py    # ModuleSpec, Option, RunContext, Module protocol
│   ├── registry.py  # entry-point discovery with an allowlist
│   ├── engine.py    # guards, timeout, error isolation
│   └── scope.py     # authorization scope for active modules
├── modules/         # built-in modules and adapters
├── report.py        # text (terminal-safe) and JSON renderers
└── cli.py           # thin command line layer
```

## Development

```bash
ruff format --check . && ruff check . && mypy && pytest --cov --cov-fail-under=90
```

Tests never touch the network: the Kalkan adapter is tested against a fake scanner.

## Roadmap

1. **Core** (this release): contract, registry, engine, scope, CLI and adapters for all three
   tools: `logs.auth`, `malware.static`, `web.scan`.
2. **Repository and CI**: CI that checks out the wrapped tools next to kale and runs the
   contract tests against them.
3. **New modules**: `intel.enrich` (IP/domain/URL/hash reputation), `vuln.intel` (CVEs from
   OSV/NVD, prioritized with CISA KEV and EPSS), `surface.discover` (subdomains from
   Certificate Transparency, subdomain takeover). Then `kale investigate`, which feeds each
   module's observables to the next.
4. **Interfaces**: FastAPI service with a job queue, HTML/PDF reports, web UI.
5. **Depth**: YARA, Sigma rules, EVTX, SARIF and STIX export, MITRE ATT&CK mapping.

## License

[MIT](LICENSE)
