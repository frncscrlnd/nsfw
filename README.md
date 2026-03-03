# **N**avigator for **S**ecurity **F**rame**w**orks

A security tool that maps relationships across the major cybersecurity knowledge bases: **CVE**, **CWE**, **CAPEC**, **ATT&CK**, and **D3FEND**. Heavily inspired from **galeax.github.io/CVE2CAPEC/**


## What it does

![Diagram](img/diagram.drawio.png)

Security frameworks don't exist in isolation — a vulnerability (CVE) maps to a weakness class (CWE), which maps to an attack pattern (CAPEC), which maps to an ATT&CK technique, which maps to a D3FEND defensive countermeasure. NSFW traverses this entire chain for you.

You enter a single ID from any supported framework. NSFW instantly shows you every related entry across all the others, letting you pivot from a known CVE all the way to actionable defenses — or in reverse, from a D3FEND technique back to the CVEs it protects against.

---

## Features

- **Bidirectional traversal** — search from any framework, navigate in any direction
- **Multi-ID filtering** — check multiple IDs to intersect results and narrow your research
- **CISA KEV highlighting** — CVEs present in the Known Exploited Vulnerabilities catalog are flagged with a pulsing red badge
- **CPE panel** — for checked CVEs, view all affected products and versions (vendor/product/version breakdown)
- **Autocomplete** — instant suggestions as you type any ID
- **Direct links** — every entry links to its official source (cve.org, cwe.mitre.org, capec.mitre.org, attack.mitre.org, d3fend.mitre.org)
- **Fully client-side** — no backend, no tracking, no requests after initial data load

---

## Supported Frameworks

| Framework | Description | Example ID |
|-----------|-------------|------------|
| [CVE](https://www.cve.org/) | Common Vulnerabilities and Exposures | `CVE-2021-44228` |
| [CWE](https://cwe.mitre.org/) | Common Weakness Enumeration | `CWE-79` |
| [CAPEC](https://capec.mitre.org/) | Common Attack Pattern Enumeration and Classification | `CAPEC-86` |
| [ATT&CK](https://attack.mitre.org/) | MITRE ATT&CK Techniques | `T1059` / `T1059.001` |
| [D3FEND](https://d3fend.mitre.org/) | MITRE D3FEND Countermeasures | `D3-MFA` |

---

## Data Files

NSFW reads from a local `./data/` directory at startup. The expected files are:

```
data/
├── cve_cwe.json        # CVE → [CWE, ...]
├── cwe_capec.json      # CWE → [CAPEC, ...]
├── capec_attack.json   # CAPEC → [ATT&CK, ...]
├── attack_defend.json  # ATT&CK → [D3FEND, ...]
├── cve_cpe.json        # CVE → [CPE, ...]
└── kevs.txt            # One CVE ID per line (CISA KEV catalog)
```

All mapping files are plain JSON objects where keys are framework IDs and values are arrays of related IDs. `kevs.txt` is a newline-separated list of CVE IDs marked as known exploited.

---

## How it works

On load, NSFW fetches the data files, builds inverted indexes in memory, and is ready to resolve relationships in any direction. When you search for an ID:

1. The type is detected by pattern matching (`CVE-*`, `CWE-*`, `CAPEC-*`, `T####`, `D3-*`)
2. The graph is traversed forward and backward across all mappings
3. Results are displayed in a columnar table, one column per framework
4. Checking items in the table intersects their result sets, filtering down to only shared relationships

