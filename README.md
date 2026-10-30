# PK ccTLD DNSSEC Bulk Signing Checker

<div align="center">
<img src="pk-cctld-dnssec.png" alt="PK ccTLD DNSSEC Bulk Signing Checker" width="650">
</div>

A lightweight Python utility to assess DNSSEC deployment across domains registered under Pakistan's country-code Top-Level Domain (**.pk**).

This tool allows researchers, DNS operators, Internet governance professionals, and the wider technical community to identify how many `.pk` domains have DNSSEC enabled and are successfully publishing DNSSEC-related records.

By processing a list of `.pk` domains, the program performs DNS lookups and checks their DNSSEC signing status, producing a CSV report for further analysis.

## Objectives

The primary objectives of this project are to:

- Measure DNSSEC adoption across domains under the `.pk` ccTLD.
- Identify domains that have DNSSEC signing enabled.
- Determine the number and percentage of DNSSEC-signed domains.
- Provide transparent and reproducible DNSSEC deployment statistics.
- Support research, monitoring, and awareness of DNSSEC adoption in Pakistan.
- Encourage wider DNSSEC deployment across the `.pk` domain namespace.

## Repository Structure

```text
.
├── dnssec_check.py
├── test_dnssec_check.py
└── pk-50k.txt
```

## Requirements

- Python 3.x
- Internet connectivity for DNS queries.
- `dnspython` Python library.

## Installation

**1. Clone the repository**

```bash
git clone https://github.com/eunomate/pkcctld.git
cd pkcctld
```

**2. Install the required Python dependency**

```bash
pip install dnspython
```

## Input File

The program accepts a plain-text (`.txt`) file containing a list of domains to check. You can use sample pk-50k.txt as input to verify

Each domain must be specified on a separate line.

Example: `domains.txt`

```text
example.pk
example.com.pk
example.org.pk
example.net.pk
example.edu.pk
```

You can provide any number of domains in the input file, subject to DNS query and network limitations.

## Execution

Run the program using Python:

```bash
python dnssec_check.py pk-50k.txt --out results.csv
```

Where:

- `results.csv` is the output file containing DNSSEC signing results.

## Output

The program generates a CSV file containing the DNSSEC signing check results for each domain.

Example:

| domain | status | ds | dnskey_alg |
|---|---|---|---|
| ecp.gov.pk | signed_no_ds | | 8 |
| newspak.pk | secure | 13/2 | 13 |
| pcb.gov.pk | unreachable | | |

The CSV output can be imported into Excel, LibreOffice, or other data-analysis tools to calculate DNSSEC adoption statistics.

## Understanding DNSSEC Results

- **secure:** Domain is signed, its DS is published in .pk, and the chain validates.
- **bogus:** DS is published in .pk, but validation fails.
- **signed_no_ds:** Domain owner has signed the zone, but ccTLD manager did not publish their DS.
- **ds_no_dnskey:** DS is published in .pk, but the domain serves no DNSKEY (broken).
- **unsigned:** The script did not detect any DNSSEC signing records.
- **nxdomain:** Domain doesn't exist in .pk.
- **unreachable:** Domain is registered, but its nameservers do not answer.
- **error:** No reply after retries; re-run or lower `-c`.

**Important:** DNSSEC chain of trust.

For a domain under `.pk` to validate successfully through the DNS hierarchy, the `.pk` parent zone must publish the corresponding DS record for the delegated child domain. The `.pk` zone itself must also have a valid chain of trust from the DNS root.

Therefore, DNSSEC signing and end-to-end DNSSEC validation are two distinct aspects and should be evaluated separately.

## DNSSEC Adoption Statistics

Once the CSV report is generated, the results can be used to calculate:

```text
DNSSEC Adoption (%) =
(Number of Signed Domains / Total Domains Checked) × 100
```

This provides an indicative measurement of DNSSEC deployment among the supplied `.pk` domains.

## Scope and Limitations

- The tool checks only the domains supplied in the input text file.
- It does not automatically discover all registered `.pk` domains.
- Results depend on DNS resolver responses and network availability.
- DNSSEC signing detection should not be interpreted as proof of successful end-to-end DNSSEC validation.
- Domains with DNS resolution failures or incomplete DNS responses may require additional investigation.

## Contributing

Contributions, suggestions, bug reports, and improvements are welcome.

If you identify an issue or would like to improve DNSSEC monitoring capabilities, please open a GitHub Issue or submit a Pull Request.

## License

Apache License 2.0

## Acknowledgements

This project aims to promote DNSSEC awareness, transparency, and measurement of DNSSEC adoption within Pakistan's Internet ecosystem.

It is intended as an open technical resource for the Internet community, DNS operators, researchers, and stakeholders interested in the security and resilience of the `.pk` ccTLD.

