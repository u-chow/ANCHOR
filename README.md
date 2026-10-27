# ANCHOR: Role-Preserving Artifact Normalization for Cross-Campaign Technique Hunting at Scale

![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-green)
![IEEE Big Data 2026](https://img.shields.io/badge/IEEE_Big_Data-2026-blue)
![Accepted](https://img.shields.io/badge/Status-Accepted-purple)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-yellow)](LICENSE)

Preprocessing implementation for **ANCHOR: Role-Preserving Artifact Normalization for Cross-Campaign Technique Hunting at Scale**, accepted at the **2026 IEEE International Conference on Big Data (IEEE Big Data 2026)**.

Yu-Chiao Cheng<sup>1</sup>, Wei-Ta Chen<sup>1</sup>, Ying-Ren Guo<sup>2</sup>, Yeali Sun<sup>3</sup>, and Meng Chang Chen<sup>2</sup>

<sup>1</sup>Department of Electrical Engineering, National Taiwan University, Taiwan  
<sup>2</sup>Research Center for Information Technology Innovation, Academia Sinica, Taiwan  
<sup>3</sup>Department of Information Management, National Taiwan University, Taiwan

[Overview](#overview) | [Method](#method) | [Quick start](#quick-start) | [Citation](#citation) | [License](#license)

The paper link and final proceedings metadata will be added when available.

## Overview

**ANCHOR** stands for **Artifact Normalization for Cross-Host Observable Roles**. It is a deterministic, auditable, and label-free preprocessing method for security artifacts. Rather than retaining every instance-specific value or masking all variable fields, ANCHOR reduces surface variation while preserving operational roles useful for security analysis.

- **Role-preserving:** retain directory roles, registry structure, network context, and command behavior.
- **Deterministic and auditable:** explicit rules produce inspectable representations without attack labels or generative models.
- **Model-independent:** normalized artifacts can be supplied to different encoders and downstream security models.

**Repository scope:** this release contains only the preprocessing method and a small synthetic example. Downstream encoders, anomaly detectors, technique hunters, model weights, datasets, and experiment scripts are not included. ANCHOR produces normalized text; it does not itself predict maliciousness or attack techniques.

## Method

ANCHOR takes an artifact value and its type, applies the corresponding normalization rules, and returns a structured text representation. The current implementation focuses on Windows-style security artifacts.

| Artifact type | Input | Representation captures | Module |
| --- | --- | --- | --- |
| `file` | Supported file path | Directory roles, file types, and selected name information | [file.py](file.py) |
| `registry` | Registry key | Hive aliases, path components, identifier tokens, and action categories | [registry.py](registry.py) |
| `network` | Network endpoint | Protocol, address scope and family, endpoint information, and port categories | [network.py](network.py) |
| `process` | Recorded command line | Executable identity, supported shell behaviors, and argument types | [process.py](process.py) |

[standardizer.py](standardizer.py) provides a shared Python interface to these modules. [preprocess.py](preprocess.py) applies the same interface to CSV records. Inputs are treated as text; recorded commands are not executed.

## Repository structure

```text
.
|-- examples/
|   `-- artifacts.csv       # Four synthetic artifacts, one per type
|-- file.py                # File path and file type normalization
|-- registry.py            # Registry key normalization
|-- network.py             # Network endpoint normalization
|-- process.py             # Process command line normalization
|-- standardizer.py        # Shared Python API
|-- preprocess.py          # CSV preprocessing entry point
|-- requirements.txt       # Python version and dependency notes
|-- LICENSE                # Apache License 2.0
|-- .gitignore
`-- README.md
```

## Installation

Use **Python 3.10 or newer**. The `standardize()` API and `preprocess.py` entry point use only the Python standard library: no package installation, GPU, model weights, or external service is required.

Download the repository, open a terminal in its root directory, and check the available options:

```bash
python --version
python preprocess.py --help
```

The examples below should also be run from the repository root. Use `preprocess.py` for CSV processing; the separate legacy CLI in `network.py` is not needed for this workflow.

## Quick start

### Batch preprocessing

Run the included synthetic example:

```bash
python preprocess.py --input examples/artifacts.csv --output outputs/normalized.csv
```

The command creates the output directory if needed, preserves every input column, and appends `normalized_artifact`. Use a new output path for each run: `preprocess.py` refuses to overwrite an existing file.

### Python API

Normalize individual artifacts with the shared interface:

```python
from standardizer import standardize

print(standardize(r"C:\Users\Example\Downloads\sample.exe", "file"))
print(standardize(r"HKCU\Software\Example\Run", "registry"))
print(standardize("192.0.2.10:443", "network"))
print(standardize("cmd.exe /c echo example", "process"))
```

Output for these examples:

```text
<USER_FOLDER>/<DOWNLOADS>/<EXECUTABLE_FILE>/<sample.exe>
<HKCU>/<SOFTWARE>/<EXAMPLE>/<RUN>/<APP_VENDOR>/<run>
<TCP>/<PUBLIC>/<IPV4>/<NONE>/<192.0.2.10>/<PORT_SYSTEM>/<PORT_00443>
<PROCESS>/<CMD.EXE>/<INLINE>/<CMD_ECHO>
```

To collect raw-to-normalized pairs for inspection, pass an optional list:

```python
from standardizer import standardize

mappings = []
normalized = standardize("cmd.exe /c echo example", "process", mapping_collector=mappings)
print(mappings)
```

The default process profile returns structured tokens. For recognized `cmd.exe` inputs, the optional `process_profile="cmdcaliper"` preserves more command text while replacing recognized paths, URLs, and IPv4 addresses. This is a text-processing option only; it does not load the CmdCaliper model. Other process types follow the default rules. The CSV entry point uses the default profile.

## Input format

Provide a UTF-8 CSV containing `artifact_type` and `raw_artifact`. Additional columns, such as event identifiers, are preserved.

```csv
id,artifact_type,raw_artifact
1,file,C:\Users\Example\Downloads\sample.exe
2,registry,HKCU\Software\Example\Run
3,network,192.0.2.10:443
4,process,cmd.exe /c echo example
```

Supported artifact types are `file`, `registry`, `network`, and `process`. Quote CSV fields containing commas, quotes, or line breaks. Input must not already contain a `normalized_artifact` column or duplicate column names.

The entry point expects extracted artifact fields, not arbitrary raw log formats. Adapt your log schema to these columns before preprocessing. If a malformed record stops a run, the output may contain the header and previously completed records; check the command's exit status before using the result.

## Release notes

- **Not anonymization:** normalized outputs may retain file names, registry terminal names, addresses, domains, or command arguments. CSV output also retains the raw input. Review both before sharing.
- **Rule coverage:** normalization is based on explicit patterns, not a complete shell parser or a guarantee that every artifact is recognized.
- **Repository scope:** This repository provides ANCHOR's preprocessing implementation. Downstream experiment code, datasets, and model checkpoints are not included.

## Citation

If ANCHOR is useful for your research, please cite our accepted IEEE Big Data 2026 paper:

```bibtex
@inproceedings{cheng2026anchor,
  author    = {Yu-Chiao Cheng and Wei-Ta Chen and Ying-Ren Guo and Yeali Sun and Meng Chang Chen},
  title     = {{ANCHOR}: Role-Preserving Artifact Normalization for Cross-Campaign Technique Hunting at Scale},
  booktitle = {2026 IEEE International Conference on Big Data (Big Data)},
  year      = {2026},
  note      = {Accepted for publication}
}
```

The DOI, page numbers, and proceedings link will be added when assigned.

## License

The original ANCHOR source code is released under the **Apache License 2.0**; see [LICENSE](LICENSE). Third-party materials, if used separately, remain subject to their respective license terms. This source-code license does not cover the paper or external datasets and model checkpoints.
