# Linux Kernel Vulnerability Dataset

**125,183 bug-fix pairs** mined from 20 years of Linux kernel git history (2005-2025).

## Dataset

`vuln_commits_full.csv` contains:

| Column | Description |
|--------|-------------|
| `fixing_commit` | SHA of the commit that fixed the bug |
| `introducing_commit` | SHA of the commit that introduced the bug |
| `lifetime_days` | Days between introduction and fix |
| `subsystem` | Kernel subsystem (networking, drivers, gpu, etc.) |
| `bug_type` | Detected bug type (use-after-free, null-deref, etc.) |
| `fixing_date` / `introducing_date` | Timestamps |
| `fix_author` / `intro_author` | Who wrote each commit |
| `files_changed`, `insertions`, `deletions` | Diff stats |
| `cve_id` | CVE ID if mentioned (nullable) |
| `cc_stable` | Whether fix was tagged for stable backport |

## Key Findings

| Metric | Value |
|--------|-------|
| Total bug-fix pairs | **125,183** |
| Average bug lifetime | **2.1 years** |
| Median bug lifetime | **0.7 years** |
| Longest-lived bug | **20.7 years** (ethtool buffer overflow) |
| Bugs hiding 5+ years | **13.5%** |

### By Subsystem

| Subsystem | Avg Lifetime |
|-----------|--------------|
| CAN bus | 4.2 years |
| SCTP | 4.0 years |
| IPv4 | 3.6 years |
| USB | 3.5 years |
| Netfilter | 2.9 years |
| GPU | 1.4 years |
| BPF | 1.1 years |

### By Bug Type

| Bug Type | Avg Lifetime |
|----------|--------------|
| Race condition | 5.1 years |
| Integer overflow | 3.9 years |
| Use-after-free | 3.2 years |
| Memory leak | 3.1 years |
| Null dereference | 2.2 years |

## Scripts

- `cve_miner.py` - Extract `Fixes:` tags from kernel git history
- `extract_features.py` - Extract 51 features from commit diffs for ML training

## Usage

```python
import pandas as pd

df = pd.read_csv('vuln_commits_full.csv')

# Average lifetime by subsystem
df.groupby('subsystem')['lifetime_days'].mean().sort_values(ascending=False)

# Bug type distribution
df['bug_type'].value_counts()
```

## HuggingFace

This dataset is also available on HuggingFace with a Data Studio viewer:

🤗 [huggingface.co/datasets/quguanni/kernel-vuln-dataset](https://huggingface.co/datasets/quguanni/kernel-vuln-dataset)

## Blog Post

[Kernel bugs hide for 2 years on average. Some hide for 20.](https://pebblebed.com/blog/kernel-bugs)

## Citation

```bibtex
@dataset{qu2026kernelvuln,
  author = {Qu, Jenny Guanni},
  title = {Linux Kernel Vulnerability Dataset},
  year = {2026},
  url = {https://github.com/quguanni/kernel-vuln-data}
}
```

## License

MIT

## Contact

Jenny Guanni Qu - jenny@pebblebed.com
