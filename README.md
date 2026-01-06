# Linux Kernel Vulnerability Dataset

9,876 vulnerability-fixing commits with traceable bug-introducing commits, mined from Linux kernel git history.

## Dataset

`vuln_commits.csv` contains:
- `fixing_commit` - commit that fixed the bug
- `introducing_commit` - commit that introduced the bug  
- `fixing_date` / `introducing_date` - timestamps
- `subsystem` - kernel subsystem (networking, drivers, etc.)
- `files_changed`, `insertions`, `deletions`

## Key findings

- Average bug lifetime: **2.8 years**
- Networking bugs: **5.1 years** average
- Longest-lived bug: **19 years** (netfilter refcount leak)

## Scripts

- `cve_miner.py` - Extract Fixes: tags from kernel git history
- `extract_features.py` - Extract 51 features from commit diffs

## Blog post

[Networking bugs hide for 5 years—here's why](link-to-your-blog)

## Contact

jenny@pebblebed.com
