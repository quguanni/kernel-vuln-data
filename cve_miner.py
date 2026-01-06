"""
Linux Kernel CVE Commit Miner
Extracts introducing and fixing commits for vulnerabilities from git history.

Usage:
    python cve_miner.py /path/to/linux/repo

This script:
1. Finds commits with "Fixes:" tags
2. Extracts the introducing commit from the Fixes tag  
3. Identifies CVE references in commit messages
4. Outputs a dataset for ML training
"""

import subprocess
import re
import json
import os
import sys
from dataclasses import dataclass, asdict
from typing import Optional, List
from datetime import datetime

@dataclass
class VulnCommit:
    """Represents a vulnerability-related commit pair"""
    fixing_commit: str
    introducing_commit: str
    cve_id: Optional[str]
    subsystem: str
    fixing_date: str
    introducing_date: str
    fix_subject: str
    files_changed: List[str]
    insertions: int
    deletions: int

def run_git(repo_path: str, args: List[str]) -> str:
    """Run a git command and return output"""
    cmd = ["git", "-C", repo_path] + args
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

def extract_fixes_tag(commit_msg: str) -> Optional[str]:
    """Extract the commit ID from a Fixes: tag"""
    # Pattern: Fixes: <12+ char hex> ("subject line")
    pattern = r'Fixes:\s*([a-f0-9]{12,40})'
    match = re.search(pattern, commit_msg, re.IGNORECASE)
    if match:
        return match.group(1)
    return None

def extract_cve(commit_msg: str) -> Optional[str]:
    """Extract CVE ID from commit message"""
    pattern = r'CVE-\d{4}-\d{4,7}'
    match = re.search(pattern, commit_msg, re.IGNORECASE)
    if match:
        return match.group(0).upper()
    return None

def get_commit_date(repo_path: str, commit_hash: str) -> str:
    """Get the date of a commit"""
    output = run_git(repo_path, ["show", "-s", "--format=%ci", commit_hash])
    return output.strip()

def get_commit_subject(repo_path: str, commit_hash: str) -> str:
    """Get the subject line of a commit"""
    output = run_git(repo_path, ["show", "-s", "--format=%s", commit_hash])
    return output.strip()

def get_commit_stats(repo_path: str, commit_hash: str) -> tuple:
    """Get files changed, insertions, deletions"""
    output = run_git(repo_path, ["show", "--stat", "--format=", commit_hash])
    
    files = []
    insertions = 0
    deletions = 0
    
    for line in output.strip().split('\n'):
        if '|' in line:
            # File line: " path/to/file | 5 ++-"
            file_part = line.split('|')[0].strip()
            if file_part:
                files.append(file_part)
        elif 'insertions' in line or 'deletions' in line:
            # Summary line
            ins_match = re.search(r'(\d+) insertions?', line)
            del_match = re.search(r'(\d+) deletions?', line)
            if ins_match:
                insertions = int(ins_match.group(1))
            if del_match:
                deletions = int(del_match.group(1))
    
    return files, insertions, deletions

def get_subsystem(files: List[str]) -> str:
    """Determine subsystem from files changed"""
    if not files:
        return "unknown"
    
    # Priority mapping
    subsystem_patterns = [
        (r'^net/netfilter/', 'netfilter'),
        (r'^net/', 'networking'),
        (r'^drivers/gpu/', 'gpu'),
        (r'^drivers/usb/', 'usb'),
        (r'^drivers/nvme/', 'nvme'),
        (r'^drivers/', 'drivers'),
        (r'^fs/', 'filesystem'),
        (r'^mm/', 'memory'),
        (r'^kernel/', 'kernel'),
        (r'^security/', 'security'),
        (r'^crypto/', 'crypto'),
        (r'^io_uring/', 'io_uring'),
        (r'^block/', 'block'),
        (r'^sound/', 'sound'),
        (r'^arch/', 'arch'),
    ]
    
    for f in files:
        for pattern, subsystem in subsystem_patterns:
            if re.match(pattern, f):
                return subsystem
    
    return "other"

def find_fixing_commits(repo_path: str, since: str = "2020-01-01", limit: int = 10000) -> List[VulnCommit]:
    """Find all commits with Fixes: tags since a given date"""
    
    # Get commits with Fixes: in their message
    output = run_git(repo_path, [
        "log",
        f"--since={since}",
        "--grep=Fixes:",
        "--format=%H",
        f"-{limit}"
    ])
    
    fixing_commits = output.strip().split('\n')
    fixing_commits = [c for c in fixing_commits if c]  # Remove empty
    
    print(f"Found {len(fixing_commits)} commits with Fixes: tags")
    
    results = []
    
    for i, fix_hash in enumerate(fixing_commits):
        if i % 100 == 0:
            print(f"Processing {i}/{len(fixing_commits)}...")
        
        # Get full commit message
        msg = run_git(repo_path, ["show", "-s", "--format=%B", fix_hash])
        
        # Extract the introducing commit
        intro_hash = extract_fixes_tag(msg)
        if not intro_hash:
            continue
        
        # Verify introducing commit exists
        verify = run_git(repo_path, ["cat-file", "-t", intro_hash])
        if "commit" not in verify:
            continue
        
        # Get metadata
        cve_id = extract_cve(msg)
        files, ins, dels = get_commit_stats(repo_path, fix_hash)
        subsystem = get_subsystem(files)
        
        vuln = VulnCommit(
            fixing_commit=fix_hash[:12],
            introducing_commit=intro_hash[:12],
            cve_id=cve_id,
            subsystem=subsystem,
            fixing_date=get_commit_date(repo_path, fix_hash),
            introducing_date=get_commit_date(repo_path, intro_hash),
            fix_subject=get_commit_subject(repo_path, fix_hash),
            files_changed=files[:10],  # Limit to first 10 files
            insertions=ins,
            deletions=dels
        )
        
        results.append(vuln)
    
    return results

def export_to_json(results: List[VulnCommit], output_path: str):
    """Export results to JSON"""
    data = [asdict(r) for r in results]
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Exported {len(results)} records to {output_path}")

def export_to_csv(results: List[VulnCommit], output_path: str):
    """Export results to CSV"""
    import csv
    
    if not results:
        return
    
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        # Header
        writer.writerow([
            'fixing_commit', 'introducing_commit', 'cve_id', 'subsystem',
            'fixing_date', 'introducing_date', 'fix_subject', 
            'files_changed', 'insertions', 'deletions'
        ])
        
        for r in results:
            writer.writerow([
                r.fixing_commit,
                r.introducing_commit,
                r.cve_id or '',
                r.subsystem,
                r.fixing_date,
                r.introducing_date,
                r.fix_subject,
                ';'.join(r.files_changed),
                r.insertions,
                r.deletions
            ])
    
    print(f"Exported {len(results)} records to {output_path}")

def get_hot_subsystems(repo_path: str, since: str = "2024-01-01") -> dict:
    """Find which subsystems have the most commits recently"""
    
    output = run_git(repo_path, [
        "log",
        f"--since={since}",
        "--format=",
        "--name-only"
    ])
    
    subsystem_counts = {}
    
    for line in output.split('\n'):
        line = line.strip()
        if not line:
            continue
        
        # Get top-level directory
        parts = line.split('/')
        if len(parts) >= 2:
            subsystem = f"{parts[0]}/{parts[1]}"
        else:
            subsystem = parts[0]
        
        subsystem_counts[subsystem] = subsystem_counts.get(subsystem, 0) + 1
    
    # Sort by count
    sorted_subsystems = sorted(subsystem_counts.items(), key=lambda x: -x[1])
    
    return dict(sorted_subsystems[:30])

def main():
    if len(sys.argv) < 2:
        print("Usage: python cve_miner.py /path/to/linux/repo [since_date]")
        print("Example: python cve_miner.py ~/linux 2022-01-01")
        sys.exit(1)
    
    repo_path = sys.argv[1]
    since = sys.argv[2] if len(sys.argv) > 2 else "2022-01-01"
    
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        print(f"Error: {repo_path} is not a git repository")
        sys.exit(1)
    
    print(f"Mining CVE commits from {repo_path} since {since}")
    print("-" * 50)
    
    # Find hot subsystems first
    print("\n=== Hot Subsystems (most commits in 2024) ===")
    hot = get_hot_subsystems(repo_path, "2024-01-01")
    for subsystem, count in list(hot.items())[:15]:
        print(f"  {subsystem}: {count} commits")
    
    print("\n=== Mining Fixes: tags ===")
    results = find_fixing_commits(repo_path, since=since)
    
    # Export
    export_to_json(results, "vuln_commits.json")
    export_to_csv(results, "vuln_commits.csv")
    
    # Summary statistics
    print("\n=== Summary ===")
    print(f"Total vulnerability-fixing commits: {len(results)}")
    
    with_cve = [r for r in results if r.cve_id]
    print(f"Commits with CVE IDs: {len(with_cve)}")
    
    subsystem_counts = {}
    for r in results:
        subsystem_counts[r.subsystem] = subsystem_counts.get(r.subsystem, 0) + 1
    
    print("\nBy subsystem:")
    for sub, count in sorted(subsystem_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"  {sub}: {count}")

if __name__ == "__main__":
    main()
