#!/usr/bin/env python3
"""
Extract features from git commits for ML training.

Features include:
- Basic: lines added/removed, files changed
- Code patterns: goto, null checks, locks, refcounts, memory ops
- Semantic: pointer after loop, unbalanced operations, error paths
- Structural: cyclomatic complexity, nesting depth, function calls
- Historical: author bug rate, file bug rate, file age
"""
import subprocess
import re
from datetime import datetime
from functools import lru_cache


def get_diff(repo_path, commit_hash):
    """Get the diff for a commit"""
    try:
        result = subprocess.run(
            ["git", "-C", repo_path, "show", "--format=", "-p", commit_hash],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout
    except Exception:
        return ""


def get_commit_metadata(repo_path, commit_hash):
    """Get commit author, date, and files changed"""
    try:
        result = subprocess.run(
            ["git", "-C", repo_path, "show", "-s",
             "--format=%ae|%ad|%H", "--date=iso", commit_hash],
            capture_output=True, text=True, timeout=10
        )
        parts = result.stdout.strip().split("|")
        if len(parts) >= 3:
            return {
                "author_email": parts[0],
                "date": parts[1],
                "hash": parts[2]
            }
    except Exception:
        pass
    return {"author_email": "", "date": "", "hash": ""}


def get_files_in_commit(repo_path, commit_hash):
    """Get list of files changed in commit"""
    try:
        result = subprocess.run(
            ["git", "-C", repo_path, "show", "--name-only", "--format=", commit_hash],
            capture_output=True, text=True, timeout=10
        )
        return [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
    except Exception:
        return []


# ============================================================================
# BASIC FEATURES
# ============================================================================

def extract_basic_features(diff_text):
    """Extract basic size/count features"""
    added_lines = re.findall(r'^\+[^+].*', diff_text, re.MULTILINE)
    removed_lines = re.findall(r'^-[^-].*', diff_text, re.MULTILINE)

    return {
        'lines_added': len(added_lines),
        'lines_removed': len(removed_lines),
        'files_changed': len(re.findall(r'^diff --git', diff_text, re.MULTILINE)),
        'hunks_count': len(re.findall(r'^@@', diff_text, re.MULTILINE)),
    }


# ============================================================================
# CODE PATTERN FEATURES
# ============================================================================

def extract_pattern_features(diff_text):
    """Extract code pattern features from added lines"""
    added = '\n'.join(re.findall(r'^\+[^+].*', diff_text, re.MULTILINE))
    removed = '\n'.join(re.findall(r'^-[^-].*', diff_text, re.MULTILINE))

    features = {
        # Memory operations
        'has_kmalloc': 1 if re.search(r'k[mz]alloc\s*\(', added) else 0,
        'has_kfree': 1 if 'kfree(' in added else 0,
        'has_alloc_no_free': 1 if (re.search(r'k[mz]alloc\s*\(', added) and 'kfree(' not in added) else 0,

        # Refcount operations
        'has_get': 1 if re.search(r'_get\s*\(', added) else 0,
        'has_put': 1 if re.search(r'_put\s*\(', added) else 0,
        'get_count': len(re.findall(r'_get\s*\(', added)),
        'put_count': len(re.findall(r'_put\s*\(', added)),
        'unbalanced_refcount': 1 if abs(len(re.findall(r'_get\s*\(', added)) -
                                        len(re.findall(r'_put\s*\(', added))) > 0 else 0,

        # Locking
        'has_lock': 1 if re.search(r'spin_lock|mutex_lock|rcu_read_lock|down_read|down_write', added) else 0,
        'has_unlock': 1 if re.search(r'spin_unlock|mutex_unlock|rcu_read_unlock|up_read|up_write', added) else 0,
        'lock_count': len(re.findall(r'spin_lock|mutex_lock|rcu_read_lock|down_read|down_write', added)),
        'unlock_count': len(re.findall(r'spin_unlock|mutex_unlock|rcu_read_unlock|up_read|up_write', added)),
        'unbalanced_lock': 1 if abs(len(re.findall(r'spin_lock|mutex_lock', added)) -
                                    len(re.findall(r'spin_unlock|mutex_unlock', added))) > 0 else 0,

        # Pointer operations
        'has_deref': 1 if '->' in added else 0,
        'deref_count': added.count('->'),
        'has_null_check': 1 if re.search(r'if\s*\([^)]*==\s*NULL|if\s*\(\s*!\s*\w+\s*\)', added) else 0,
        'has_deref_no_null_check': 1 if ('->' in added and
                                          not re.search(r'if\s*\([^)]*==\s*NULL|if\s*\(\s*!\s*\w+\s*\)', added)) else 0,

        # Error handling
        'has_goto': 1 if 'goto ' in added else 0,
        'goto_count': len(re.findall(r'\bgoto\s+\w+', added)),
        'has_error_return': 1 if re.search(r'return\s+-E[A-Z]+', added) else 0,
        'has_error_label': 1 if re.search(r'^[+-]\s*(err|out|fail|error|cleanup):', diff_text, re.MULTILINE) else 0,
        'error_return_count': len(re.findall(r'return\s+-E[A-Z]+', added)),

        # Return without cleanup
        'has_early_return': 1 if re.search(r'return\s+[^;]+;(?!.*goto)', added) else 0,
    }

    return features


# ============================================================================
# SEMANTIC FEATURES (subtle bug patterns)
# ============================================================================

def extract_semantic_features(diff_text):
    """Extract semantic features to catch subtle bugs"""
    added = '\n'.join(re.findall(r'^\+[^+].*', diff_text, re.MULTILINE))

    features = {}

    # Pointer/variable used after loop (common bug pattern)
    # Look for: while/for loop, then same variable used after
    loop_vars = set()
    for match in re.finditer(r'(?:for|while)\s*\([^)]*\b(\w+)\b', added):
        loop_vars.add(match.group(1))

    # Check if loop variable used after loop ends
    features['var_after_loop'] = 0
    if loop_vars:
        # Simple heuristic: look for variable after closing brace
        lines = added.split('\n')
        in_loop = False
        brace_depth = 0
        for line in lines:
            if re.search(r'(?:for|while)\s*\(', line):
                in_loop = True
            if in_loop:
                brace_depth += line.count('{') - line.count('}')
                if brace_depth <= 0:
                    in_loop = False
            if not in_loop and brace_depth == 0:
                for var in loop_vars:
                    if re.search(rf'\b{var}\b', line):
                        features['var_after_loop'] = 1
                        break

    # Iterator modified inside loop (bug-prone pattern)
    features['iterator_modified_in_loop'] = 0
    for_loops = re.findall(r'for\s*\(\s*\w+\s*=\s*[^;]+;\s*(\w+)[^;]+;[^)]+\)\s*\{([^}]+)\}',
                           added, re.DOTALL)
    for iterator, body in for_loops:
        if re.search(rf'\b{iterator}\s*[+\-]=|\b{iterator}\s*=', body):
            features['iterator_modified_in_loop'] = 1
            break

    # List iteration without proper checks
    features['list_iteration'] = 1 if re.search(r'list_for_each|hlist_for_each', added) else 0
    features['list_del_in_loop'] = 1 if (re.search(r'list_for_each|hlist_for_each', added) and
                                          re.search(r'list_del|hlist_del', added)) else 0

    # Use of container_of (common source of bugs if used wrong)
    features['has_container_of'] = 1 if 'container_of(' in added else 0

    # Casting operations (potential type confusion)
    features['has_cast'] = 1 if re.search(r'\(\s*(?:struct\s+)?\w+\s*\*\s*\)', added) else 0
    features['cast_count'] = len(re.findall(r'\(\s*(?:struct\s+)?\w+\s*\*\s*\)', added))

    # sizeof without proper variable (common allocation bug)
    features['sizeof_type'] = 1 if re.search(r'sizeof\s*\(\s*struct\s+\w+\s*\)', added) else 0
    features['sizeof_ptr'] = 1 if re.search(r'sizeof\s*\(\s*\*\s*\w+\s*\)', added) else 0

    # Potential integer overflow patterns
    features['has_arithmetic'] = 1 if re.search(r'\+\s*\d+|\*\s*\d+', added) else 0
    features['has_shift'] = 1 if re.search(r'<<|>>', added) else 0

    # Copy operations (potential buffer overflow)
    features['has_copy'] = 1 if re.search(r'memcpy|strcpy|strncpy|copy_from_user|copy_to_user', added) else 0
    features['copy_count'] = len(re.findall(r'memcpy|strcpy|strncpy|copy_from_user|copy_to_user', added))

    return features


# ============================================================================
# STRUCTURAL FEATURES (complexity metrics)
# ============================================================================

def extract_structural_features(diff_text):
    """Extract code structure/complexity features"""
    added = '\n'.join(re.findall(r'^\+[^+].*', diff_text, re.MULTILINE))

    # Count conditionals (estimate cyclomatic complexity)
    if_count = len(re.findall(r'\bif\s*\(', added))
    else_count = len(re.findall(r'\belse\b', added))
    switch_count = len(re.findall(r'\bswitch\s*\(', added))
    case_count = len(re.findall(r'\bcase\s+', added))
    for_count = len(re.findall(r'\bfor\s*\(', added))
    while_count = len(re.findall(r'\bwhile\s*\(', added))
    ternary_count = len(re.findall(r'\?[^:]+:', added))

    # Estimate cyclomatic complexity (simplified)
    cyclomatic = 1 + if_count + switch_count + for_count + while_count + ternary_count

    # Nesting depth (count max brace depth in added code)
    max_depth = 0
    current_depth = 0
    for char in added:
        if char == '{':
            current_depth += 1
            max_depth = max(max_depth, current_depth)
        elif char == '}':
            current_depth = max(0, current_depth - 1)

    # Function calls
    func_calls = re.findall(r'\b([a-z_][a-z0-9_]*)\s*\(', added)

    # Lines per function (rough estimate)
    func_defs = len(re.findall(r'^[+-]\s*(?:static\s+)?(?:\w+\s+)+\w+\s*\([^)]*\)\s*\{',
                                diff_text, re.MULTILINE))

    features = {
        'if_count': if_count,
        'else_count': else_count,
        'switch_count': switch_count,
        'case_count': case_count,
        'loop_count': for_count + while_count,
        'ternary_count': ternary_count,
        'cyclomatic_complexity': cyclomatic,
        'max_nesting_depth': max_depth,
        'function_call_count': len(func_calls),
        'unique_functions_called': len(set(func_calls)),
        'function_definitions': func_defs,
    }

    return features


# ============================================================================
# HISTORICAL FEATURES (git history analysis)
# ============================================================================

class HistoricalFeatureExtractor:
    """Extract features from git history"""

    def __init__(self, repo_path, bug_commits=None):
        """
        Args:
            repo_path: Path to git repository
            bug_commits: Set of known bug-introducing commits for calculating rates
        """
        self.repo_path = repo_path
        self.bug_commits = bug_commits or set()
        self._author_commits_cache = {}
        self._file_commits_cache = {}

    @lru_cache(maxsize=10000)
    def get_author_history(self, author_email, before_date=None):
        """Get author's commit history"""
        try:
            cmd = ["git", "-C", self.repo_path, "log",
                   f"--author={author_email}", "--format=%H", "-n", "500"]
            if before_date:
                cmd.extend(["--before", before_date])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.stdout.strip().split("\n") if result.stdout.strip() else []
        except Exception:
            return []

    @lru_cache(maxsize=10000)
    def get_file_history(self, file_path, before_date=None):
        """Get file's commit history"""
        try:
            cmd = ["git", "-C", self.repo_path, "log",
                   "--format=%H|%ad", "--date=iso", "-n", "100", "--", file_path]
            if before_date:
                cmd.insert(4, f"--before={before_date}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            commits = []
            for line in result.stdout.strip().split("\n"):
                if "|" in line:
                    parts = line.split("|")
                    commits.append({"hash": parts[0], "date": parts[1]})
            return commits
        except Exception:
            return []

    def get_file_age_days(self, file_path, commit_date):
        """Get days since file was created"""
        try:
            result = subprocess.run(
                ["git", "-C", self.repo_path, "log", "--follow", "--format=%ad",
                 "--date=iso", "--diff-filter=A", "--", file_path],
                capture_output=True, text=True, timeout=30
            )
            if result.stdout.strip():
                first_date = result.stdout.strip().split("\n")[-1]
                d1 = datetime.fromisoformat(first_date.replace(" ", "T").split("+")[0])
                d2 = datetime.fromisoformat(commit_date.replace(" ", "T").split("+")[0])
                return (d2 - d1).days
        except Exception:
            pass
        return 0

    def get_days_since_last_change(self, file_path, commit_date):
        """Get days since file was last modified before this commit"""
        history = self.get_file_history(file_path, commit_date)
        if len(history) >= 2:
            try:
                prev_date = history[1]["date"]
                d1 = datetime.fromisoformat(prev_date.replace(" ", "T").split("+")[0])
                d2 = datetime.fromisoformat(commit_date.replace(" ", "T").split("+")[0])
                return (d2 - d1).days
            except Exception:
                pass
        return 0

    def extract_features(self, commit_hash, author_email, commit_date, files):
        """Extract all historical features for a commit"""
        features = {
            'author_total_commits': 0,
            'author_bug_commits': 0,
            'author_bug_rate': 0.0,
            'file_total_commits': 0,
            'file_bug_commits': 0,
            'file_bug_rate': 0.0,
            'file_age_days': 0,
            'days_since_last_change': 0,
            'files_avg_bug_rate': 0.0,
        }

        # Author history
        author_commits = self.get_author_history(author_email, commit_date)
        features['author_total_commits'] = len(author_commits)
        if author_commits:
            author_bugs = sum(1 for c in author_commits if c in self.bug_commits)
            features['author_bug_commits'] = author_bugs
            features['author_bug_rate'] = author_bugs / len(author_commits) if author_commits else 0

        # File history (aggregate over all files)
        total_file_commits = 0
        total_file_bugs = 0
        max_file_age = 0
        min_days_since_change = float('inf')

        for file_path in files[:5]:  # Limit to 5 files for performance
            file_history = self.get_file_history(file_path, commit_date)
            if file_history:
                total_file_commits += len(file_history)
                file_bugs = sum(1 for c in file_history if c["hash"] in self.bug_commits)
                total_file_bugs += file_bugs

                age = self.get_file_age_days(file_path, commit_date)
                max_file_age = max(max_file_age, age)

                days_since = self.get_days_since_last_change(file_path, commit_date)
                if days_since > 0:
                    min_days_since_change = min(min_days_since_change, days_since)

        features['file_total_commits'] = total_file_commits
        features['file_bug_commits'] = total_file_bugs
        features['file_bug_rate'] = total_file_bugs / total_file_commits if total_file_commits > 0 else 0
        features['file_age_days'] = max_file_age
        features['days_since_last_change'] = min_days_since_change if min_days_since_change != float('inf') else 0

        return features


# ============================================================================
# COMBINED FEATURE EXTRACTION
# ============================================================================

def extract_all_features(diff_text, repo_path=None, commit_hash=None,
                         historical_extractor=None):
    """
    Extract all features from a commit.

    Args:
        diff_text: The git diff text
        repo_path: Path to git repo (optional, for historical features)
        commit_hash: Commit hash (optional, for historical features)
        historical_extractor: HistoricalFeatureExtractor instance (optional)

    Returns:
        Dictionary of all features
    """
    features = {}

    # Basic features
    features.update(extract_basic_features(diff_text))

    # Pattern features
    features.update(extract_pattern_features(diff_text))

    # Semantic features
    features.update(extract_semantic_features(diff_text))

    # Structural features
    features.update(extract_structural_features(diff_text))

    # Historical features (if repo info provided)
    if repo_path and commit_hash and historical_extractor:
        metadata = get_commit_metadata(repo_path, commit_hash)
        files = get_files_in_commit(repo_path, commit_hash)
        hist_features = historical_extractor.extract_features(
            commit_hash,
            metadata.get("author_email", ""),
            metadata.get("date", ""),
            files
        )
        features.update(hist_features)

    return features


def get_feature_names(include_historical=True):
    """Return list of all feature names in order"""
    names = [
        # Basic
        'lines_added', 'lines_removed', 'files_changed', 'hunks_count',
        # Pattern - memory
        'has_kmalloc', 'has_kfree', 'has_alloc_no_free',
        # Pattern - refcount
        'has_get', 'has_put', 'get_count', 'put_count', 'unbalanced_refcount',
        # Pattern - locking
        'has_lock', 'has_unlock', 'lock_count', 'unlock_count', 'unbalanced_lock',
        # Pattern - pointers
        'has_deref', 'deref_count', 'has_null_check', 'has_deref_no_null_check',
        # Pattern - error handling
        'has_goto', 'goto_count', 'has_error_return', 'has_error_label',
        'error_return_count', 'has_early_return',
        # Semantic
        'var_after_loop', 'iterator_modified_in_loop', 'list_iteration',
        'list_del_in_loop', 'has_container_of', 'has_cast', 'cast_count',
        'sizeof_type', 'sizeof_ptr', 'has_arithmetic', 'has_shift',
        'has_copy', 'copy_count',
        # Structural
        'if_count', 'else_count', 'switch_count', 'case_count', 'loop_count',
        'ternary_count', 'cyclomatic_complexity', 'max_nesting_depth',
        'function_call_count', 'unique_functions_called', 'function_definitions',
    ]

    if include_historical:
        names.extend([
            # Historical
            'author_total_commits', 'author_bug_commits', 'author_bug_rate',
            'file_total_commits', 'file_bug_commits', 'file_bug_rate',
            'file_age_days', 'days_since_last_change', 'files_avg_bug_rate',
        ])

    return names


def features_to_vector(features_dict, include_historical=True):
    """Convert feature dictionary to ordered list for ML"""
    names = get_feature_names(include_historical)
    return [features_dict.get(name, 0) for name in names]


# ============================================================================
# MAIN / TESTING
# ============================================================================

if __name__ == "__main__":
    import sys

    repo = "/Users/jennyqu/linux"

    # Test on a specific commit if provided
    if len(sys.argv) > 1:
        commit = sys.argv[1]
    else:
        commit = "de788b2e6227"  # Known refcount leak fix

    print(f"Extracting features for commit: {commit}")
    print("=" * 60)

    diff = get_diff(repo, commit)
    if not diff:
        print("Could not get diff")
        sys.exit(1)

    # Extract all features
    features = extract_all_features(diff, repo, commit)

    # Print by category
    categories = {
        "Basic": ['lines_added', 'lines_removed', 'files_changed', 'hunks_count'],
        "Memory": ['has_kmalloc', 'has_kfree', 'has_alloc_no_free'],
        "Refcount": ['has_get', 'has_put', 'get_count', 'put_count', 'unbalanced_refcount'],
        "Locking": ['has_lock', 'has_unlock', 'lock_count', 'unlock_count', 'unbalanced_lock'],
        "Pointers": ['has_deref', 'deref_count', 'has_null_check', 'has_deref_no_null_check'],
        "Error Handling": ['has_goto', 'goto_count', 'has_error_return', 'has_error_label',
                          'error_return_count', 'has_early_return'],
        "Semantic": ['var_after_loop', 'iterator_modified_in_loop', 'list_iteration',
                    'list_del_in_loop', 'has_container_of', 'has_cast', 'cast_count'],
        "Complexity": ['cyclomatic_complexity', 'max_nesting_depth',
                      'function_call_count', 'unique_functions_called'],
    }

    for cat_name, cat_features in categories.items():
        print(f"\n{cat_name}:")
        for name in cat_features:
            val = features.get(name, 0)
            if val != 0:
                print(f"  {name}: {val}")

    print(f"\nTotal features: {len(features)}")
