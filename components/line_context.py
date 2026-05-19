"""
Optional helper for fetching source-code context around an alert.

The main interview stimuli do not show code snippets by default. Participants compare
ranked alert lists using neutral alert metadata only (rank, file, line, rule, type,
message, effort). This helper is provided for optional backup context — it can fetch
surrounding code for selected alerts only if a participant cannot reason about an alert
without seeing the source.

Code context is NOT part of the main interview protocol.
"""

import base64
import logging
import os
import time

import requests

log = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"


class LineContextFetcher:
    def __init__(self, config: dict):
        """
        Initialize fetcher with GitHub repository configuration.
        
        Args:
            config: dictionary with structure {
                "github": {
                    "repo_owner": str,
                    "repo_name": str,
                    "branch": str
                }
            }
        """
        gh = config.get("github", {})
        self.repo_owner = gh.get("repo_owner", "")
        self.repo_name = gh.get("repo_name", "")
        self.branch = gh.get("branch", "master")
        self.token = os.getenv("GITHUB_TOKEN", "")
        self.session = requests.Session()
        if self.token:
            self.session.headers["Authorization"] = f"Bearer {self.token}"
        self.session.headers["Accept"] = "application/vnd.github.v3+json"
        
        # Per-session file content cache: {file_path: file_content}
        self._file_cache = {}

    def _check_rate_limit(self, resp: requests.Response) -> None:
        """Log warning if rate limit is low; sleep until reset if needed."""
        remaining = int(resp.headers.get("X-RateLimit-Remaining", 100))
        reset_time = int(resp.headers.get("X-RateLimit-Reset", 0))
        
        if remaining < 10 and reset_time > 0:
            sleep_seconds = max(0, reset_time - time.time())
            log.warning(f"GitHub API rate limit low ({remaining} remaining), sleeping {sleep_seconds:.1f}s")
            time.sleep(sleep_seconds + 1)

    def _fetch_file_content(self, file_path: str) -> str | None:
        """
        Fetch file content from GitHub at HEAD (specified branch).
        
        Args:
            file_path: relative path to file (e.g., "src/main/java/Foo.java")
            
        Returns:
            File content as string, or None if fetch failed
        """
        if file_path in self._file_cache:
            return self._file_cache[file_path]

        try:
            url = f"{GITHUB_API}/repos/{self.repo_owner}/{self.repo_name}/contents/{file_path}"
            params = {"ref": self.branch}
            resp = self.session.get(url, params=params, timeout=30)
            self._check_rate_limit(resp)
            
            if resp.status_code == 404:
                log.debug(f"File not found: {file_path}")
                return None
            
            resp.raise_for_status()
            data = resp.json()
            
            if "content" not in data:
                log.debug(f"No content in response for {file_path}")
                return None
            
            # GitHub returns base64-encoded content
            content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            self._file_cache[file_path] = content
            return content
            
        except requests.exceptions.Timeout:
            log.warning(f"Timeout fetching {file_path}")
            return None
        except Exception as e:
            log.warning(f"Error fetching {file_path}: {e}")
            return None

    def fetch_context(self, file_path: str, line: int, context_lines: int = 5) -> dict:
        """
        Fetch source lines around a flagged line from GitHub at HEAD.
        
        Args:
            file_path: relative path to file (e.g., "src/main/java/Foo.java")
            line: 1-indexed line number of the flagged line
            context_lines: number of lines before and after to fetch (default 5)
            
        Returns:
            {
                "file_path": str,
                "flagged_line": int,
                "start_line": int,         # flagged_line - context_lines, min 1
                "end_line": int,           # flagged_line + context_lines
                "lines": [                 # list of dicts, one per line
                    {
                        "line_number": int,
                        "content": str,
                        "is_flagged": bool  # True only for the alert's exact line
                    }
                ],
                "fetch_error": str | None  # populated if fetch failed, null otherwise
            }
        """
        result = {
            "file_path": file_path,
            "flagged_line": line,
            "start_line": max(1, line - context_lines),
            "end_line": line + context_lines,
            "lines": [],
            "fetch_error": None,
        }
        
        # Handle missing or invalid line number
        if line is None or not isinstance(line, int) or line < 1:
            result["fetch_error"] = f"Invalid line number: {line}"
            return result
        
        # Fetch file content
        content = self._fetch_file_content(file_path)
        if content is None:
            result["fetch_error"] = f"Failed to fetch {file_path} from GitHub"
            return result
        
        # Split into lines (1-indexed for readability)
        file_lines = content.splitlines()
        
        # Extract context window (clamp to file bounds)
        start = max(0, result["start_line"] - 1)  # Convert to 0-indexed
        end = min(len(file_lines), result["end_line"])  # end is exclusive
        
        for i in range(start, end):
            line_number = i + 1  # Convert back to 1-indexed
            result["lines"].append({
                "line_number": line_number,
                "content": file_lines[i],
                "is_flagged": (line_number == line),
            })
        
        if not result["lines"]:
            result["fetch_error"] = f"Line {line} not found in {file_path}"
        
        return result

    def fetch_context_batch(self, issues: list[dict]) -> dict[str, dict]:
        """
        Fetch context for a batch of issues.
        
        Args:
            issues: list of dicts with structure {
                "issue_key": str,
                "file_path": str,
                "line": int
            }
            
        Returns:
            Dictionary keyed by issue_key with context dicts (see fetch_context)
        """
        results = {}
        for issue in issues:
            issue_key = issue.get("issue_key", "")
            file_path = issue.get("file_path", "")
            line = issue.get("line")
            
            if not issue_key or not file_path:
                continue
            
            results[issue_key] = self.fetch_context(file_path, line)
        
        return results
