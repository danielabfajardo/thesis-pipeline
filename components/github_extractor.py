"""
Extracts file-level churn and contributor metrics via the GitHub REST API.

Input:  Project config, results/{project_id}/sonarqube_issues.csv (for file list)
Output: results/{project_id}/churn_metrics.csv

Design decisions:
- GitHub API over local clone: avoids data exposure for proprietary repositories
- Bus factor = minimum authors covering >=50% of commits (Yamashita 2015)
- All metrics scoped to time_period window for temporal consistency with SonarQube snapshot
"""

import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import requests

log = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"


class GitHubExtractor:
    def __init__(self, config: dict, results_path: Path):
        self.config = config
        self.results_path = results_path
        gh = config.get("github", {})
        self.owner = gh.get("repo_owner", "")
        self.repo = gh.get("repo_name", "")
        self.branch = gh.get("branch", "master")
        tp = config.get("time_period", {})
        self.start_date = tp.get("start_date", "")
        self.end_date = tp.get("end_date", "")
        self.token = os.getenv("GITHUB_TOKEN", "")
        self.session = requests.Session()
        if self.token:
            self.session.headers["Authorization"] = f"token {self.token}"
        self.session.headers["Accept"] = "application/vnd.github.v3+json"

    def _get(self, path: str, params: dict = None) -> requests.Response:
        url = f"{GITHUB_API}{path}"
        resp = self.session.get(url, params=params, timeout=30)
        self._check_rate_limit(resp)
        return resp

    def _check_rate_limit(self, resp: requests.Response) -> None:
        remaining = int(resp.headers.get("X-RateLimit-Remaining", 100))
        if remaining < 10:
            reset_ts = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
            sleep_secs = max(reset_ts - int(time.time()), 1)
            log.warning(f"GitHub rate limit low ({remaining} remaining). Sleeping {sleep_secs}s...")
            time.sleep(sleep_secs)

    def _fetch_commits_for_file(self, file_path: str, since: str = None, until: str = None) -> list[dict]:
        params = {"path": file_path, "sha": self.branch, "per_page": 100}
        if since:
            params["since"] = since + "T00:00:00Z"
        if until:
            params["until"] = until + "T00:00:00Z"

        commits = []
        page = 1
        while True:
            params["page"] = page
            resp = self._get(f"/repos/{self.owner}/{self.repo}/commits", params)
            if resp.status_code == 404:
                return []
            if resp.status_code != 200:
                log.warning(f"GitHub API {resp.status_code} for {file_path}: {resp.text[:200]}")
                return []
            batch = resp.json()
            if not batch:
                break
            commits.extend(batch)
            if len(batch) < 100:
                break
            page += 1

        return commits

    def _compute_bus_factor(self, author_commit_counts: dict) -> int:
        total = sum(author_commit_counts.values())
        if total == 0:
            return 0
        sorted_counts = sorted(author_commit_counts.values(), reverse=True)
        cumulative = 0
        for i, count in enumerate(sorted_counts):
            cumulative += count
            if cumulative / total >= 0.5:
                return i + 1
        return len(sorted_counts)

    def _compute_churn_for_file(self, file_path: str) -> dict:
        commits = self._fetch_commits_for_file(file_path, self.start_date, self.end_date)

        if not commits:
            log.warning(f"No commits found for {file_path} in window — recording zeros")
            return self._zero_row(file_path)

        author_counts: dict[str, int] = {}
        lines_added = 0
        lines_deleted = 0
        dates = []

        for c in commits:
            sha = c.get("sha", "")
            author = (c.get("commit", {}).get("author", {}).get("email") or
                      c.get("author", {}).get("login") or "unknown")
            author_counts[author] = author_counts.get(author, 0) + 1

            date_str = c.get("commit", {}).get("author", {}).get("date", "")
            if date_str:
                dates.append(date_str)

            detail_resp = self._get(f"/repos/{self.owner}/{self.repo}/commits/{sha}")
            if detail_resp.status_code == 200:
                detail = detail_resp.json()
                for f in detail.get("files", []):
                    if f.get("filename") == file_path:
                        lines_added += f.get("additions", 0)
                        lines_deleted += f.get("deletions", 0)

        end_dt = datetime.strptime(self.end_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)

        last_modified_date = ""
        days_since_modified = 0
        if dates:
            dates.sort(reverse=True)
            last_modified_date = dates[0]
            try:
                last_dt = datetime.fromisoformat(last_modified_date.replace("Z", "+00:00"))
                days_since_modified = (end_dt - last_dt).days
            except Exception:
                days_since_modified = 0

        first_commits = self._fetch_commits_for_file(file_path)
        file_age_days = 0
        if first_commits:
            oldest = sorted(first_commits, key=lambda c: c.get("commit", {}).get("author", {}).get("date", ""))
            first_date_str = oldest[0].get("commit", {}).get("author", {}).get("date", "")
            if first_date_str:
                try:
                    first_dt = datetime.fromisoformat(first_date_str.replace("Z", "+00:00"))
                    file_age_days = (end_dt - first_dt).days
                except Exception:
                    file_age_days = 0

        return {
            "file_path": file_path,
            "commit_count": len(commits),
            "unique_authors": len(author_counts),
            "bus_factor": self._compute_bus_factor(author_counts),
            "lines_added": lines_added,
            "lines_deleted": lines_deleted,
            "churn": lines_added + lines_deleted,
            "last_modified_date": last_modified_date,
            "days_since_modified": days_since_modified,
            "file_age_days": file_age_days,
        }

    def _zero_row(self, file_path: str) -> dict:
        return {
            "file_path": file_path,
            "commit_count": 0,
            "unique_authors": 0,
            "bus_factor": 0,
            "lines_added": 0,
            "lines_deleted": 0,
            "churn": 0,
            "last_modified_date": "",
            "days_since_modified": 0,
            "file_age_days": 0,
        }

    def run(self) -> None:
        issues_path = self.results_path / "sonarqube_issues.csv"
        if not issues_path.exists():
            raise FileNotFoundError("sonarqube_issues.csv must exist before running GitHub extractor")

        issues = pd.read_csv(issues_path)
        file_paths = issues["file_path"].dropna().unique().tolist()
        log.info(f"GitHub extractor: processing {len(file_paths)} unique files")

        rows = []
        for i, fp in enumerate(file_paths, 1):
            log.info(f"  [{i}/{len(file_paths)}] {fp}")
            try:
                row = self._compute_churn_for_file(fp)
            except Exception as e:
                log.warning(f"Error processing {fp}: {e}")
                row = self._zero_row(fp)
            rows.append(row)

        df = pd.DataFrame(rows)
        out_path = self.results_path / "churn_metrics.csv"
        df.to_csv(out_path, index=False)
        log.info(f"churn_metrics.csv written: {len(df)} rows")
