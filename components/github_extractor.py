import json
import logging
import os
import time
from datetime import datetime, timezone, timedelta
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
        
        # Calculate churn window independently from SonarQube/SATD time_period
        churn_lookback_days = gh.get("churn_lookback_days", 365)
        today = datetime.now(timezone.utc).date()
        lookback_date = today - timedelta(days=churn_lookback_days)
        
        self.start_date = lookback_date.isoformat()  # e.g., "2025-05-09"
        self.end_date = today.isoformat()            # e.g., "2026-05-09"
        
        log.info(f"GitHub churn window: {self.start_date} → {self.end_date} ({churn_lookback_days} days lookback)")
        
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

    def _fetch_commits_for_file(self, file_path: str, since: str = None, until: str = None, max_pages: int = None) -> list[dict]:
        """Fetch commits for a file, optionally limited by page count.
        
        Args:
            file_path: Path to the file
            since: Start date for commits (YYYY-MM-DD format)
            until: End date for commits (YYYY-MM-DD format)
            max_pages: Maximum number of pages to fetch (None = unlimited). Each page is 100 commits.
        """
        params = {"path": file_path, "sha": self.branch, "per_page": 100}
        if since:
            params["since"] = since + "T00:00:00Z"
        if until:
            params["until"] = until + "T00:00:00Z"

        commits = []
        page = 1
        while True:
            if max_pages and page > max_pages:
                log.warning(f"Hit pagination cap ({max_pages} pages, ~{len(commits)} commits) for {file_path}")
                break
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

    def _compute_churn_for_file(self, file_path: str) -> dict:
        """Compute development activity for a file over the lookback window."""
        commits = self._fetch_commits_for_file(file_path, self.start_date, self.end_date)

        if not commits:
            log.info(f"No commit activity available for {file_path} in window")
            return self._unknown_activity_row(file_path)

        authors: set[str] = set()
        churn = 0
        dates = []

        for c in commits:
            sha = c.get("sha", "")
            author = (c.get("commit", {}).get("author", {}).get("email") or
                      c.get("author", {}).get("login") or "unknown")
            authors.add(author)

            date_str = c.get("commit", {}).get("author", {}).get("date", "")
            if date_str:
                dates.append(date_str)

            # The detail call is the only source of additions/deletions per file.
            # We accumulate added+deleted directly into churn without storing them
            # as separate output columns.
            detail_resp = self._get(f"/repos/{self.owner}/{self.repo}/commits/{sha}")
            if detail_resp.status_code == 200:
                detail = detail_resp.json()
                for f in detail.get("files", []):
                    if f.get("filename") == file_path:
                        churn += f.get("additions", 0) + f.get("deletions", 0)

        end_dt = (
            datetime.strptime(self.end_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if self.end_date else datetime.now(timezone.utc)
        )

        days_since_modified = None
        if dates:
            dates.sort(reverse=True)
            try:
                last_dt = datetime.fromisoformat(dates[0].replace("Z", "+00:00"))
                days_since_modified = (end_dt - last_dt).days
            except Exception as e:
                log.warning(f"Could not parse last commit date for {file_path}: {e}")

        return {
            "file_path": file_path,
            "commit_count": len(commits),
            "unique_authors": len(authors),
            "churn": churn,
            "days_since_modified": days_since_modified,
        }

    def _unknown_activity_row(self, file_path: str) -> dict:
        """Return row with null values when activity data is unavailable."""
        return {
            "file_path": file_path,
            "commit_count": None,
            "unique_authors": None,
            "churn": None,
            "days_since_modified": None,
        }

    def run(self) -> None:
        # Log extraction metadata
        extraction_datetime = datetime.now(timezone.utc).isoformat()
        log.info(f"GitHub extraction started: {extraction_datetime} UTC")
        
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
                log.warning(f"Error computing churn for {fp}: {e}")
                row = self._unknown_activity_row(fp)
            rows.append(row)

        df = pd.DataFrame(rows)
        out_path = self.results_path / "churn_metrics.csv"
        df.to_csv(out_path, index=False)
        log.info(f"churn_metrics.csv written: {len(df)} rows")

        # Write extraction metadata (overwrite — no merge with prior runs)
        metadata = {
            "github_extraction_date": extraction_datetime,
            "churn_window_start": self.start_date,
            "churn_window_end": self.end_date,
        }
        metadata_path = self.results_path / "extraction_metadata.json"
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
        log.info(f"extraction_metadata.json written")
