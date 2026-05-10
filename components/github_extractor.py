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
GRAPHQL_API = "https://api.github.com/graphql"

_BLAME_QUERY = """
query GetBlame($owner: String!, $name: String!, $path: String!, $ref: String!) {
  repository(owner: $owner, name: $name) {
    object(expression: $ref) {
      ... on Commit {
        blame(path: $path) {
          ranges {
            startingLine
            endingLine
            commit {
              oid
              committedDate
              author { name }
            }
          }
        }
      }
    }
  }
}
"""


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
                log.warning(f"Hit pagination cap ({max_pages} pages, ~{len(commits)} commits) for {file_path} — file_age_days may be a lower bound")
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

        end_dt = (
            datetime.strptime(self.end_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if self.end_date else datetime.now(timezone.utc)
        )

        last_modified_date = ""
        days_since_modified = 0
        last_dt = None
        if dates:
            dates.sort(reverse=True)
            last_modified_date = dates[0]
            try:
                last_dt = datetime.fromisoformat(last_modified_date.replace("Z", "+00:00"))
                days_since_modified = (end_dt - last_dt).days
            except Exception:
                days_since_modified = 0

        first_commits = self._fetch_commits_for_file(file_path, max_pages=5)
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

    def _fetch_blame_ranges(self, file_path: str) -> list[dict]:
        """Fetch git blame ranges via GitHub GraphQL API.
        Returns list of {startingLine, endingLine, oid, committedDate, authorName}."""
        if not self.token:
            return []
        payload = {
            "query": _BLAME_QUERY,
            "variables": {
                "owner": self.owner,
                "name": self.repo,
                "path": file_path,
                "ref": self.branch,
            },
        }
        resp = self.session.post(GRAPHQL_API, json=payload, timeout=30)
        self._check_rate_limit(resp)

        if resp.status_code != 200:
            log.warning(f"GraphQL blame {resp.status_code} for {file_path}")
            return []

        data = resp.json()
        if "errors" in data:
            log.warning(f"GraphQL errors for {file_path}: {data['errors'][:1]}")
            return []

        try:
            ranges = data["data"]["repository"]["object"]["blame"]["ranges"]
        except (KeyError, TypeError):
            log.warning(f"Unexpected GraphQL blame structure for {file_path}")
            return []

        result = []
        for r in ranges:
            commit = r.get("commit", {})
            author = commit.get("author") or {}
            result.append({
                "startingLine": r["startingLine"],
                "endingLine": r["endingLine"],
                "oid": commit.get("oid", ""),
                "committedDate": commit.get("committedDate", ""),
                "authorName": author.get("name", ""),
            })
        return result

    def _compute_alert_churn(self, issues_df: pd.DataFrame) -> pd.DataFrame:
        """Map each issue to its line's blame entry: days since line last modified, author, commit SHA."""
        end_dt = (
            datetime.strptime(self.end_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if self.end_date else datetime.now(timezone.utc)
        )

        blame_cache: dict[str, list[dict]] = {}
        rows = []

        for _, issue in issues_df.iterrows():
            issue_key = str(issue.get("issue_key", ""))
            file_path = str(issue.get("file_path", ""))
            line = issue.get("line")

            if not file_path or pd.isna(line):
                rows.append({"issue_key": issue_key, "line_last_modified_days": None,
                              "line_author": ""})
                continue

            line = int(line)

            if file_path not in blame_cache:
                try:
                    blame_cache[file_path] = self._fetch_blame_ranges(file_path)
                except Exception as e:
                    log.warning(f"Blame fetch failed for {file_path}: {e}")
                    blame_cache[file_path] = []

            matched = next(
                (r for r in blame_cache[file_path]
                 if r["startingLine"] <= line <= r["endingLine"]),
                None,
            )

            if matched is None:
                rows.append({"issue_key": issue_key, "line_last_modified_days": None,
                              "line_author": ""})
                continue

            line_last_modified_days = None
            try:
                committed_dt = datetime.fromisoformat(matched["committedDate"].replace("Z", "+00:00"))
                line_last_modified_days = max((end_dt - committed_dt).days, 0)
            except Exception:
                pass

            rows.append({
                "issue_key": issue_key,
                "line_last_modified_days": line_last_modified_days,
                "line_author": matched.get("authorName", ""),
            })

        return pd.DataFrame(rows)

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
                log.warning(f"Error processing {fp}: {e}")
                row = self._zero_row(fp)
            rows.append(row)

        df = pd.DataFrame(rows)
        out_path = self.results_path / "churn_metrics.csv"
        df.to_csv(out_path, index=False)
        log.info(f"churn_metrics.csv written: {len(df)} rows")

        # Alert-level churn via GraphQL blame (requires GITHUB_TOKEN)
        if self.token:
            try:
                log.info(f"Computing alert-level churn via GitHub blame API ({len(issues)} issues)...")
                alert_df = self._compute_alert_churn(issues)
                alert_path = self.results_path / "alert_churn_metrics.csv"
                alert_df.to_csv(alert_path, index=False)
                enriched_count = alert_df["line_last_modified_days"].notna().sum()
                log.info(f"alert_churn_metrics.csv written: {len(alert_df)} rows, {enriched_count} with blame data")
            except Exception as e:
                log.warning(f"Alert-level churn computation failed: {e} — skipping")
        else:
            log.warning("GITHUB_TOKEN not set — skipping alert-level churn (blame requires authentication)")
        
        # Write extraction metadata
        metadata = {
            "github_extraction_date": extraction_datetime,
            "churn_window_start": self.start_date,
            "churn_window_end": self.end_date,
        }
        metadata_path = self.results_path / "extraction_metadata.json"
        if metadata_path.exists():
            try:
                with open(metadata_path, "r") as f:
                    existing = json.load(f)
                existing.update(metadata)
                metadata = existing
            except Exception as e:
                log.warning(f"Could not merge extraction metadata: {e}")
        
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
        log.info(f"extraction_metadata.json written")
