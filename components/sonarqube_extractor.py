"""
Extracts individual issues and file-level quality measures from SonarQube.

Input:  Project config (host, project_key, token, max_issues)
Output: results/{project_id}/sonarqube_issues.csv
        results/{project_id}/sonarqube_measures.csv
        results/{project_id}/ranking_c1.csv

Design decisions:
- Issues and measures are separate API calls: /api/issues/search returns violations,
  /api/measures/component_tree returns file quality metrics — they serve different purposes
- Severity score added numerically to enable deterministic default sort
- C1 ranking replicates SonarQube's native ordering for a faithful baseline
"""

import logging
import os
from pathlib import Path

import pandas as pd
import requests

log = logging.getLogger(__name__)

SEVERITY_SCORE = {"BLOCKER": 5, "CRITICAL": 4, "MAJOR": 3, "MINOR": 2, "INFO": 1}
TYPE_WEIGHT = {"BUG": 3, "VULNERABILITY": 2, "CODE_SMELL": 1}

# SonarQube's component_tree endpoint rejects requests with more than ~15 metric keys
# in a single call. Split into two fixed groups that each stay under the limit.
MEASURE_KEYS_A = (
    "bugs,vulnerabilities,code_smells,violations,"
    "blocker_violations,critical_violations,major_violations,minor_violations,info_violations,"
    "complexity,cognitive_complexity,functions,duplicated_lines_density,sqale_index,sqale_debt_ratio"
)
MEASURE_KEYS_B = (
    "coverage,lines,reliability_rating,security_rating,sqale_rating"
)

RATING_MAP = {"1": "A", "2": "B", "3": "C", "4": "D", "5": "E"}


class SonarQubeExtractor:
    def __init__(self, config: dict, results_path: Path):
        self.config = config
        self.results_path = results_path
        sq = config.get("sonarqube", {})
        self.host = sq.get("host", "http://localhost:9000").rstrip("/")
        self.project_key = sq.get("project_key", "")
        self.token = sq.get("token") or os.getenv("SONAR_TOKEN", "")
        self.max_issues = sq.get("max_issues", 500)

    def _auth(self):
        return (self.token, "")

    def _get(self, path: str, params: dict = None) -> dict:
        url = f"{self.host}{path}"
        resp = requests.get(url, params=params, auth=self._auth(), timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _extract_file_path(self, component: str) -> str:
        if ":" in component:
            return component.split(":", 1)[1]
        return component

    def _extract_file_name(self, component: str) -> str:
        return self._extract_file_path(component).split("/")[-1]

    def fetch_issues(self) -> pd.DataFrame:
        log.info("Fetching issues from SonarQube...")
        issues = []
        page = 1
        page_size = 500

        while True:
            data = self._get("/api/issues/search", {
                "componentKeys": self.project_key,
                "statuses": "OPEN,CONFIRMED,REOPENED",
                "ps": page_size,
                "p": page,
            })
            for issue in data.get("issues", []):
                component = issue.get("component", "")
                severity = issue.get("severity", "MAJOR")
                issues.append({
                    "issue_key": issue.get("key", ""),
                    "component": component,
                    "file_path": self._extract_file_path(component),
                    "file": self._extract_file_name(component),
                    "rule": issue.get("rule", ""),
                    "severity": severity,
                    "severity_score": SEVERITY_SCORE.get(severity, 3),
                    "type": issue.get("type", ""),
                    "message": issue.get("message", ""),
                    "line": issue.get("line"),
                    "status": issue.get("status", ""),
                    "effort": issue.get("effort", ""),
                    "debt": issue.get("debt", ""),
                    "tags": ",".join(issue.get("tags", [])),
                    "creationDate": issue.get("creationDate", ""),
                })

            total = data.get("total", 0)
            fetched = page * page_size
            log.info(f"  Page {page}: fetched {min(fetched, total)}/{total} issues")

            if fetched >= total or fetched >= self.max_issues:
                break
            page += 1

        df = pd.DataFrame(issues)
        log.info(f"Total issues fetched: {len(df)}")
        return df

    def _fetch_measures_for_keys(self, metric_keys: str) -> dict[str, dict]:
        """Fetch all pages for a given set of metric keys, return {file_path: {metric: value}}."""
        result: dict[str, dict] = {}
        page = 1
        while True:
            data = self._get("/api/measures/component_tree", {
                "component": self.project_key,
                "metricKeys": metric_keys,
                "strategy": "leaves",
                "ps": 500,
                "p": page,
            })
            for comp in data.get("components", []):
                if comp.get("qualifier") != "FIL":
                    continue
                fp = self._extract_file_path(comp.get("key", ""))
                row = result.setdefault(fp, {"file_path": fp})
                for m in comp.get("measures", []):
                    key = m["metric"]
                    val = m.get("value", "0") or "0"
                    if key in ("reliability_rating", "security_rating", "sqale_rating"):
                        row[key] = RATING_MAP.get(val, val)
                    else:
                        try:
                            row[key] = float(val)
                        except (ValueError, TypeError):
                            row[key] = val
            paging = data.get("paging", {})
            total = paging.get("total", 0)
            fetched = page * 500
            log.info(f"  Measures page {page}: fetched {min(fetched, total)}/{total} files")
            if fetched >= total:
                break
            page += 1
        return result

    def fetch_measures(self) -> pd.DataFrame:
        log.info("Fetching file-level measures from SonarQube...")
        # Two calls because SonarQube rejects more than ~15 metric keys per request
        merged = self._fetch_measures_for_keys(MEASURE_KEYS_A)
        for fp, row in self._fetch_measures_for_keys(MEASURE_KEYS_B).items():
            merged.setdefault(fp, {"file_path": fp}).update(row)

        df = pd.DataFrame(list(merged.values()))
        if df.empty:
            return df
        rating_cols = {"reliability_rating", "security_rating", "sqale_rating"}
        for col in df.columns:
            if col not in ("file_path",) | rating_cols:
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
        log.info(f"Total files with measures: {len(df)}")
        return df

    def build_c1_ranking(self, issues: pd.DataFrame) -> pd.DataFrame:
        df = issues.copy()
        df["type_weight"] = df["type"].map(TYPE_WEIGHT).fillna(0)
        df["creationDate_dt"] = pd.to_datetime(df["creationDate"], errors="coerce", utc=True)
        df = df.sort_values(
            ["type_weight", "severity_score", "creationDate_dt"],
            ascending=[False, False, True],
        ).reset_index(drop=True)
        df["c1_rank"] = df.index + 1
        df = df.drop(columns=["type_weight", "creationDate_dt"])
        return df

    def run(self) -> None:
        issues = self.fetch_issues()
        issues.to_csv(self.results_path / "sonarqube_issues.csv", index=False)
        log.info(f"sonarqube_issues.csv written: {len(issues)} rows")

        try:
            measures = self.fetch_measures()
            measures.to_csv(self.results_path / "sonarqube_measures.csv", index=False)
            log.info(f"sonarqube_measures.csv written: {len(measures)} rows")
        except Exception as e:
            log.error(f"Measures fetch failed: {e} — continuing without file-level metrics")

        # C1 ranking is built from issues alone; always written even if measures failed
        ranking_c1 = self.build_c1_ranking(issues)
        ranking_c1.to_csv(self.results_path / "ranking_c1.csv", index=False)
        log.info(f"ranking_c1.csv written: {len(ranking_c1)} rows")
