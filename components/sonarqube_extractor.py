import json
import logging
import os
import time
from pathlib import Path

import pandas as pd
import requests

log = logging.getLogger(__name__)

SEVERITY_SCORE = {"BLOCKER": 5, "CRITICAL": 4, "MAJOR": 3, "MINOR": 2, "INFO": 1}

# SonarQube 10.x impact-based severity system (replaces legacy BLOCKER/CRITICAL/... ordering)
IMPACT_SEVERITY_SCORE = {"BLOCKER": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
QUALITY_PRIORITY = {"SECURITY": 3, "RELIABILITY": 2, "MAINTAINABILITY": 1}

# SonarQube's component_tree endpoint rejects requests with more than ~15 metric keys.
# Split into three named groups, each fetched independently so one failing group
# (e.g. legacy violation counts removed in SonarQube 10.x) does not block the others.
MEASURE_KEYS_CORE = (
    "bugs,vulnerabilities,code_smells,violations,"
    "complexity,cognitive_complexity,functions,duplicated_lines_density,sqale_index,sqale_debt_ratio"
)
# blocker_violations etc. were deprecated in SonarQube 10.x — fetched separately so
# failure here does not prevent complexity/coverage from being collected.
MEASURE_KEYS_VIOLATIONS = (
    "blocker_violations,critical_violations,major_violations,minor_violations,info_violations"
)
MEASURE_KEYS_RATINGS = (
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
        # Thesis design requires all severity tiers; no filtering allowed
        if sq.get("severities"):
            raise ValueError(
                "severities filter must not be set — thesis design requires all severity tiers "
                "to be extracted and ranked by impact, not pre-filtered by BLOCKER/CRITICAL/MAJOR labels"
            )
        tp = config.get("time_period", {})
        self.start_date = tp.get("start_date") or ""   # empty → no lower bound
        self.end_date = tp.get("end_date") or ""       # empty → no upper bound

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

    def _parse_impacts(self, impacts: list) -> tuple[str, str]:
        """Return (impact_severity, impact_quality) for the highest-priority impact entry."""
        if not impacts:
            return ("", "")
        best = max(
            impacts,
            key=lambda x: (
                IMPACT_SEVERITY_SCORE.get(x.get("severity", "").upper(), 0),
                QUALITY_PRIORITY.get(x.get("softwareQuality", "").upper(), 0),
            ),
        )
        return (best.get("severity", "").upper(), best.get("softwareQuality", "").upper())

    def _parse_issue(self, issue: dict) -> dict:
        component = issue.get("component", "")
        severity = issue.get("severity", "MAJOR")
        impact_severity, impact_quality = self._parse_impacts(issue.get("impacts", []))
        return {
            "issue_key": issue.get("key", ""),
            "component": component,
            "file_path": self._extract_file_path(component),
            "file": self._extract_file_name(component),
            "rule": issue.get("rule", ""),
            "severity": severity,
            "severity_score": SEVERITY_SCORE.get(severity, 3),
            "impact_severity": impact_severity,
            "impact_quality": impact_quality,
            "type": issue.get("type", ""),
            "message": issue.get("message", ""),
            "line": issue.get("line"),
            "status": issue.get("status", ""),
            "effort": issue.get("effort", ""),
            "debt": issue.get("debt", ""),
            "tags": ",".join(issue.get("tags", [])),
            "creationDate": issue.get("creationDate", ""),
        }

    def _fetch_issues_page(self, base_params: dict) -> list[dict]:
        """
        Paginate one filtered slice of /api/issues/search.
        SonarQube hard-caps at 10,000 results per filter (p * ps ≤ 10,000).
        Callers are responsible for keeping each slice under that limit.
        """
        issues = []
        page = 1
        page_size = 500
        while True:
            params = {**base_params, "ps": page_size, "p": page}
            data = self._get("/api/issues/search", params)
            for issue in data.get("issues", []):
                issues.append(self._parse_issue(issue))
            total = data.get("total", 0)
            fetched = page * page_size
            log.info(f"    page {page}: {min(fetched, total)}/{total}")
            if fetched >= total:
                break
            page += 1
        return issues

    def fetch_issues(self) -> pd.DataFrame:
        # Build date-scoped query params.
        # createdBefore=end_date  → snapshot: only issues first detected by end of period
        # createdAfter=start_date → additionally excludes pre-existing issues (use for
        #                           proprietary repos where only a time slice is accessible)
        # Omitting either bound means no restriction on that side (full history).
        base_params: dict = {
            "componentKeys": self.project_key,
            "statuses": "OPEN,CONFIRMED,REOPENED",
            # Fetch in SonarQube's native severity order so ranking_c1.csv exactly replicates
            # the API response order: BLOCKER → CRITICAL → MAJOR → MINOR → INFO.
            # Within the same severity, SonarQube's own secondary sort (creation date ASC) applies.
            "s": "SEVERITY",
            "asc": "false",
        }
        if self.end_date:
            base_params["createdBefore"] = self.end_date
        if self.start_date:
            base_params["createdAfter"] = self.start_date

        window_desc = f"{self.start_date or '(any)'} → {self.end_date or '(any)'}"
        log.info(f"Fetching issues from SonarQube (window: {window_desc})...")

        # Probe total without fetching all pages
        probe = self._get("/api/issues/search", {**base_params, "ps": 1, "p": 1})
        total = probe.get("total", 0)
        log.info(f"Total issues in SonarQube: {total}")

        # SonarQube caps pagination at 10,000 results per filter (p * ps ≤ 10,000).
        # When total exceeds the cap, split by severity to keep each slice under 10,000.
        SONAR_PAGE_CAP = 10_000
        seen_keys: set[str] = set()
        all_issues: list[dict] = []

        def _collect(params: dict, label: str) -> None:
            log.info(f"  Fetching slice: {label}")
            for row in self._fetch_issues_page(params):
                if row["issue_key"] not in seen_keys:
                    seen_keys.add(row["issue_key"])
                    all_issues.append(row)

        def _collect_or_split_by_rules(params: dict, label: str, slice_total: int) -> None:
            """Fetch a slice; if it still exceeds the cap, split by individual rule."""
            if slice_total <= SONAR_PAGE_CAP:
                _collect(params, f"{label} ({slice_total})")
                return
            log.warning(f"  {label} has {slice_total} issues (>10k) — splitting by rule")
            facet_data = self._get("/api/issues/search", {**params, "ps": 1, "p": 1, "facets": "rules"})
            rules = [
                bucket["val"]
                for facet in facet_data.get("facets", [])
                if facet["property"] == "rules"
                for bucket in facet["values"]
                if bucket["count"] > 0
            ]
            if not rules:
                log.warning(f"  No rules found for {label} — skipping this slice")
                return
            for rule in rules:
                rule_params = {**params, "rules": rule}
                rule_probe = self._get("/api/issues/search", {**rule_params, "ps": 1, "p": 1})
                rule_total = rule_probe.get("total", 0)
                if rule_total > 0:
                    _collect(rule_params, f"{label} rule={rule} ({rule_total})")

        if total <= SONAR_PAGE_CAP:
            _collect(base_params, "all severities")
        else:
            # Split by severity, then by type, then by rule if still needed.
            for sev in ("BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"):
                sev_params = {**base_params, "severities": sev}
                sev_probe = self._get("/api/issues/search", {**sev_params, "ps": 1, "p": 1})
                sev_total = sev_probe.get("total", 0)
                if sev_total == 0:
                    continue
                if sev_total <= SONAR_PAGE_CAP:
                    _collect(sev_params, f"severity={sev} ({sev_total})")
                else:
                    log.warning(f"  severity={sev} has {sev_total} issues (>10k) — splitting by type")
                    for typ in ("BUG", "VULNERABILITY", "CODE_SMELL"):
                        typ_params = {**sev_params, "types": typ}
                        typ_probe = self._get("/api/issues/search", {**typ_params, "ps": 1, "p": 1})
                        typ_total = typ_probe.get("total", 0)
                        if typ_total == 0:
                            continue
                        _collect_or_split_by_rules(typ_params, f"severity={sev} type={typ}", typ_total)

        if not all_issues:
            hint = ""
            if self.start_date or self.end_date:
                hint = (
                    f" NOTE: date filter active ({window_desc}). "
                    "SonarQube creationDate reflects when the analysis was run, not when "
                    "the code was written. If your SonarQube instance was set up recently, "
                    "set start_date: null in your project YAML to fetch all issues."
                )
            log.warning(f"No issues returned from SonarQube.{hint}")

        # Always return a DataFrame with the expected schema so downstream steps
        # receive a typed, predictable structure even when the result set is empty.
        df = pd.DataFrame(all_issues) if all_issues else pd.DataFrame(columns=[
            "issue_key", "component", "file_path", "file", "rule",
            "severity", "severity_score", "impact_severity", "impact_quality",
            "type", "message", "line", "status", "effort", "debt", "tags", "creationDate",
        ])
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
                        # SonarQube returns "1.0" but RATING_MAP keys are "1"
                        int_val = str(int(float(val))) if val.replace(".", "").isdigit() else val
                        row[key] = RATING_MAP.get(int_val, int_val)
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
        merged: dict[str, dict] = {}

        for keys, label in [
            (MEASURE_KEYS_CORE, "core"),
            (MEASURE_KEYS_VIOLATIONS, "violation-counts"),
            (MEASURE_KEYS_RATINGS, "ratings"),
        ]:
            try:
                for fp, row in self._fetch_measures_for_keys(keys).items():
                    merged.setdefault(fp, {"file_path": fp}).update(row)
                log.info(f"  Measures group '{label}': OK")
            except Exception as e:
                log.warning(f"  Measures group '{label}' failed: {e} — skipping")

        df = pd.DataFrame(list(merged.values()))
        if df.empty:
            return df
        rating_cols = {"reliability_rating", "security_rating", "sqale_rating"}
        for col in df.columns:
            if col not in {"file_path"} | rating_cols:
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
        log.info(f"Total files with measures: {len(df)}")
        return df

    def build_c1_ranking(self, issues: pd.DataFrame) -> pd.DataFrame:
        # Issues are already fetched with s=SEVERITY&asc=false so they arrive in exactly
        # the order SonarQube shows them. Just assign sequential rank numbers — do not
        # re-sort, which would deviate from SonarQube's own ordering.
        df = issues.copy().reset_index(drop=True)
        df["c1_rank"] = df.index + 1
        return df

    def fetch_rule_descriptions(self, issues: pd.DataFrame) -> dict:
        """
        Fetch SonarQube rule metadata for each unique rule key, for interview UI display.
        
        Scientific justification: Interview participants must see the same rule explanation
        they would see in SonarQube to validate whether an alert represents a real problem.
        Rule descriptions are identical across C1, C2, C3 (they come from SonarQube's
        rule database, not from ranking), so their presence does not contaminate the
        comparison between conditions. Fetching is done once per unique rule key, not once
        per alert, to minimize API calls.
        
        Args:
            issues: DataFrame with 'rule' column containing rule keys
            
        Returns:
            Dictionary keyed by rule key with structure:
            {
                "rule_key": str,
                "rule_name": str,
                "rule_description": str,  # HTML or Markdown
                "rule_type": str,
                "rule_tags": list[str],
                "default_impacts": list[dict]  # [{"softwareQuality": str, "severity": str}]
            }
        """
        unique_rules = issues["rule"].unique()
        log.info(f"Fetching descriptions for {len(unique_rules)} unique rule keys...")
        
        descriptions = {}
        failed = 0
        
        for rule_key in unique_rules:
            try:
                resp = requests.get(
                    f"{self.host}/api/rules/show",
                    params={"key": rule_key},
                    auth=self._auth(),
                    timeout=30
                )
                if resp.status_code == 404:
                    log.warning(f"Rule not found: {rule_key}")
                    failed += 1
                    continue
                    
                resp.raise_for_status()
                data = resp.json()
                rule = data.get("rule", {})
                
                descriptions[rule_key] = {
                    "rule_key": rule.get("key", rule_key),
                    "rule_name": rule.get("name", ""),
                    "rule_description": rule.get("htmlDesc") or rule.get("mdDesc", ""),
                    "rule_type": rule.get("type", ""),
                    "rule_tags": rule.get("tags", []),
                    "default_impacts": rule.get("defaultImpacts", []),
                }
            except requests.exceptions.Timeout:
                log.warning(f"Timeout fetching rule {rule_key}, retrying once...")
                try:
                    time.sleep(2)
                    resp = requests.get(
                        f"{self.host}/api/rules/show",
                        params={"key": rule_key},
                        auth=self._auth(),
                        timeout=30
                    )
                    if resp.status_code == 404:
                        failed += 1
                    else:
                        resp.raise_for_status()
                        data = resp.json()
                        rule = data.get("rule", {})
                        descriptions[rule_key] = {
                            "rule_key": rule.get("key", rule_key),
                            "rule_name": rule.get("name", ""),
                            "rule_description": rule.get("htmlDesc") or rule.get("mdDesc", ""),
                            "rule_type": rule.get("type", ""),
                            "rule_tags": rule.get("tags", []),
                            "default_impacts": rule.get("defaultImpacts", []),
                        }
                except Exception:
                    failed += 1
            except Exception as e:
                log.warning(f"Error fetching rule {rule_key}: {e}")
                failed += 1
        
        log.info(f"Rule descriptions fetched: {len(descriptions)} success, {failed} failed")
        return descriptions

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

        # Rule descriptions fetched for interview UI — one request per unique rule key,
        # cached to rule_descriptions.json. Descriptions are identical across conditions
        # and do not affect rankings; they are fetched for ecological validity (developers
        # see rule explanations when investigating alerts in SonarQube).
        try:
            descriptions = self.fetch_rule_descriptions(issues)
            desc_path = self.results_path / "rule_descriptions.json"
            with open(desc_path, "w") as f:
                json.dump(descriptions, f, indent=2)
            log.info(f"rule_descriptions.json written: {len(descriptions)} rules")
        except Exception as e:
            log.error(f"Rule descriptions fetch failed: {e} — continuing without UI descriptions")
