import logging
import os
from pathlib import Path
import pandas as pd
import requests

log = logging.getLogger(__name__)

# SonarQube's component_tree endpoint rejects requests with more than ~15 metric keys.
# Split into named groups, each fetched independently so one failing group does not
# block the others.
MEASURE_KEYS_CORE = (
    "bugs,vulnerabilities,code_smells,violations,"
    "complexity,cognitive_complexity,sqale_index"
)
MEASURE_KEYS_RATINGS = (
    "lines,reliability_rating,security_rating"
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

    def _parse_issue(self, issue: dict) -> dict:
        return {
            "issue_key": issue.get("key", ""),
            "file_path": self._extract_file_path(issue.get("component", "")),
            "file": self._extract_file_name(issue.get("component", "")),
            "rule": issue.get("rule", ""),
            "impact_severity": str(issue.get("impacts", [{}])[0].get("severity", "")).upper() if issue.get("impacts") else "",
            "impact_quality": str(issue.get("impacts", [{}])[0].get("softwareQuality", "")).upper() if issue.get("impacts") else "",
            "type": issue.get("type", ""),
            "message": issue.get("message", ""),
            "line": issue.get("line"),
            "effort": issue.get("effort", ""),
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
        """
        Fetch all open issues from SonarQube in 10.x impact-severity order:
        HIGH → MEDIUM → LOW.

        SonarQube 10.x's UI orders alerts by impact_severity when developers use the
        severity filter. To replicate that view, the extractor calls
        /api/issues/search three times — once per impactSeverities tier — and
        concatenates results in HIGH, MEDIUM, LOW order. Within each tier the API's
        default ordering applies (no explicit s= parameter), matching what a developer
        scrolling the UI would see.

        Each tier is its own slice for the 10,000-result-per-filter cap, so a tier
        with fewer than 10k alerts needs no further splitting. Tiers that exceed the
        cap fall back to splitting by type, then by individual rule.
        """
        base_params: dict = {
            "componentKeys": self.project_key,
            "statuses": "OPEN,CONFIRMED,REOPENED",
        }

        log.info("Fetching all open issues from SonarQube in severity order...")

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

        # Tier order matters: HIGH → MEDIUM → LOW reflects SonarQube 10.x UI ordering.
        # Concatenating in this order is what gives ranking_c1.csv the right sequence;
        # build_c1_ranking() just numbers rows 1..N without re-sorting.
        for impact_tier in ("HIGH", "MEDIUM", "LOW"):
            tier_params = {**base_params, "impactSeverities": impact_tier}
            probe = self._get("/api/issues/search", {**tier_params, "ps": 1, "p": 1})
            tier_total = probe.get("total", 0)
            log.info(f"Tier impactSeverities={impact_tier}: {tier_total} issues")
            if tier_total == 0:
                continue
            if tier_total <= SONAR_PAGE_CAP:
                _collect(tier_params, f"impactSeverities={impact_tier} ({tier_total})")
                continue
            # Tier exceeds the per-filter cap → fall back to type, then rule splitting.
            log.warning(f"  Tier {impact_tier} has {tier_total} issues (>10k) — splitting by type")
            for typ in ("BUG", "VULNERABILITY", "CODE_SMELL"):
                typ_params = {**tier_params, "types": typ}
                typ_probe = self._get("/api/issues/search", {**typ_params, "ps": 1, "p": 1})
                typ_total = typ_probe.get("total", 0)
                if typ_total == 0:
                    continue
                _collect_or_split_by_rules(typ_params, f"impactSeverities={impact_tier} type={typ}", typ_total)

        if not all_issues:
            log.warning("No issues returned from SonarQube.")

        # Always return a DataFrame with the expected schema so downstream steps
        # receive a typed, predictable structure even when the result set is empty.
        df = pd.DataFrame(all_issues) if all_issues else pd.DataFrame(columns=[
            "issue_key", "file_path", "file", "rule",
            "impact_severity", "impact_quality",
            "type", "message", "line", "effort",
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
                    if key in ("reliability_rating", "security_rating"):
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
        rating_cols = {"reliability_rating", "security_rating"}
        for col in df.columns:
            if col not in {"file_path"} | rating_cols:
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
        log.info(f"Total files with measures: {len(df)}")
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
