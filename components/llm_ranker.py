"""
Reprioritises individual SonarQube issues using the Anthropic API.

Input:  results/{project_id}/enriched_issues.csv
Output: results/{project_id}/ranking_c2.csv
        results/{project_id}/ranking_c3.csv

Design decisions:
- Issue-level ranking (not file-level): matches how SonarQube presents alerts to developers
- Single prompt per project: allows holistic relative prioritisation across all issues;
  avoids seam artifacts from independent batch rankings
- File-level context (churn, SATD, complexity) attached to each issue of that file:
  provides the contextual signal SonarQube cannot compute
- Temperature=0: mandatory for reproducibility across all interview participants
- Per-issue reasoning: one sentence per issue citing specific signal values,
  used in interview UI expanded rows and explanation card
"""

import json
import logging
import os
import re
from pathlib import Path

import anthropic
import pandas as pd

log = logging.getLogger(__name__)

# SonarQube 10.x impact-based severity model uses three levels: HIGH, MEDIUM, LOW.
# LLM output uses this vocabulary (not the legacy five-level BLOCKER/CRITICAL/MAJOR/MINOR/INFO).
# This ensures visual consistency across C1, C2, and C3 conditions in the interview UI:
# C1 displays SonarQube's native HIGH/MEDIUM/LOW labels; C2 and C3 must use the same
# vocabulary to isolate the effect of ordering from label presentation differences.
# Interview participants evaluate all three conditions side by side, so mismatched
# vocabulary would be an artifact, not a methodological signal. See RQ2:Actionability.
SEVERITY_SCORE = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
VALID_SEVERITIES = {"HIGH", "MEDIUM", "LOW"}
VALID_TYPES = {"BUG", "VULNERABILITY", "CODE_SMELL"}

PROMPTS_DIR = Path(__file__).parent.parent / "prompts"


class LLMRanker:
    def __init__(self, config: dict, results_path: Path):
        self.config = config
        self.results_path = results_path
        llm = config.get("llm", {})
        self.model = llm.get("model", "claude-sonnet-4-6")
        self.max_tokens = llm.get("max_tokens", 8192)
        # THESIS DESIGN: Batching is NOT permitted. Single prompt per condition per repository.
        # The 200-alert pool (externally controlled) is the mechanism that prevents
        # oversized prompts. No per-pipeline alert limit is needed.
        self.client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY", ""))

    def _load_prompt_template(self, condition: str) -> str:
        path = PROMPTS_DIR / f"system_prompt_{condition}.txt"
        return path.read_text()

    @staticmethod
    def _coverage_or_null(row: pd.Series):
        """Return coverage as float if configured, None if not (SonarQube returns 0 for both
        'genuinely 0% covered' and 'coverage analysis not set up' — we treat 0 as null
        to avoid the LLM misinterpreting missing data as a quality signal)."""
        cov = float(row.get("coverage", 0) or 0)
        lines = float(row.get("lines", 0) or 0)
        return round(cov, 1) if cov > 0 or lines == 0 else None

    def _build_c2_issue(self, row: pd.Series) -> dict:
        # THESIS DESIGN: C2 issue JSON excludes impact_severity and impact_quality.
        # The LLM ranks based on SonarQube severity only (not impact-based fields).
        # This avoids anchoring bias from the combined impact model.
        return {
            "issue_key": str(row.get("issue_key", "")),
            "file": str(row.get("file", "")),
            "rule": str(row.get("rule", "")),
            "severity": str(row.get("severity", "")),
            "type": str(row.get("type", "")),
            "message": str(row.get("message", "")),
            "line": int(row["line"]) if pd.notna(row.get("line")) else None,
            "effort": str(row.get("effort", "") or ""),
            "file_bugs": int(row.get("bugs", 0) or 0),
            "file_vulnerabilities": int(row.get("vulnerabilities", 0) or 0),
            "file_code_smells": int(row.get("code_smells", 0) or 0),
            "file_violations": int(row.get("violations", 0) or 0),
            "file_complexity": int(row.get("complexity", 0) or 0),
            "file_cognitive_complexity": int(row.get("cognitive_complexity", 0) or 0),
            "file_coverage": self._coverage_or_null(row),
            "file_sqale_index": int(row.get("sqale_index", 0) or 0),
            "file_reliability_rating": str(row.get("reliability_rating", "") or ""),
            "file_security_rating": str(row.get("security_rating", "") or ""),
        }

    def _build_c3_issue(self, row: pd.Series) -> dict:
        obj = self._build_c2_issue(row)
        lld = row.get("line_last_modified_days")
        satd_count = row.get("satd_count")
        satd_age_days = row.get("satd_age_days")
        satd_change_count = row.get("satd_change_count")
        obj.update({
            "file_commit_count": int(row.get("commit_count", 0) or 0),
            "file_unique_authors": int(row.get("unique_authors", 0) or 0),
            "file_bus_factor": int(row.get("bus_factor", 0) or 0),
            "file_churn": int(row.get("churn", 0) or 0),
            "file_days_since_modified": int(row.get("days_since_modified", 0) or 0),
            "file_age_days": int(row.get("file_age_days", 0) or 0),
            "file_satd_count": int(satd_count) if pd.notna(satd_count) else None,
            "file_satd_text": str(row.get("satd_text", "") or ""),
            "file_satd_age_days": int(satd_age_days) if pd.notna(satd_age_days) else None,
            "file_satd_change_count": int(satd_change_count) if pd.notna(satd_change_count) else None,
            "line_last_modified_days": int(lld) if pd.notna(lld) else None,
        })
        return obj

    def _call_api(self, issues_json: str, condition: str) -> str:
        template = self._load_prompt_template(condition)
        prompt = template.replace("{issues_json}", issues_json)

        # RESEARCH INTEGRITY: temperature=0 is mandatory.
        # Ensures identical outputs for identical inputs across all interview sessions.
        # Do not change this value under any circumstances.
        message = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=0,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text

    def _parse_response(self, raw: str, fallback_df: pd.DataFrame, condition: str) -> list[dict]:
        cleaned = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.MULTILINE)
        cleaned = re.sub(r"\s*```$", "", cleaned.strip(), flags=re.MULTILINE)
        cleaned = cleaned.strip()

        # Fallback mapping: converts any severity value from CSV (legacy or 10.x) to three-level LLM output vocabulary
        severity_fallback_map = {"BLOCKER": "HIGH", "CRITICAL": "HIGH", "MAJOR": "MEDIUM", "MINOR": "LOW", "INFO": "LOW", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}

        try:
            parsed = json.loads(cleaned)
            if not isinstance(parsed, list):
                raise ValueError("Response is not a JSON array")
            validated = []
            for item in parsed:
                severity = item.get("llm_severity", "").upper()
                issue_type = item.get("llm_type", "").upper()
                if severity not in VALID_SEVERITIES:
                    fb_sev = fallback_df.loc[
                        fallback_df["issue_key"] == item.get("issue_key"), "severity"
                    ].values[0] if item.get("issue_key") in fallback_df["issue_key"].values else "MAJOR"
                    severity = severity_fallback_map.get(str(fb_sev).upper(), "MEDIUM")
                if issue_type not in VALID_TYPES:
                    issue_type = fallback_df.loc[
                        fallback_df["issue_key"] == item.get("issue_key"), "type"
                    ].values[0] if item.get("issue_key") in fallback_df["issue_key"].values else "CODE_SMELL"
                validated.append({
                    "issue_key": item.get("issue_key", ""),
                    "llm_severity": severity,
                    "llm_type": issue_type,
                    "llm_priority_score": SEVERITY_SCORE.get(severity, 2),
                    "llm_reasoning": item.get("llm_reasoning", ""),
                })
            return validated
        except Exception as e:
            log.error(f"JSON parse failure ({condition}): {e}")
            log.error(f"Raw response (first 500 chars): {raw[:500]}")
            severity_fallback_map = {"BLOCKER": "HIGH", "CRITICAL": "HIGH", "MAJOR": "MEDIUM", "MINOR": "LOW", "INFO": "LOW", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
            return [
                {
                    "issue_key": str(row["issue_key"]),
                    "llm_severity": severity_fallback_map.get(str(row.get("severity", "MAJOR")).upper(), "MEDIUM"),
                    "llm_type": str(row.get("type", "CODE_SMELL")),
                    "llm_priority_score": SEVERITY_SCORE.get(
                        severity_fallback_map.get(str(row.get("severity", "MAJOR")).upper(), "MEDIUM"), 2
                    ),
                    "llm_reasoning": "",
                }
                for _, row in fallback_df.iterrows()
            ]

    def _call_single(self, issues: pd.DataFrame, condition: str) -> list[dict]:
        log.info(f"Calling LLM (single prompt, {condition}): {len(issues)} issues")
        if condition == "c2":
            issue_list = [self._build_c2_issue(row) for _, row in issues.iterrows()]
        else:
            issue_list = [self._build_c3_issue(row) for _, row in issues.iterrows()]
        raw = self._call_api(json.dumps(issue_list, ensure_ascii=False), condition)
        return self._parse_response(raw, issues, condition)



    def _rank_and_save(self, enriched: pd.DataFrame, llm_results: list[dict], condition: str) -> None:
        llm_df = pd.DataFrame(llm_results)
        merged = enriched.merge(llm_df, on="issue_key", how="left")

        merged["llm_priority_score"] = pd.to_numeric(merged.get("llm_priority_score"), errors="coerce").fillna(3)

        if condition == "c2":
            merged["file_critical_violations"] = pd.to_numeric(merged.get("critical_violations"), errors="coerce").fillna(0)
            merged["file_complexity_sort"] = pd.to_numeric(merged.get("complexity"), errors="coerce").fillna(0)
            merged = merged.sort_values(
                ["llm_priority_score", "file_critical_violations", "file_complexity_sort"],
                ascending=[False, False, False],
            ).reset_index(drop=True)
            merged["c2_rank"] = merged.index + 1
            out_cols = [c for c in merged.columns if c not in ("file_critical_violations", "file_complexity_sort")]
            merged = merged[out_cols]
            rank_col = "c2_rank"
        else:
            merged["file_churn_sort"] = pd.to_numeric(merged.get("churn"), errors="coerce").fillna(0)
            merged["file_cognitive_complexity_sort"] = pd.to_numeric(merged.get("cognitive_complexity"), errors="coerce").fillna(0)
            merged = merged.sort_values(
                ["llm_priority_score", "file_churn_sort", "file_cognitive_complexity_sort"],
                ascending=[False, False, False],
            ).reset_index(drop=True)
            merged["c3_rank"] = merged.index + 1
            out_cols = [c for c in merged.columns if c not in ("file_churn_sort", "file_cognitive_complexity_sort")]
            merged = merged[out_cols]
            rank_col = "c3_rank"

        out_path = self.results_path / f"ranking_{condition}.csv"
        merged.to_csv(out_path, index=False)
        log.info(f"ranking_{condition}.csv written: {len(merged)} issues ranked")

    def run(self) -> None:
        enriched_path = self.results_path / "enriched_issues.csv"
        if not enriched_path.exists():
            raise FileNotFoundError("enriched_issues.csv must exist before running LLM ranker")

        enriched = pd.read_csv(enriched_path)
        log.info(f"LLM ranker: {len(enriched)} issues loaded from enriched_issues.csv")

        # THESIS DESIGN: Single prompt per condition per repository (no batching).
        # Batching would introduce seam artifacts and violate holistic ranking design.
        # The alert pool size is externally controlled (e.g., 200-alert cap); failures
        # upstream prevent oversized inputs here.

        for condition in ("c2", "c3"):
            log.info(f"--- Condition {condition.upper()} ---")
            results = self._call_single(enriched, condition)
            self._rank_and_save(enriched, results, condition)
