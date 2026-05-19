from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd

log = logging.getLogger(__name__)

DISPLAY_TOTAL = 15

OUTPUT_COLS = [
    "issue_key", "file_path", "file", "rule", "message", "line",
    "type", "effort", "impact_severity", "impact_quality",
    "rank", "llm_reasoning",
]

INTERVIEW_COLS = [
    "rank", "file", "line", "rule", "type", "message", "effort",
]

def build_display_set(condition: str, ranking: pd.DataFrame) -> pd.DataFrame:
    rank_col = f"{condition}_rank"
    if rank_col not in ranking.columns:
        raise ValueError(f"ranking for {condition} is missing column {rank_col}")

    top = ranking.sort_values(rank_col, ascending=True).head(DISPLAY_TOTAL).copy()

    out = pd.DataFrame({
        "issue_key": top.get("issue_key", pd.Series([""] * len(top))).astype(str),
        "file_path": top.get("file_path", pd.Series([""] * len(top))).astype(str),
        "file": top.get("file", pd.Series([""] * len(top))).astype(str),
        "rule": top.get("rule", pd.Series([""] * len(top))).astype(str),
        "message": top.get("message", pd.Series([""] * len(top))).astype(str),
        "line": top.get("line", pd.Series([None] * len(top))),
        "type": top.get("type", pd.Series([""] * len(top))).astype(str),
        "effort": top.get("effort", pd.Series([""] * len(top))).astype(str),
        "impact_severity": top.get("impact_severity", pd.Series([""] * len(top))).astype(str),
        "impact_quality": top.get("impact_quality", pd.Series([""] * len(top))).astype(str),
        "rank": top[rank_col].astype(int),
        "llm_reasoning": (
            top["llm_reasoning"].fillna("").astype(str)
            if condition != "c1" and "llm_reasoning" in top.columns
            else pd.Series([""] * len(top), index=top.index)
        ),
    })
    return out.reset_index(drop=True)[OUTPUT_COLS]


def run(project_id: str, results_path: Path) -> None:
    for fname in ("ranking_c1.csv", "ranking_c2.csv", "ranking_c3.csv"):
        if not (results_path / fname).exists():
            raise FileNotFoundError(f"{fname} missing — run LLM ranker first")

    rankings = {
        "c1": pd.read_csv(results_path / "ranking_c1.csv"),
        "c2": pd.read_csv(results_path / "ranking_c2.csv"),
        "c3": pd.read_csv(results_path / "ranking_c3.csv"),
    }

    for condition, ranking in rankings.items():
        df = build_display_set(condition, ranking)
        out_path = results_path / f"display_set_{condition}.csv"
        df.to_csv(out_path, index=False)
        if len(df) == DISPLAY_TOTAL:
            log.info("display_set_%s.csv written: %d rows (✓ exactly %d)",
                     condition, len(df), DISPLAY_TOTAL)
        else:
            log.warning("display_set_%s.csv written: %d rows (expected %d)",
                        condition, len(df), DISPLAY_TOTAL)

        # Also build neutral interview list: only Rank, File, Line, Rule, Type, Message, Effort.
        # No severity, no context, no reasoning — shown to participants before disclosure.
        interview_df = df[INTERVIEW_COLS].copy() if INTERVIEW_COLS else df
        interview_path = results_path / f"interview_list_{condition}.csv"
        interview_df.to_csv(interview_path, index=False)
        log.info("interview_list_%s.csv written: %d rows", condition, len(interview_df))
