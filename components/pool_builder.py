from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd

log = logging.getLogger(__name__)

# Deterministic pool building: stratified by severity, max 5 per rule, API order preserved.
# This is deterministic — no randomness. Same input always produces same pool.
TIER_BUDGETS = {"HIGH": 17, "MEDIUM": 17, "LOW": 16}
TARGET_TOTAL = 50
RULE_MAX_IN_POOL = 5
FILE_MAX_IN_POOL = 5

def build_pool(issues: pd.DataFrame) -> pd.DataFrame:
    """Build a deterministic 50-alert candidate pool.
    
    Strategy:
    - Stratify alerts by SonarQube impact_severity: HIGH=17, MEDIUM=17, LOW=16.
    - Within each tier, preserve SonarQube API order (no re-sorting).
    - Within each tier, enforce max 5 alerts per rule to avoid rule domination.
    - No randomness; same input always produces same pool.
    """
    issues = issues.reset_index(drop=False).rename(columns={"index": "_api_order"})
    log.info("Pool builder: %d total alerts", len(issues))

    rule_counts: dict[str, int] = {}
    file_counts: dict[str, int] = {}
    selected_orders: list[int] = []

    for tier, budget in TIER_BUDGETS.items():
        # Preserve API order within the tier — no re-sorting.
        tier_df = issues[issues["impact_severity"] == tier]
        if tier_df.empty:
            log.info("Tier %s: 0 available", tier)
            continue

        picked_in_tier = 0
        skipped_rule_cap = 0
        skipped_file_cap = 0
        for _, row in tier_df.iterrows():
            if picked_in_tier >= budget:
                break
            rule = str(row.get("rule", ""))
            fp_raw = row.get("file_path")
            file_path = str(fp_raw) if pd.notna(fp_raw) else str(row.get("file", ""))
            if rule_counts.get(rule, 0) >= RULE_MAX_IN_POOL:
                skipped_rule_cap += 1
                continue
            if file_counts.get(file_path, 0) >= FILE_MAX_IN_POOL:
                skipped_file_cap += 1
                continue
            selected_orders.append(int(row["_api_order"]))
            rule_counts[rule] = rule_counts.get(rule, 0) + 1
            file_counts[file_path] = file_counts.get(file_path, 0) + 1
            picked_in_tier += 1

        log.info(
            "Tier %s: %d available, budget %d, picked %d (skipped %d rule-cap, %d file-cap)",
            tier, len(tier_df), budget, picked_in_tier, skipped_rule_cap, skipped_file_cap,
        )

    pool = issues[issues["_api_order"].isin(selected_orders)] if selected_orders else issues.iloc[0:0]
    pool = pool.sort_values("_api_order", ascending=True).reset_index(drop=True)
    pool["pool_rank"] = range(1, len(pool) + 1)
    pool = pool.drop(columns=["_api_order"])

    log.info("Pool: %d alerts selected", len(pool))
    log.info("Per tier: %s", {t: int((pool["impact_severity"] == t).sum()) for t in TIER_BUDGETS})
    log.info("Unique rules in pool: %d", pool["rule"].nunique())
    log.info("Unique files in pool: %d", pool["file_path"].nunique() if "file_path" in pool.columns else pool["file"].nunique())
    return pool


def run(project_id: str, results_path: Path) -> Path:
    issues_path = results_path / "sonarqube_issues.csv"
    if not issues_path.exists():
        raise FileNotFoundError(f"{issues_path} missing — run sonarqube stage first")
    issues = pd.read_csv(issues_path)
    pool = build_pool(issues)
    out_path = results_path / "alert_pool_50.csv"
    pool.to_csv(out_path, index=False)
    log.info("Wrote %d-alert pool → %s", len(pool), out_path)
    
    # C1 ranking: rank the same 50-alert pool by SonarQube-derived order
    # (which is impact_severity + API order within each tier from sonarqube_extractor).
    # ranking_c1.csv now has exactly the same 50 alerts as C2 and C3, ranked by pool order.
    ranking_c1 = pool.copy()
    ranking_c1["c1_rank"] = ranking_c1["pool_rank"]
    c1_path = results_path / "ranking_c1.csv"
    ranking_c1.to_csv(c1_path, index=False)
    log.info("Wrote ranking_c1.csv from 50-alert pool: %d rows", len(ranking_c1))
    
    return out_path
