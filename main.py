"""
Main pipeline orchestrator.

Usage:
  python main.py --project commons-lang
  python main.py --project commons-lang --project schuberg-repo
  python main.py --all
  python main.py --project commons-lang --skip-sonarqube
  python main.py --project commons-lang --skip-github
  python main.py --project commons-lang --skip-satd
  python main.py --project commons-lang --skip-llm
  python main.py --project commons-lang --ui-only
  python main.py --project commons-lang --ui
"""

import argparse
import glob
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import yaml
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent
PROJECTS_DIR = BASE_DIR / "projects"
RESULTS_DIR = BASE_DIR / "results"


def load_config(project_id: str) -> dict:
    """Load global defaults and merge project-specific overrides."""
    with open(BASE_DIR / "config.yaml") as f:
        config = yaml.safe_load(f)

    project_file = PROJECTS_DIR / f"{project_id}.yaml"
    if not project_file.exists():
        raise FileNotFoundError(f"Project config not found: {project_file}")

    with open(project_file) as f:
        project = yaml.safe_load(f)

    merged = config["defaults"].copy()
    _deep_merge(merged, project)
    return merged


def _deep_merge(base: dict, override: dict) -> None:
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def validate_api_keys(config: dict, skip_sonarqube: bool, skip_github: bool, skip_satd: bool, skip_llm: bool) -> None:
    errors = []
    if not skip_sonarqube and config["components"].get("run_sonarqube"):
        token = config.get("sonarqube", {}).get("token") or os.getenv("SONAR_TOKEN")
        if not token:
            errors.append("SONAR_TOKEN not set (required for SonarQube extractor)")
    if not skip_github and config["components"].get("run_github_churn"):
        if not os.getenv("GITHUB_TOKEN"):
            errors.append("GITHUB_TOKEN not set (required for GitHub extractor)")
    if not skip_llm and config["components"].get("run_llm_ranking"):
        if not os.getenv("ANTHROPIC_API_KEY"):
            errors.append("ANTHROPIC_API_KEY not set (required for LLM ranker)")
    if errors:
        for e in errors:
            log.error(e)
        sys.exit(1)


def enrich_issues(project_id: str) -> pd.DataFrame:
    """
    Join sonarqube_issues + sonarqube_measures + churn_metrics + satd_comments on file_path.
    Returns one row per issue with all file-level context attached.
    Writes enriched_issues.csv.
    """
    results_path = RESULTS_DIR / project_id

    issues_path = results_path / "sonarqube_issues.csv"
    if not issues_path.exists():
        raise FileNotFoundError(f"sonarqube_issues.csv not found at {issues_path}")

    issues = pd.read_csv(issues_path)

    measures_path = results_path / "sonarqube_measures.csv"
    if measures_path.exists():
        try:
            measures = pd.read_csv(measures_path)
            if not measures.empty:
                issues = issues.merge(measures, on="file_path", how="left", suffixes=("", "_m"))
            else:
                log.warning("sonarqube_measures.csv is empty — file quality metrics will be empty")
        except Exception as e:
            log.warning(f"sonarqube_measures.csv could not be read ({e}) — skipping")
    else:
        log.warning("sonarqube_measures.csv not found — file quality metrics will be empty")

    churn_path = results_path / "churn_metrics.csv"
    if churn_path.exists():
        churn = pd.read_csv(churn_path)
        issues = issues.merge(churn, on="file_path", how="left", suffixes=("", "_c"))
    else:
        log.warning("churn_metrics.csv not found — churn metrics will be empty")

    satd_path = results_path / "satd_comments.csv"
    if satd_path.exists():
        satd = pd.read_csv(satd_path)
        issues = issues.merge(satd, on="file_path", how="left", suffixes=("", "_s"))
    else:
        log.warning("satd_comments.csv not found — SATD fields will be empty")

    alert_churn_path = results_path / "alert_churn_metrics.csv"
    if alert_churn_path.exists():
        alert_churn = pd.read_csv(alert_churn_path)
        issues = issues.merge(alert_churn, on="issue_key", how="left", suffixes=("", "_ac"))
    else:
        log.warning("alert_churn_metrics.csv not found — alert-level churn fields will be empty")

    final_cols = [
        "issue_key", "file_path", "file", "rule",
        "severity", "severity_score", "impact_severity", "impact_quality", "type",
        "message", "line", "effort", "debt", "tags", "creationDate", "status",
        "bugs", "vulnerabilities", "code_smells", "violations",
        "blocker_violations", "critical_violations", "major_violations",
        "minor_violations", "info_violations",
        "complexity", "cognitive_complexity", "functions", "duplicated_lines_density",
        "sqale_index", "sqale_debt_ratio", "coverage", "lines",
        "reliability_rating", "security_rating", "sqale_rating",
        "commit_count", "unique_authors", "bus_factor",
        "lines_added", "lines_deleted", "churn",
        "days_since_modified", "file_age_days",
        "satd_count", "satd_text", "satd_types",
        "satd_age_days", "satd_change_count",
        "line_last_modified_days", "line_author",
    ]

    for col in final_cols:
        if col not in issues.columns:
            issues[col] = None

    issues = issues[final_cols]

    # Check for Python-specific SATD schema (ML classifier only).
    # Python repos (3-col SATD: satd_count, satd_text, satd_types)
    # vs Java repos (6-col SATD: satd_{count,text,types,age_days,change_count} from SATDBailiff).
    if "satd_types" not in issues.columns or issues["satd_types"].isna().all():
        log.info("Python repo: satd_types, satd_age_days, satd_change_count set to null (ML classifier path, no lifecycle signals)")
        issues["satd_types"] = None
        issues["satd_age_days"] = None
        issues["satd_change_count"] = None

    # Fill only numeric columns where 0 is a meaningful value.
    # SATD and churn columns are preserved as null when LEFT JOIN finds no match—
    # 0 would incorrectly signal absence of SATD/churn activity.
    # E.g., commit_count=0 means the file genuinely had no commits in the window,
    # but satd_count=0 means either no SATD exists OR no SATD extractor ran.
    numeric_fill_with_zero = [
        "bugs", "vulnerabilities", "code_smells", "violations",
        "blocker_violations", "critical_violations", "major_violations",
        "minor_violations", "info_violations",
        "complexity", "cognitive_complexity", "functions", "duplicated_lines_density",
        "sqale_index", "sqale_debt_ratio", "coverage", "lines",
        "commit_count", "unique_authors", "bus_factor",
        "lines_added", "lines_deleted", "churn",
        "days_since_modified", "file_age_days",
    ]
    for col in numeric_fill_with_zero:
        if col in issues.columns:
            issues[col] = issues[col].fillna(0)

    # SATD and churn columns preserve null (no fill):
    # satd_count, satd_age_days, satd_change_count (remain null if no SATD extractor output)
    # line_last_modified_days (remains null if no blame data available)

    out_path = results_path / "enriched_issues.csv"
    issues.to_csv(out_path, index=False)
    log.info(f"enriched_issues.csv written: {len(issues)} issues")

    # Rebuild ranking_c1.csv from fully-enriched data so the UI has file-level metrics
    # (complexity, coverage, etc.) in the C1 list — the extractor writes a metric-less
    # preliminary version; this overwrites it with the complete enriched columns.
    _rebuild_c1_ranking(results_path, issues)

    return issues


def _rebuild_c1_ranking(results_path: Path, enriched: pd.DataFrame) -> None:
    # sonarqube_issues.csv was fetched with s=SEVERITY&asc=false so it already carries
    # SonarQube's exact ordering. enriched_issues.csv preserves that order via LEFT JOINs
    # (pandas merge with how="left" keeps the left-frame order). Just re-assign rank numbers.
    df = enriched.copy().reset_index(drop=True)
    df["c1_rank"] = df.index + 1
    df.to_csv(results_path / "ranking_c1.csv", index=False)
    log.info(f"ranking_c1.csv rebuilt from enriched data: {len(df)} issues")


def write_run_summary(project_id: str, config: dict, results: dict, start_time: float) -> None:
    elapsed = time.time() - start_time
    path = RESULTS_DIR / project_id / "run_summary.txt"
    tp = config.get("time_period", {})
    start_date = tp.get("start_date") or "(none)"
    end_date = tp.get("end_date") or "(none)"
    lines = [
        f"Run summary: {project_id}",
        f"Timestamp:   {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"Duration:    {elapsed:.1f}s",
        f"Time window: {start_date} → {end_date}",
        "",
        "Component results:",
    ]
    for component, status in results.items():
        lines.append(f"  {component:<20} {status}")
    lines.append("")

    def _csv_len(p: Path) -> str:
        try:
            return str(len(pd.read_csv(p)))
        except Exception:
            return "0"

    issues_csv = RESULTS_DIR / project_id / "sonarqube_issues.csv"
    if issues_csv.exists():
        lines.append(f"Issues extracted: {_csv_len(issues_csv)}")

    enriched_csv = RESULTS_DIR / project_id / "enriched_issues.csv"
    if enriched_csv.exists():
        lines.append(f"Enriched issues: {_csv_len(enriched_csv)}")

    for cond in ("c1", "c2", "c3"):
        r = RESULTS_DIR / project_id / f"ranking_{cond}.csv"
        if r.exists():
            lines.append(f"ranking_{cond}.csv: {_csv_len(r)} issues ranked")

    path.write_text("\n".join(lines) + "\n")
    log.info(f"run_summary.txt written to {path}")


def discover_projects() -> list[str]:
    return [
        Path(f).stem
        for f in glob.glob(str(PROJECTS_DIR / "*.yaml"))
        if Path(f).stem != "project_template"
    ]


def run_project(
    project_id: str,
    skip_sonarqube: bool = False,
    skip_github: bool = False,
    skip_satd: bool = False,
    skip_llm: bool = False,
) -> None:
    start = time.time()
    log.info(f"=== Starting project: {project_id} ===")

    config = load_config(project_id)
    config["project_id"] = project_id   # passed to extractors for per-project artefact naming
    validate_api_keys(config, skip_sonarqube, skip_github, skip_satd, skip_llm)

    results_path = RESULTS_DIR / project_id
    results_path.mkdir(parents=True, exist_ok=True)

    component_results = {}

    # Step 1: SonarQube
    if not skip_sonarqube and config["components"].get("run_sonarqube"):
        try:
            from components.sonarqube_extractor import SonarQubeExtractor
            extractor = SonarQubeExtractor(config, results_path)
            extractor.run()
            component_results["sonarqube"] = "OK"
        except Exception as e:
            log.error(f"SonarQube extractor failed: {e}")
            component_results["sonarqube"] = f"FAILED: {e}"
    else:
        component_results["sonarqube"] = "SKIPPED"

    # Step 2: GitHub churn
    if not skip_github and config["components"].get("run_github_churn"):
        try:
            from components.github_extractor import GitHubExtractor
            extractor = GitHubExtractor(config, results_path)
            extractor.run()
            component_results["github"] = "OK"
        except Exception as e:
            log.error(f"GitHub extractor failed: {e}")
            component_results["github"] = f"FAILED: {e}"
    else:
        component_results["github"] = "SKIPPED"

    # Step 3: SATDBailiff
    if not skip_satd and config["components"].get("run_satd"):
        try:
            from components.satd_extractor import SATDExtractor
            extractor = SATDExtractor(config, results_path)
            satd_method = extractor.run()
            component_results["satd"] = f"OK ({satd_method})"
        except Exception as e:
            log.error(f"SATD extractor failed: {e}")
            component_results["satd"] = f"FAILED: {e}"
    else:
        component_results["satd"] = "SKIPPED"

    # Step 4: Enrich issues
    try:
        enrich_issues(project_id)
        component_results["enrich"] = "OK"
    except Exception as e:
        log.error(f"enrich_issues failed: {e}")
        component_results["enrich"] = f"FAILED: {e}"

    # Step 5: LLM ranking
    if not skip_llm and config["components"].get("run_llm_ranking"):
        try:
            from components.llm_ranker import LLMRanker
            ranker = LLMRanker(config, results_path)
            ranker.run()
            component_results["llm"] = "OK"
        except Exception as e:
            log.error(f"LLM ranker failed: {e}")
            component_results["llm"] = f"FAILED: {e}"
    else:
        component_results["llm"] = "SKIPPED"

    write_run_summary(project_id, config, component_results, start)
    log.info(f"=== Done: {project_id} ({time.time() - start:.1f}s) ===")


def run_ui(project_ids: list[str], port: int = None) -> None:
    from ui.app import create_app
    config_path = BASE_DIR / "config.yaml"
    with open(config_path) as f:
        global_config = yaml.safe_load(f)
    ui_port = port or global_config["defaults"]["ui"]["port"]
    app = create_app(RESULTS_DIR, project_ids)
    log.info(f"Starting UI on http://localhost:{ui_port}")
    app.run(host="0.0.0.0", port=ui_port, debug=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="Thesis pipeline: LLM-based SonarQube issue prioritisation")
    parser.add_argument("--project", action="append", dest="projects", metavar="PROJECT_ID",
                        help="Project ID to run (can be repeated)")
    parser.add_argument("--all", action="store_true", help="Run all configured projects")
    parser.add_argument("--skip-sonarqube", action="store_true")
    parser.add_argument("--skip-github", action="store_true")
    parser.add_argument("--skip-satd", action="store_true")
    parser.add_argument("--skip-llm", action="store_true")
    parser.add_argument("--ui-only", action="store_true", help="Start UI without running pipeline")
    parser.add_argument("--ui", action="store_true", help="Run pipeline then start UI")
    parser.add_argument("--port", type=int, help="UI port (overrides config)")
    args = parser.parse_args()

    if args.all:
        project_ids = discover_projects()
        if not project_ids:
            log.error("No project configs found in projects/")
            sys.exit(1)
    elif args.projects:
        project_ids = args.projects
    elif args.ui_only:
        project_ids = discover_projects()
    else:
        parser.print_help()
        sys.exit(0)

    if args.ui_only:
        run_ui(project_ids, args.port)
        return

    for project_id in project_ids:
        run_project(
            project_id,
            skip_sonarqube=args.skip_sonarqube,
            skip_github=args.skip_github,
            skip_satd=args.skip_satd,
            skip_llm=args.skip_llm,
        )

    if args.ui:
        run_ui(project_ids, args.port)


if __name__ == "__main__":
    main()
