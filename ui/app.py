"""
Flask UI for the thesis pipeline interview tool.

Neutral presentation: no AI, LLM, algorithm, or condition labels visible to participants.
Lists are shown as "List 1", "List 2", "List 3". Reasoning shown as "Analysis notes:".
List-to-condition mapping is stable per project (seeded from project_id) and documented
in a hidden HTML comment.
"""

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

import pandas as pd
import yaml
from flask import Flask, jsonify, redirect, render_template, url_for


def _condition_rotation(project_id: str) -> dict[str, str]:
    """
    Derive a stable, project-specific mapping from condition (c1/c2/c3) to list number (1/2/3).
    The mapping is deterministic: same project_id always yields the same rotation.
    """
    seed = int(hashlib.md5(project_id.encode()).hexdigest()[:8], 16)
    conditions = ["c1", "c2", "c3"]
    rotated = conditions[seed % 3:] + conditions[:seed % 3]
    return {cond: f"List {i + 1}" for i, cond in enumerate(rotated)}


def _rotation_comment(mapping: dict[str, str]) -> str:
    parts = [f"{cond.upper()}={label}" for cond, label in mapping.items()]
    return f"<!-- {', '.join(parts)} -->"


def _load_ranking(results_path: Path, condition: str) -> pd.DataFrame:
    path = results_path / f"ranking_{condition}.csv"
    if path.exists():
        return pd.read_csv(path)
    return pd.DataFrame()


def _issue_age_days(creation_date_str: str) -> int:
    if not creation_date_str or pd.isna(creation_date_str):
        return 0
    try:
        dt = datetime.fromisoformat(str(creation_date_str).replace("Z", "+00:00"))
        return (datetime.now(dt.tzinfo) - dt).days
    except Exception:
        return 0


def _df_to_issue_list(df: pd.DataFrame, rank_col: str, reasoning_col: bool = True) -> list[dict]:
    issues = []
    for _, row in df.iterrows():
        issue = {
            "issue_key": str(row.get("issue_key", "")),
            "severity": str(row.get("llm_severity" if reasoning_col else "severity", "MAJOR")),
            "type": str(row.get("llm_type" if reasoning_col else "type", "CODE_SMELL")),
            "message": str(row.get("message", "")),
            "file": str(row.get("file", "")),
            "file_path": str(row.get("file_path", "")),
            "rule": str(row.get("rule", "")),
            "line": int(row["line"]) if pd.notna(row.get("line")) else None,
            "effort": str(row.get("effort", "") or ""),
            "age_days": _issue_age_days(row.get("creationDate", "")),
            "rank": int(row.get(rank_col, 0)),
            "reasoning": str(row.get("llm_reasoning", "") or "") if reasoning_col else "",
            "file_complexity": int(row.get("complexity", 0) or 0),
            "file_cognitive_complexity": int(row.get("cognitive_complexity", 0) or 0),
            "file_coverage": round(float(row.get("coverage", 0) or 0), 1),
            "file_bugs": int(row.get("bugs", 0) or 0),
        }
        issues.append(issue)
    return issues


def create_app(results_dir: Path, project_ids: list[str] = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.results_dir = results_dir

    if project_ids is None:
        project_ids = [
            d.name for d in results_dir.iterdir()
            if d.is_dir() and (d / "sonarqube_issues.csv").exists()
        ]

    app.project_ids = project_ids

    @app.route("/")
    def index():
        if len(app.project_ids) == 1:
            return redirect(url_for("issues", project_id=app.project_ids[0]))
        return render_template("index.html", projects=app.project_ids)

    @app.route("/issues/<project_id>")
    def issues(project_id: str):
        if project_id not in app.project_ids:
            return "Project not found", 404

        rotation = _condition_rotation(project_id)
        rotation_comment = _rotation_comment(rotation)

        results_path = results_dir / project_id

        c1 = _load_ranking(results_path, "c1")
        c2 = _load_ranking(results_path, "c2")
        c3 = _load_ranking(results_path, "c3")

        counts = {
            "c1": len(c1),
            "c2": len(c2),
            "c3": len(c3),
        }

        list_labels = {}
        for cond, label in rotation.items():
            list_labels[label] = cond

        ordered_lists = sorted(rotation.items(), key=lambda x: x[1])

        return render_template(
            "issues.html",
            project_id=project_id,
            rotation=rotation,
            rotation_comment=rotation_comment,
            ordered_lists=ordered_lists,
            counts=counts,
        )

    @app.route("/api/rankings/<project_id>")
    def api_rankings(project_id: str):
        if project_id not in app.project_ids:
            return jsonify({"error": "Project not found"}), 404

        results_path = results_dir / project_id
        rotation = _condition_rotation(project_id)

        c1 = _load_ranking(results_path, "c1")
        c2 = _load_ranking(results_path, "c2")
        c3 = _load_ranking(results_path, "c3")

        data = {}

        if not c1.empty:
            data["c1"] = _df_to_issue_list(c1.sort_values("c1_rank"), "c1_rank", reasoning_col=False)
        else:
            data["c1"] = []

        if not c2.empty:
            data["c2"] = _df_to_issue_list(c2.sort_values("c2_rank"), "c2_rank", reasoning_col=True)
        else:
            data["c2"] = []

        if not c3.empty:
            data["c3"] = _df_to_issue_list(c3.sort_values("c3_rank"), "c3_rank", reasoning_col=True)
        else:
            data["c3"] = []

        return jsonify({
            "project_id": project_id,
            "rotation": rotation,
            "rankings": data,
        })

    @app.route("/health")
    def health():
        return jsonify({"status": "ok"})

    return app
