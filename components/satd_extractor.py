import base64
import logging
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import pandas as pd
import requests

log = logging.getLogger(__name__)

# Comment-line extraction: strips //, /*, *, # markers and returns inner text.
# All extracted comments are passed directly to the ML classifier — pre-filtering
# risks silently dropping SATD that the classifier would correctly identify.
COMMENT_LINE_RE = re.compile(r"^\s*(?://+|/\*+|\*+|#)\s*(.+)$")


def _extract_all_comments(content: str) -> list[str]:
    """
    Extract comment lines from source file, stripping syntax markers.
    
    Empty strings after stripping are excluded to preserve stdin line protocol integrity;
    all other comment text is passed to the classifier without filtering.
    """
    comments = []
    for line in content.splitlines():
        m = COMMENT_LINE_RE.match(line)
        if not m:
            continue
        text = m.group(1).strip()
        if not text:  # skip empty lines after stripping
            continue
        comments.append(text)
    return comments


class SATDExtractor:
    def __init__(self, config: dict, results_path: Path):
        self.config = config
        self.results_path = results_path
        gh = config.get("github", {})
        self.repo_owner = gh.get("repo_owner", "")
        self.repo_name = gh.get("repo_name", "")
        self.language = config.get("language", "java").lower()
        self.github_token = os.getenv("GITHUB_TOKEN", "")
        self._session: requests.Session | None = None

    # ------------------------------------------------------------------ #
    #  GitHub API helpers                                                  #
    # ------------------------------------------------------------------ #

    def _github_session(self) -> requests.Session:
        if self._session is None:
            s = requests.Session()
            s.headers["Accept"] = "application/vnd.github.v3+json"
            if self.github_token:
                s.headers["Authorization"] = f"token {self.github_token}"
            self._session = s
        return self._session

    def _fetch_file_content(self, file_path: str, ref: str) -> str | None:
        session = self._github_session()
        try:
            resp = session.get(
                f"https://api.github.com/repos/{self.repo_owner}/{self.repo_name}/contents/{file_path}",
                params={"ref": ref},
                timeout=20,
            )
            remaining = int(resp.headers.get("X-RateLimit-Remaining", 100))
            if remaining < 10:
                reset_ts = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
                sleep_secs = max(reset_ts - int(time.time()), 1)
                log.warning(f"GitHub rate limit low ({remaining} remaining). Sleeping {sleep_secs}s...")
                time.sleep(sleep_secs)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("encoding") == "base64":
                    return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            elif resp.status_code != 404:
                log.debug(f"GitHub {resp.status_code} for {file_path}")
        except Exception as e:
            log.debug(f"Error fetching {file_path}: {e}")
        return None

    def _get_file_paths(self) -> list[str]:
        issues_path = self.results_path / "sonarqube_issues.csv"
        if issues_path.exists():
            return pd.read_csv(issues_path)["file_path"].dropna().unique().tolist()
        return []

    # ------------------------------------------------------------------ #
    #  Path 1: satd_detector.jar ML classifier                            #
    # ------------------------------------------------------------------ #

    def _find_classifier_jar(self) -> Path | None:
        tools = Path(__file__).parent.parent / "tools"
        for name in ["satd_detector.jar", "satd-detector.jar"]:
            p = tools / name
            if p.exists():
                return p
        return None

    def _run_ml_classifier(self, file_paths: list[str], commit_ref: str) -> pd.DataFrame | None:
        """
        Fetch all comments from GitHub, classify them with satd_detector.jar in one
        subprocess call (one comment per stdin line → one ">SATD"/">Not SATD" per stdout line),
        then aggregate results per file.
        """
        jar = self._find_classifier_jar()
        java_bin = shutil.which("java")
        if not jar or not java_bin:
            return None

        log.info(f"ML classifier: fetching comments from {len(file_paths)} files...")

        # Collect (file_path, comment_text) pairs
        all_comments: list[tuple[str, str]] = []

        for i, fp in enumerate(file_paths, 1):
            if i % 50 == 0:
                log.info(f"  [{i}/{len(file_paths)}] fetching comments...")
            content = self._fetch_file_content(fp, commit_ref)
            if content is None:
                continue
            comments = _extract_all_comments(content)
            if not comments:
                continue
            # Replace newlines within a comment so stdin line protocol stays intact
            cleaned = [c.replace("\n", " ").replace("\r", "") for c in comments]
            all_comments.extend((fp, c) for c in cleaned)

        if not all_comments:
            log.warning("No comments found in any file — skipping ML classifier")
            return self._empty_df()

        ml_timeout = int(os.getenv("SATD_ML_TIMEOUT", "1800"))
        log.info(f"ML classifier: running on {len(all_comments)} comments (timeout={ml_timeout}s)...")
        stdin_text = "\n".join(c for _, c in all_comments) + "\n"

        try:
            result = subprocess.run(
                [java_bin, "-jar", str(jar), "test"],
                input=stdin_text,
                capture_output=True,
                text=True,
                timeout=ml_timeout,
            )
            # Exit code is always 1 (NullPointerException on EOF) — ignore it, use stdout.
            # Classifier may emit one extra classification for the trailing newline in stdin;
            # take exactly as many outputs as there are inputs.
            all_output = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            output_lines = all_output[:len(all_comments)]
        except subprocess.TimeoutExpired:
            log.warning(f"ML classifier timed out after {ml_timeout}s — set SATD_ML_TIMEOUT to a higher value")
            return None
        except Exception as e:
            log.warning(f"ML classifier failed: {e}")
            return None

        if len(output_lines) < len(all_comments):
            log.warning(
                f"ML classifier output too short: {len(output_lines)} outputs for "
                f"{len(all_comments)} comments — falling through to next method"
            )
            return None

        # Aggregate per file
        file_satd: dict[str, list[str]] = {}
        for (fp, comment_text), label in zip(all_comments, output_lines):
            if label == ">SATD":
                file_satd.setdefault(fp, []).append(comment_text)

        # Robustness check: if no SATD found despite having comments, warn about possible JAR format mismatch
        if not file_satd and all_comments:
            log.warning(
                f"ML classifier produced no '>SATD' labels despite {len(all_comments)} comments. "
                f"Possible JAR format mismatch or configuration issue — verify satd_detector.jar "
                f"version and output format."
            )

        rows = []
        for fp, satd_texts in file_satd.items():
            if len(satd_texts) > 20:
                log.warning(
                    f"satd_text capped at 20 comments for {fp} ({len(satd_texts)} total SATD instances) — "
                    f"full count preserved in satd_count"
                )
            rows.append({
                "file_path": fp,
                "satd_count": len(satd_texts),
                "satd_text": " | ".join(satd_texts[:20]),  # cap at 20 for CSV readability
            })

        df = pd.DataFrame(rows) if rows else self._empty_df()
        log.info(f"ML classifier done: {len(df)} files with SATD identified")
        return df

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _empty_df(self) -> pd.DataFrame:
        """Return empty DataFrame with ML classifier schema (3 columns: file_path, satd_count, satd_text)."""
        return pd.DataFrame(columns=[
            "file_path", "satd_count", "satd_text",
        ])

    def _save(self, df: pd.DataFrame, method: str) -> str:
        df.to_csv(self.results_path / "satd_comments.csv", index=False)
        (self.results_path / "satd_method.txt").write_text(method + "\n")
        log.info(f"SATD method used: {method}")
        
        # Verify output schema matches expected set for the detected method
        # ML classifier path: file_path, satd_count, satd_text (3 columns)
        # SATDBailiff path: file_path, satd_count, satd_text, satd_age_days, satd_change_count (5 columns)
        if "satd_age_days" in df.columns:
            # SATDBailiff path (Java)
            expected_columns = {
                "file_path", "satd_count", "satd_text",
                "satd_age_days", "satd_change_count",
            }
        else:
            # ML classifier path (Python repos) or empty fallback
            expected_columns = {"file_path", "satd_count", "satd_text"}
        
        actual_columns = set(df.columns)
        if actual_columns != expected_columns:
            extra = actual_columns - expected_columns
            missing = expected_columns - actual_columns
            raise ValueError(
                f"Output schema mismatch: expected={expected_columns}, "
                f"actual={actual_columns}, extra={extra}, missing={missing}"
            )
        
        log.info(f"✓ SATD schema verified: {len(df.columns)} columns {sorted(df.columns)}")
        return method

    # ------------------------------------------------------------------ #
    #  Main entry point                                                    #
    # ------------------------------------------------------------------ #

    def run(self) -> str:
        """Run SATD extraction. Returns the method name that was used.

        The pipeline uses the ML classifier (Ren et al. 2019) for both Java and
        Python repositories. SATDBailiff (Ren et al. 2021) was previously used for
        Java repos for its lifecycle tracking, but for long-lived projects with
        significant historical restructuring (e.g., Hibernate ORM), it reports SATD
        against historical file paths that no longer intersect with the current
        SonarQube alert pool. The ML classifier reads current HEAD comments and
        produces SATD signal aligned with current paths, giving symmetric Java/Python
        behavior. Only satd_count and satd_text reach the LLM regardless of detection
        method, so SATDBailiff's extra lifecycle fields were not used downstream.
        """
        commit_ref = "HEAD"
        file_paths = self._get_file_paths()

        # --- ML classifier (used for all languages) ---
        if self._find_classifier_jar() and shutil.which("java") and file_paths and self.github_token:
            df = self._run_ml_classifier(file_paths, commit_ref)
            if df is not None and not df.empty:
                return self._save(df, f"satd-detector-jar-ml ({len(df)} files with SATD)")
            elif df is not None:
                log.info(f"ML classifier output columns: {list(df.columns)}")
                log.info("ML classifier found no SATD — falling through to empty")

        # --- Empty fallback ---
        log.warning("No ML classifier available — SATD will be empty for this repo. Verify satd_detector.jar is in tools/")
        empty_df = self._empty_df()
        return self._save(empty_df, "empty (no method available)")
