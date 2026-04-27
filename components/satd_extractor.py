"""
Extracts self-admitted technical debt comments for each source file.

Input:  Project config (GitHub repo, time_period), sonarqube_issues.csv (file list)
Output: results/{project_id}/satd_comments.csv
        results/{project_id}/satd_method.txt

Detection strategy (tried in order):
1. satd_detector.jar ML classifier (tools/satd_detector.jar) via stdin — most accurate,
   no MySQL or Docker needed, just Java and the JAR.
2. SATDBailiff Docker image — if Docker is available and the image can be pulled.
3. SATDBailiff full JAR + MySQL — if tools/SATDBailiff.jar and MySQL are configured.
4. Keyword-based via GitHub API — built-in fallback requiring only a GitHub token.
5. Empty CSV — if no method is available.

Design decisions:
- ML classifier (satd_detector.jar) reads one comment per line from stdin and writes
  ">SATD" or ">Not SATD" per line to stdout. We batch ALL comments from all files in
  one subprocess call, then map results back to files by position.
- SATD type (DEFECT vs DESIGN) is determined by keyword patterns applied only to
  comments already classified as SATD by the ML model — higher precision than applying
  keywords to all text.
- Docker image availability checked with a 30s pull timeout; if unavailable, Docker
  is skipped immediately rather than waiting 10 minutes for docker run to time out.
- Keyword patterns based on Potdar & Shihab (2014) and Maldonado & Shihab (2015).
"""

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

# Comment-line extraction: strips //, /*, *, # markers and returns inner text
COMMENT_LINE_RE = re.compile(r"^\s*(?://+|/\*+|\*+|#)\s*(.+)$")

# Applied to confirmed SATD text to determine type (DEFECT vs DESIGN)
DEFECT_RE = re.compile(
    r"\b(fixme|fix me|bug[:\s]|broken|workaround|kludge|hack[:\s]|xxx[:\s])\b",
    re.IGNORECASE,
)
DESIGN_RE = re.compile(
    r"\b(todo|to[- ]do|refactor|redesign|temp[:\s]|temporary|pending|review later|"
    r"clean[- ]?up|remove this|should be|needs? to be|must be|revisit|"
    r"this is wrong|not ideal|better approach)\b",
    re.IGNORECASE,
)


def _extract_all_comments(content: str) -> list[str]:
    """Extract all comment lines from source file, stripping syntax markers."""
    comments = []
    for line in content.splitlines():
        m = COMMENT_LINE_RE.match(line)
        if m:
            text = m.group(1).strip()
            if len(text) > 3:  # skip trivial markers like "---" or "..."
                comments.append(text)
    return comments


def _classify_satd_type(text: str) -> tuple[bool, bool]:
    """Return (has_defect_satd, has_design_satd) for a confirmed SATD comment."""
    return bool(DEFECT_RE.search(text)), bool(DESIGN_RE.search(text))


class SATDExtractor:
    def __init__(self, config: dict, results_path: Path):
        self.config = config
        self.results_path = results_path
        gh = config.get("github", {})
        self.repo_owner = gh.get("repo_owner", "")
        self.repo_name = gh.get("repo_name", "")
        tp = config.get("time_period", {})
        self.end_date = tp.get("end_date", "")
        self.github_token = os.getenv("GITHUB_TOKEN", "")
        project_id = config.get("project_id", "project")
        self.repos_file = results_path / f"repos_{project_id}.txt"
        self.db_props_file = results_path / f"db_{project_id}.properties"
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

    def _resolve_end_date_commit(self) -> str:
        branch = self.config.get("github", {}).get("branch", "master")
        try:
            resp = self._github_session().get(
                f"https://api.github.com/repos/{self.repo_owner}/{self.repo_name}/commits",
                params={"sha": branch, "until": self.end_date + "T00:00:00Z", "per_page": 1},
                timeout=30,
            )
            if resp.status_code == 200 and resp.json():
                return resp.json()[0]["sha"]
        except Exception as e:
            log.warning(f"Could not resolve end_date commit: {e}")
        log.warning("Falling back to HEAD for end_date commit")
        return "HEAD"

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
        file_comment_counts: dict[str, int] = {}  # file_path → how many comments it contributed

        for i, fp in enumerate(file_paths, 1):
            if i % 50 == 0:
                log.info(f"  [{i}/{len(file_paths)}] fetching comments...")
            content = self._fetch_file_content(fp, commit_ref)
            if content is None:
                continue
            comments = _extract_all_comments(content)
            if not comments:
                continue
            start_idx = len(all_comments)
            # Replace newlines within a comment so stdin line protocol stays intact
            cleaned = [c.replace("\n", " ").replace("\r", "") for c in comments]
            all_comments.extend((fp, c) for c in cleaned)
            file_comment_counts[fp] = len(cleaned)

        if not all_comments:
            log.warning("No comments found in any file — skipping ML classifier")
            return None

        log.info(f"ML classifier: running on {len(all_comments)} comments...")
        stdin_text = "\n".join(c for _, c in all_comments) + "\n"

        try:
            result = subprocess.run(
                [java_bin, "-jar", str(jar), "test"],
                input=stdin_text,
                capture_output=True,
                text=True,
                timeout=300,
            )
            # Exit code is always 1 (NullPointerException on EOF) — ignore it, use stdout.
            # Classifier may emit one extra classification for the trailing newline in stdin;
            # take exactly as many outputs as there are inputs.
            all_output = [l.strip() for l in result.stdout.splitlines() if l.strip()]
            output_lines = all_output[:len(all_comments)]
        except subprocess.TimeoutExpired:
            log.warning("ML classifier timed out after 300s")
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

        rows = []
        for fp, satd_texts in file_satd.items():
            has_defect = any(_classify_satd_type(t)[0] for t in satd_texts)
            has_design = any(_classify_satd_type(t)[1] for t in satd_texts)
            # Determine type label (fallback to DESIGN if no keyword match — ML confirmed it's SATD)
            types = set()
            for t in satd_texts:
                d, g = _classify_satd_type(t)
                if d:
                    types.add("DEFECT")
                if g:
                    types.add("DESIGN")
            if not types:
                types.add("DESIGN")  # untyped SATD defaults to DESIGN
            rows.append({
                "file_path": fp,
                "satd_count": len(satd_texts),
                "satd_text": " | ".join(satd_texts[:10]),  # cap at 10 for CSV readability
                "satd_types": ",".join(sorted(types)),
                "has_defect_satd": has_defect,
                "has_design_satd": has_design,
            })

        df = pd.DataFrame(rows) if rows else self._empty_df()
        log.info(f"ML classifier done: {len(df)} files with SATD identified")
        return df

    # ------------------------------------------------------------------ #
    #  Path 2: SATDBailiff Docker                                         #
    # ------------------------------------------------------------------ #

    def _docker_image_available(self) -> bool:
        """Pull-check with 30s timeout — avoids a 10-minute hang when image is unavailable."""
        try:
            result = subprocess.run(
                ["docker", "pull", "smilevo/satdbailiff"],
                capture_output=True, text=True, timeout=30,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _write_repos_file(self, commit_hash: str) -> None:
        self.repos_file.write_text(
            f"https://github.com/{self.repo_owner}/{self.repo_name},{commit_hash}\n"
        )

    def _write_db_properties(self) -> None:
        self.db_props_file.write_text(
            f"url=jdbc:mysql://{os.getenv('MYSQL_HOST','localhost')}:"
            f"{os.getenv('MYSQL_PORT','3306')}/{os.getenv('MYSQL_DATABASE','satd')}\n"
            f"user={os.getenv('MYSQL_USER','root')}\n"
            f"password={os.getenv('MYSQL_PASSWORD','')}\n"
        )

    def _run_docker(self) -> bool:
        if not self._docker_image_available():
            log.warning("SATDBailiff Docker image unavailable — skipping")
            return False
        log.info("Running SATDBailiff via Docker...")
        try:
            result = subprocess.run(
                ["docker", "run", "--rm",
                 "-e", f"GITHUB_TOKEN={self.github_token}",
                 "-v", f"{self.results_path}:/output",
                 "smilevo/satdbailiff",
                 "-r", f"/output/{self.repos_file.name}",
                 "-d", f"/output/{self.db_props_file.name}"],
                capture_output=True, text=True, timeout=600,
            )
            if result.returncode == 0:
                log.info("SATDBailiff Docker run succeeded")
                return True
            log.warning(f"SATDBailiff Docker failed: {result.stderr[:300]}")
        except subprocess.TimeoutExpired:
            log.warning("SATDBailiff Docker timed out after 600s")
        return False

    # ------------------------------------------------------------------ #
    #  Path 3: SATDBailiff full JAR + MySQL                               #
    # ------------------------------------------------------------------ #

    def _find_satdbailiff_jar(self) -> Path | None:
        tools = Path(__file__).parent.parent / "tools"
        for name in ["SATDBailiff.jar"]:
            p = tools / name
            if p.exists():
                return p
        matches = list(tools.glob("SATDBailiff-*.jar"))
        return matches[0] if matches else None

    def _run_bailiff_jar(self) -> bool:
        jar = self._find_satdbailiff_jar()
        java_bin = shutil.which("java")
        if not jar or not java_bin:
            return False
        log.info(f"Running SATDBailiff JAR ({jar.name})...")
        try:
            result = subprocess.run(
                [java_bin, "-jar", str(jar), "-r", str(self.repos_file), "-d", str(self.db_props_file)],
                capture_output=True, text=True, timeout=600,
            )
            if result.returncode == 0:
                log.info("SATDBailiff JAR run succeeded")
                return True
            log.warning(f"SATDBailiff JAR failed: {result.stderr[:300]}")
        except subprocess.TimeoutExpired:
            log.warning("SATDBailiff JAR timed out after 600s")
        return False

    def _query_mysql(self) -> pd.DataFrame:
        import mysql.connector
        cnx = mysql.connector.connect(
            host=os.getenv("MYSQL_HOST", "localhost"),
            port=int(os.getenv("MYSQL_PORT", "3306")),
            user=os.getenv("MYSQL_USER", "root"),
            password=os.getenv("MYSQL_PASSWORD", ""),
            database=os.getenv("MYSQL_DATABASE", "satd"),
        )
        cursor = cnx.cursor(dictionary=True)
        cursor.execute("""
            SELECT file_path,
                   COUNT(*) AS satd_count,
                   GROUP_CONCAT(satd_instance_comment SEPARATOR ' | ') AS satd_text,
                   GROUP_CONCAT(DISTINCT satd_type SEPARATOR ',') AS satd_types,
                   MAX(CASE WHEN satd_type LIKE '%DEFECT%' THEN 1 ELSE 0 END) AS has_defect_satd,
                   MAX(CASE WHEN satd_type LIKE '%DESIGN%' THEN 1 ELSE 0 END) AS has_design_satd
            FROM satd_instance
            WHERE (date_removed IS NULL OR date_removed > %s)
              AND url LIKE %s
            GROUP BY file_path
        """, (self.end_date, f"%{self.repo_owner}/{self.repo_name}%"))
        rows = cursor.fetchall()
        cursor.close()
        cnx.close()
        df = pd.DataFrame(rows) if rows else self._empty_df()
        if not df.empty:
            df["has_defect_satd"] = df["has_defect_satd"].astype(bool)
            df["has_design_satd"] = df["has_design_satd"].astype(bool)
        return df

    # ------------------------------------------------------------------ #
    #  Path 4: Keyword-based via GitHub API                               #
    # ------------------------------------------------------------------ #

    def _extract_satd_keyword(self, file_paths: list[str], commit_ref: str) -> pd.DataFrame:
        log.info(f"Keyword SATD: scanning {len(file_paths)} files...")
        rows = []
        for i, fp in enumerate(file_paths, 1):
            if i % 50 == 0:
                log.info(f"  [{i}/{len(file_paths)}] scanning...")
            content = self._fetch_file_content(fp, commit_ref)
            if not content:
                continue
            hits = []
            for line in content.splitlines():
                m = COMMENT_LINE_RE.match(line)
                if not m:
                    continue
                text = m.group(1).strip()
                is_d = bool(DEFECT_RE.search(text))
                is_g = bool(DESIGN_RE.search(text))
                if is_d or is_g:
                    hits.append({"text": text, "defect": is_d, "design": is_g})
            if hits:
                types = set()
                if any(h["defect"] for h in hits):
                    types.add("DEFECT")
                if any(h["design"] for h in hits):
                    types.add("DESIGN")
                rows.append({
                    "file_path": fp,
                    "satd_count": len(hits),
                    "satd_text": " | ".join(h["text"] for h in hits[:10]),
                    "satd_types": ",".join(sorted(types)),
                    "has_defect_satd": any(h["defect"] for h in hits),
                    "has_design_satd": any(h["design"] for h in hits),
                })
        df = pd.DataFrame(rows) if rows else self._empty_df()
        log.info(f"Keyword SATD done: {len(df)} files with SATD")
        return df

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _empty_df(self) -> pd.DataFrame:
        return pd.DataFrame(columns=[
            "file_path", "satd_count", "satd_text", "satd_types",
            "has_defect_satd", "has_design_satd",
        ])

    def _save(self, df: pd.DataFrame, method: str) -> str:
        df.to_csv(self.results_path / "satd_comments.csv", index=False)
        (self.results_path / "satd_method.txt").write_text(method + "\n")
        log.info(f"SATD method used: {method}")
        return method

    # ------------------------------------------------------------------ #
    #  Main entry point                                                    #
    # ------------------------------------------------------------------ #

    def run(self) -> str:
        """Run SATD extraction. Returns the method name that was used."""
        commit_ref = self._resolve_end_date_commit()
        file_paths = self._get_file_paths()

        # --- Path 1: ML classifier (satd_detector.jar) ---
        if self._find_classifier_jar() and shutil.which("java") and file_paths and self.github_token:
            df = self._run_ml_classifier(file_paths, commit_ref)
            if df is not None:
                return self._save(df, f"satd-detector-jar-ml ({len(df)} files with SATD)")

        # --- Path 2: SATDBailiff Docker ---
        if shutil.which("docker"):
            self._write_repos_file(commit_ref)
            self._write_db_properties()
            if self._run_docker():
                try:
                    df = self._query_mysql()
                    return self._save(df, f"satdbailiff-docker ({len(df)} files)")
                except Exception as e:
                    log.error(f"MySQL query failed after Docker run: {e}")

        # --- Path 3: SATDBailiff full JAR + MySQL ---
        if self._find_satdbailiff_jar() and shutil.which("java"):
            self._write_repos_file(commit_ref)
            self._write_db_properties()
            if self._run_bailiff_jar():
                try:
                    df = self._query_mysql()
                    return self._save(df, f"satdbailiff-jar ({len(df)} files)")
                except Exception as e:
                    log.error(f"MySQL query failed after JAR run: {e}")

        # --- Path 4: Keyword-based via GitHub API ---
        if file_paths and self.github_token:
            log.info("Falling back to keyword-based SATD detection")
            df = self._extract_satd_keyword(file_paths, commit_ref)
            return self._save(df, f"keyword-github-api ({len(df)} files with SATD)")

        # --- Path 5: Empty ---
        log.warning("No SATD extraction method available — SATD fields will be empty in C3")
        return self._save(self._empty_df(), "empty (no method available)")
