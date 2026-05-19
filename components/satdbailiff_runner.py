"""
Runs SATDBailiff (AlOmar et al., 2021/2022) to mine and track SATD from a GitHub repository's history.

SATDBailiff is a Java tool for mining and tracking Self-Admitted Technical Debt
(SATD) instances in Java repositories. It uses JGit to traverse repository history,
JavaParser to extract source-code comments, and Liu et al.'s SATD Detector for
binary classification of comments as SATD or non-SATD.

This wrapper executes the official SATDBailiff JAR, provides the required MySQL
backend, and queries the resulting database to extract SATD instances that remain
active at the analysed terminal commit.

Pipeline
--------
1. Download satd-analyzer-jar-with-all-dependencies.jar (~40 MB) once and cache it in tools/
2. Start a temporary MySQL 8 container on SATD_MYSQL_PORT (default 3307)
3. Write repos.csv  (GitHub URL, terminal commit) and db.properties for SATDBailiff
4. Run SATDBailiff JAR — clones repo via JGit, walks history, writes lifecycle to MySQL
5. Query active SATD (SATD_ADDED with no subsequent SATD_REMOVED/FILE_REMOVED) per file path
6. Map to schema: file_path, satd_count, satd_text, satd_age_days, satd_change_count
7. Remove MySQL container regardless of outcome

Requirements
------------
- Java 11+ on PATH  (java command)
- Docker on PATH    (docker command; used only for the MySQL container)
- GITHUB_TOKEN env  (required for private repos; avoids rate-limiting on public repos)
- GITHUB_USER env   (GitHub username tied to the token; falls back to "token" if unset)
- mysql-connector-python pip package (already in requirements.txt)
- SATD_MYSQL_PORT   env (optional; default 3307 to avoid clashing with any local MySQL)

Note on SATDBailiff detection
------------------------------
SATDBailiff uses Liu et al.'s SATD Detector for binary classification of Java
comments as SATD or non-SATD. SATDBailiff's main contribution is not only SATD
detection, but lifecycle tracking: it records additions, removals, changes, file
path changes, and class/method changes to SATD instances across Git history.

Reference: https://github.com/smilevo/SATDBailiff/releases/tag/1.2
"""

import logging
import os
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

import pandas as pd

log = logging.getLogger(__name__)

_JAR_URL = (
    "https://github.com/smilevo/SATDBailiff/releases/download/1.2/"
    "satd-analyzer-jar-with-all-dependencies.jar"
)
_JAR_NAME = "satd-analyzer-jar-with-all-dependencies.jar"

# MySQL 8 container — isolated from any local MySQL.
# We force mysql_native_password because SATDBailiff bundles JDBC Connector/J 5.x,
# which does not support MySQL 8's default caching_sha2_password authentication.
_MYSQL_IMAGE = "mysql:8"
_MYSQL_DB = "satd"
_MYSQL_USER = "satduser"
_MYSQL_PASS = "SATDpass123!"
_MYSQL_ROOT_PASS = "SATDroot123!"


class SATDBailiffRunner:
    def __init__(self, config: dict, results_path: Path):
        self.config = config
        self.results_path = results_path
        self.tools_path = Path(__file__).parent.parent / "tools"
        gh = config.get("github", {})
        self.repo_owner = gh.get("repo_owner", "")
        self.repo_name = gh.get("repo_name", "")
        self.github_token = os.getenv("GITHUB_TOKEN", "")
        self.github_user = os.getenv("GITHUB_USER", "")
        self.mysql_port = int(os.getenv("SATD_MYSQL_PORT", "3307"))
        # Sanitise project_id so it's safe in a Docker container name
        project_id = str(config.get("project_id", "project")).replace("/", "-").replace("_", "-")
        self.container_name = f"satdbailiff-mysql-{project_id}"
        self._mysql_started = False

    # ------------------------------------------------------------------ #
    #  Prerequisites                                                       #
    # ------------------------------------------------------------------ #

    def available(self) -> bool:
        """True if Java, Docker, and mysql-connector-python are all present."""
        if not shutil.which("java"):
            return False
        if not shutil.which("docker"):
            return False
        try:
            import mysql.connector  # noqa: F401
            return True
        except ImportError:
            return False

    # ------------------------------------------------------------------ #
    #  JAR management                                                      #
    # ------------------------------------------------------------------ #

    def _find_or_download_jar(self) -> Path | None:
        jar_path = self.tools_path / _JAR_NAME
        if jar_path.exists():
            log.info(f"SATDBailiff JAR found: {jar_path}")
            return jar_path

        log.info("Downloading SATDBailiff JAR (~40 MB) from GitHub releases ...")
        reported: set[int] = set()

        def _progress(block_num: int, block_size: int, total_size: int) -> None:
            if total_size > 0:
                pct = min(100, block_num * block_size * 100 // total_size)
                milestone = (pct // 25) * 25
                if milestone not in reported and pct >= milestone:
                    reported.add(milestone)
                    log.info(f"  Download: {milestone}%")

        try:
            urllib.request.urlretrieve(_JAR_URL, jar_path, _progress)
            log.info(f"SATDBailiff JAR downloaded: {jar_path}")
            return jar_path
        except Exception as e:
            log.error(f"Failed to download SATDBailiff JAR: {e}")
            jar_path.unlink(missing_ok=True)
            return None

    # ------------------------------------------------------------------ #
    #  MySQL container lifecycle                                           #
    # ------------------------------------------------------------------ #

    def _ensure_mysql_image(self) -> bool:
        """
        Pull mysql:8.0 if not already present locally.
        'docker run' pulls implicitly but has no visible progress and is bounded by our
        timeout, causing a spurious TimeoutExpired on slow connections.
        Pulling explicitly first gives progress feedback and no timeout risk.
        """
        check = subprocess.run(
            ["docker", "image", "inspect", _MYSQL_IMAGE],
            capture_output=True, text=True,
        )
        if check.returncode == 0:
            return True  # already cached locally

        log.info(f"Pulling {_MYSQL_IMAGE} (first run only, ~500 MB) ...")
        pull = subprocess.run(
            ["docker", "pull", _MYSQL_IMAGE],
            capture_output=False,  # let pull progress print to the terminal
            timeout=600,           # 10 min ceiling for very slow connections
        )
        if pull.returncode != 0:
            log.error(f"docker pull {_MYSQL_IMAGE} failed")
            return False
        return True

    def _existing_container_has_data(self) -> bool:
        """
        True if our named container is running AND its Projects table already has
        a row for this repo. Lets us recover from interrupted previous runs
        without destroying their data.
        """
        chk = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", self.container_name],
            capture_output=True, text=True,
        )
        if chk.returncode != 0 or chk.stdout.strip() != "true":
            return False
        try:
            import mysql.connector
            cnx = mysql.connector.connect(
                host="127.0.0.1", port=self.mysql_port,
                user=_MYSQL_USER, password=_MYSQL_PASS, database=_MYSQL_DB,
                connect_timeout=5,
            )
            cur = cnx.cursor()
            repo_url = f"https://github.com/{self.repo_owner}/{self.repo_name}"
            cur.execute(
                "SELECT COUNT(*) FROM Projects WHERE p_url = %s OR p_url LIKE %s",
                (repo_url, f"%{self.repo_owner}/{self.repo_name}%"),
            )
            n = cur.fetchone()[0]
            cur.close()
            cnx.close()
            return n > 0
        except Exception:
            return False

    def _start_mysql(self) -> bool:
        if not self._ensure_mysql_image():
            return False

        # Remove any stale container left from a previous interrupted run
        subprocess.run(
            ["docker", "rm", "-f", self.container_name],
            capture_output=True, text=True,
        )
        log.info(
            f"Starting MySQL container '{self.container_name}' on 127.0.0.1:{self.mysql_port} ..."
        )
        result = subprocess.run(
            [
                "docker", "run", "-d",
                "--name", self.container_name,
                "-e", f"MYSQL_ROOT_PASSWORD={_MYSQL_ROOT_PASS}",
                "-e", "MYSQL_ROOT_HOST=%",   # allow root TCP from any host (needed for host→container)
                "-e", f"MYSQL_DATABASE={_MYSQL_DB}",
                "-e", f"MYSQL_USER={_MYSQL_USER}",
                "-e", f"MYSQL_PASSWORD={_MYSQL_PASS}",
                "-p", f"127.0.0.1:{self.mysql_port}:3306",
                _MYSQL_IMAGE,
                # Enable mysql_native_password plugin for SATDBailiff's JDBC Connector/J 5.x.
                # --default-authentication-plugin was REMOVED in MySQL 8.4; this is the
                # replacement. The plugin is disabled by default in 8.4 to enable it.
                "--mysql-native-password=ON",
            ],
            capture_output=True, text=True, timeout=30,  # image already local → fast
        )
        if result.returncode != 0:
            log.error(f"docker run failed: {result.stderr[:500]}")
            return False
        self._mysql_started = True

        if not self._wait_for_mysql():
            return False

        # Re-key accounts to mysql_native_password so SATDBailiff's JDBC 5.x can authenticate.
        # Python connector (9.x) handles caching_sha2_password for the initial root connection;
        # after this call JDBC 5.x can connect directly.
        self._configure_native_auth()

        # Pre-create the SATDBailiff schema. SATDBailiff does NOT initialise its own
        # tables — it expects a schema already created from sql/satd.sql.
        self._create_schema()
        return True

    def _wait_for_mysql(self, timeout: int = 120) -> bool:
        """Poll until MySQL accepts connections (as root, Python connector)."""
        import mysql.connector

        log.info("Waiting for MySQL to accept connections ...")
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                cnx = mysql.connector.connect(
                    host="127.0.0.1",
                    port=self.mysql_port,
                    user="root",
                    password=_MYSQL_ROOT_PASS,
                    connect_timeout=3,
                )
                cnx.close()
                log.info("MySQL is ready")
                return True
            except Exception:
                time.sleep(3)

        log.error(
            f"MySQL did not become ready within {timeout}s — "
            f"check 'docker logs {self.container_name}' for startup errors"
        )
        return False

    def _create_schema(self) -> None:
        """
        Pre-create the SATDBailiff MySQL schema.

        SATDBailiff does NOT create its own tables — it requires a pre-initialized
        schema. This reproduces sql/satd.sql from the SATDBailiff repository verbatim:
        https://github.com/smilevo/SATDBailiff/blob/master/sql/satd.sql
        """
        import mysql.connector

        # Tables must be created in FK-dependency order.
        # DROP TABLE is omitted — Docker container is always fresh, so tables never pre-exist.
        _SCHEMA_SQL = [
            """CREATE TABLE IF NOT EXISTS Projects (
                p_id INT AUTO_INCREMENT NOT NULL,
                p_name VARCHAR(255) NOT NULL UNIQUE,
                p_url  VARCHAR(255) NOT NULL UNIQUE,
                PRIMARY KEY (p_id)
            )""",
            """CREATE TABLE IF NOT EXISTS SATDInFile (
                f_id             INT AUTO_INCREMENT,
                f_comment        VARCHAR(4096),
                f_comment_type   VARCHAR(32),
                f_path           VARCHAR(512),
                start_line       INT,
                end_line         INT,
                containing_class VARCHAR(512),
                containing_method VARCHAR(512),
                method_declaration LONGTEXT,
                method_body        LONGTEXT,
                `type`           VARCHAR(45) DEFAULT NULL,
                PRIMARY KEY (f_id)
            )""",
            """CREATE TABLE IF NOT EXISTS Commits (
                commit_hash      VARCHAR(256),
                p_id             INT,
                author_name      VARCHAR(256),
                author_email     VARCHAR(256),
                author_date      DATETIME,
                committer_name   VARCHAR(256),
                committer_email  VARCHAR(256),
                commit_date      DATETIME,
                PRIMARY KEY (p_id, commit_hash),
                FOREIGN KEY (p_id) REFERENCES Projects(p_id)
            )""",
            """CREATE TABLE IF NOT EXISTS SATD (
                satd_id          INT AUTO_INCREMENT,
                satd_instance_id INT,
                parent_instance_id INT,
                p_id             INT,
                first_commit     VARCHAR(256),
                second_commit    VARCHAR(256),
                first_file       INT,
                second_file      INT,
                resolution       VARCHAR(64),
                PRIMARY KEY (satd_id),
                FOREIGN KEY (p_id) REFERENCES Projects(p_id),
                FOREIGN KEY (p_id, first_commit)  REFERENCES Commits(p_id, commit_hash),
                FOREIGN KEY (p_id, second_commit) REFERENCES Commits(p_id, commit_hash),
                FOREIGN KEY (first_file)  REFERENCES SATDInFile(f_id),
                FOREIGN KEY (second_file) REFERENCES SATDInFile(f_id)
            )""",
            """CREATE TABLE IF NOT EXISTS RefactoringsRmv (
                `refactoringID` INT NOT NULL AUTO_INCREMENT,
                `commit_hash`   VARCHAR(256) NOT NULL,
                `projectID`     INT DEFAULT NULL,
                `type`          VARCHAR(45) DEFAULT NULL,
                `description`   MEDIUMTEXT,
                PRIMARY KEY (`refactoringID`),
                UNIQUE KEY `idRefactorings_UNIQUE` (`refactoringID`),
                KEY `commit_hash_idx`  (`commit_hash`),
                KEY `commit_hash_idx1` (`commit_hash`, `projectID`)
            )""",
            """CREATE TABLE IF NOT EXISTS AfterRefactoring (
                `afterID`     INT NOT NULL AUTO_INCREMENT,
                `refID`       INT NOT NULL,
                `filePath`    MEDIUMTEXT,
                `startLine`   INT DEFAULT NULL,
                `endLine`     INT DEFAULT NULL,
                `startColumn` INT DEFAULT NULL,
                `endColumn`   INT DEFAULT NULL,
                `description` MEDIUMTEXT,
                `codeElement` MEDIUMTEXT,
                PRIMARY KEY (`afterID`),
                KEY `idRefactorings_idx` (`refID`),
                CONSTRAINT `idRefactorings`
                    FOREIGN KEY (`refID`) REFERENCES `RefactoringsRmv` (`refactoringID`)
                    ON DELETE CASCADE ON UPDATE CASCADE
            )""",
            """CREATE TABLE IF NOT EXISTS BeforeRefactoring (
                `beforeID`       INT NOT NULL AUTO_INCREMENT,
                `refactoringID`  INT NOT NULL,
                `filePath`       MEDIUMTEXT,
                `startLine`      INT DEFAULT NULL,
                `endLine`        INT DEFAULT NULL,
                `startColumn`    INT DEFAULT NULL,
                `endColumn`      INT DEFAULT NULL,
                `description`    MEDIUMTEXT,
                `codeElement`    MEDIUMTEXT,
                PRIMARY KEY (`beforeID`)
            )""",
        ]

        try:
            cnx = mysql.connector.connect(
                host="127.0.0.1", port=self.mysql_port,
                user="root", password=_MYSQL_ROOT_PASS,
                database=_MYSQL_DB, connect_timeout=10,
            )
            cur = cnx.cursor()
            for stmt in _SCHEMA_SQL:
                cur.execute(stmt)
            cnx.commit()
            cur.close()
            cnx.close()
            log.info("SATDBailiff schema initialised (7 tables)")
        except Exception as e:
            log.error(f"Schema creation failed: {e}")
            raise  # propagate — JAR would fail without tables

    def _configure_native_auth(self) -> None:
        """
        Re-key root and satduser to mysql_native_password.
        Called after _wait_for_mysql so Python connector can connect with the default
        caching_sha2_password first; after this SATDBailiff's JDBC Connector/J 5.x
        (which only supports mysql_native_password) can authenticate.
        """
        import mysql.connector

        try:
            cnx = mysql.connector.connect(
                host="127.0.0.1", port=self.mysql_port,
                user="root", password=_MYSQL_ROOT_PASS,
                connect_timeout=10,
            )
            cur = cnx.cursor()
            for stmt in [
                f"ALTER USER 'root'@'%' IDENTIFIED WITH mysql_native_password BY '{_MYSQL_ROOT_PASS}'",
                f"ALTER USER '{_MYSQL_USER}'@'%' IDENTIFIED WITH mysql_native_password BY '{_MYSQL_PASS}'",
                "FLUSH PRIVILEGES",
            ]:
                try:
                    cur.execute(stmt)
                except Exception as e:
                    log.debug(f"Auth config stmt skipped ({e}): {stmt[:60]}")
            cur.close()
            cnx.close()
            log.info("MySQL users re-keyed to mysql_native_password (JDBC 5.x compatible)")
        except Exception as e:
            log.warning(f"Could not configure native auth: {e} — SATDBailiff JDBC connection may fail")

    def _stop_mysql(self) -> None:
        if self._mysql_started:
            log.info(f"Removing MySQL container '{self.container_name}' ...")
            subprocess.run(
                ["docker", "rm", "-f", self.container_name],
                capture_output=True, text=True, timeout=30,
            )
            self._mysql_started = False

    # ------------------------------------------------------------------ #
    #  Input file generation                                               #
    # ------------------------------------------------------------------ #

    def _write_repos_csv(self, commit_hash: str) -> Path:
        """
        SATDBailiff repos.csv format (no header):
          https://github.com/owner/repo,<commit_sha>
        The commit hash is the terminal commit — SATDBailiff mines history up to this point.
        Omitting it causes SATDBailiff to mine the full default-branch history.
        """
        path = self.results_path / "satdbailiff_repos.csv"
        url = f"https://github.com/{self.repo_owner}/{self.repo_name}"
        if commit_hash and commit_hash.lower() != "head":
            path.write_text(f"{url},{commit_hash}\n")
            log.info(f"repos.csv: {url} @ {commit_hash[:12]}")
        else:
            path.write_text(f"{url}\n")
            log.info(f"repos.csv: {url} (no terminal commit — full history)")
        return path

    def _write_db_properties(self) -> Path:
        """
        SATDBailiff db.properties format (exact key names required):
          URL=<hostname>   (bare hostname or IP, NOT a JDBC connection string)
          USERNAME=...
          PASSWORD=...
          PORT=...
          DB=...
          USE_SSL=false
        """
        # Use root credentials. SATDBailiff v1.2 bundles JDBC Connector/J 5.x which can
        # fail silently with non-root MySQL 8 accounts due to DDL grant gaps or auth edge
        # cases. Root has unrestricted access to this ephemeral container.
        path = self.results_path / "satdbailiff_db.properties"
        path.write_text(
            f"URL=127.0.0.1\n"
            f"USERNAME=root\n"
            f"PASSWORD={_MYSQL_ROOT_PASS}\n"
            f"PORT={self.mysql_port}\n"
            f"DB={_MYSQL_DB}\n"
            f"USE_SSL=false\n"
        )
        return path

    # ------------------------------------------------------------------ #
    #  Run SATDBailiff JAR                                                 #
    # ------------------------------------------------------------------ #

    def _run_jar(
        self, jar: Path, repos_csv: Path, db_props: Path, timeout: int = 7200
    ) -> bool:
        java_bin = shutil.which("java")
        if not java_bin:
            log.error("Java not found on PATH")
            return False

        cmd = [
            java_bin,
            "-Xmx4g",  # 4 GB heap — large repos can exhaust default 256 MB
            "-jar", str(jar),
            "-d", str(db_props),
            "-r", str(repos_csv),
        ]

        # GitHub auth: PAT authentication uses any non-empty username + the token as password
        if self.github_token:
            user = self.github_user or "token"
            cmd += ["-u", user, "-p", self.github_token]
        else:
            log.warning(
                "GITHUB_TOKEN not set — SATDBailiff will only work on public repos "
                "and may be rate-limited"
            )

        log.info(
            f"Running SATDBailiff JAR (timeout={timeout // 60} min) — "
            "cloning repo and walking git history, this can take 30–90 min for large repos ..."
        )
        log.info(f"  Repo: https://github.com/{self.repo_owner}/{self.repo_name}")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            log.error(
                f"SATDBailiff timed out after {timeout // 60} min. "
                "Increase SATDBAILIFF_TIMEOUT or reduce the repo's history window."
            )
            return False
        except Exception as e:
            log.error(f"SATDBailiff subprocess error: {e}")
            return False

        # Always save full output — useful for diagnosing connection / clone failures
        log_path = self.results_path / "satdbailiff_run.log"
        log_path.write_text(
            f"exit_code: {result.returncode}\n\n"
            f"=== STDOUT ===\n{result.stdout}\n\n"
            f"=== STDERR ===\n{result.stderr}\n"
        )
        log.info(f"SATDBailiff output saved to {log_path}")

        if result.returncode == 0:
            log.info("SATDBailiff JAR exited cleanly")
        else:
            # SATDBailiff 1.2 often exits non-zero (NullPointerException at end-of-stream)
            # even when it has successfully processed the repository. Trust the database
            # row count, not the exit code.
            log.info(
                f"SATDBailiff exited with code {result.returncode} — "
                "checking whether any data was written ..."
            )
            # Show the tail of stderr at INFO so failures are visible without --debug
            if result.stderr:
                tail = result.stderr.strip().splitlines()
                log.info(f"SATDBailiff stderr (last 20 lines):\n" + "\n".join(tail[-20:]))

        return self._project_recorded()

    def _project_recorded(self) -> bool:
        """Check that SATDBailiff wrote a Projects row for our repo."""
        import mysql.connector

        repo_url = f"https://github.com/{self.repo_owner}/{self.repo_name}"
        try:
            cnx = mysql.connector.connect(
                host="127.0.0.1", port=self.mysql_port,
                user=_MYSQL_USER, password=_MYSQL_PASS, database=_MYSQL_DB,
            )
            cur = cnx.cursor()

            # Show all rows in Projects for debugging — SATDBailiff may store the URL
            # with a slightly different format (e.g. trailing slash, .git suffix)
            cur.execute("SHOW TABLES")
            tables = [r[0] for r in cur.fetchall()]
            log.info(f"MySQL tables after JAR run: {tables}")

            if "Projects" not in tables:
                log.warning("Projects table does not exist — SATDBailiff never connected to MySQL")
                cur.close()
                cnx.close()
                return False

            cur.execute("SELECT p_id, p_url FROM Projects LIMIT 10")
            rows = cur.fetchall()
            if rows:
                log.info(f"Projects table rows: {rows}")
            else:
                log.warning("Projects table is empty — SATDBailiff ran but wrote nothing")
                cur.close()
                cnx.close()
                return False

            # Accept exact match OR partial match (handles .git suffix / trailing slash)
            cur.execute(
                "SELECT COUNT(*) FROM Projects WHERE p_url = %s OR p_url LIKE %s",
                (repo_url, f"%{self.repo_owner}/{self.repo_name}%"),
            )
            count = cur.fetchone()[0]
            cur.close()
            cnx.close()

            if count > 0:
                log.info("SATDBailiff successfully recorded the project in MySQL")
                return True
            log.warning(
                f"No Projects row matched '{repo_url}'. "
                "Check satdbailiff_run.log for connection or clone errors."
            )
            return False
        except Exception as e:
            log.warning(f"Cannot verify Projects row: {e}")
            return False

    # ------------------------------------------------------------------ #
    #  Query MySQL results                                                 #
    # ------------------------------------------------------------------ #

    def _query_results(self) -> pd.DataFrame:
        import mysql.connector

        repo_url = f"https://github.com/{self.repo_owner}/{self.repo_name}"
        cnx = mysql.connector.connect(
            host="127.0.0.1", port=self.mysql_port,
            user=_MYSQL_USER, password=_MYSQL_PASS, database=_MYSQL_DB,
        )
        cur = cnx.cursor()
        # Allow long GROUP_CONCAT output — default limit of 1024 bytes truncates many comments
        cur.execute("SET SESSION group_concat_max_len = 65536")
        cur.close()

        cur = cnx.cursor(dictionary=True)

        # Diagnostic: show resolution breakdown so we understand what SATDBailiff found.
        # NOTE: second_commit is NEVER NULL in SATDBailiff's data model — every row
        # represents a consecutive commit pair (Ca→Cb) and both hashes are always set.
        # Active SATD = SATD_ADDED with no subsequent SATD_REMOVED/FILE_REMOVED row.
        url_like = f"%{self.repo_owner}/{self.repo_name}%"
        try:
            cur.execute(
                """
                SELECT resolution, COUNT(*) AS cnt
                FROM SATD s
                INNER JOIN Projects p ON s.p_id = p.p_id
                WHERE (p.p_url = %s OR p.p_url LIKE %s)
                GROUP BY resolution
                ORDER BY cnt DESC
                """,
                (repo_url, url_like),
            )
            rows_stat = cur.fetchall()
            if rows_stat:
                breakdown = ", ".join(f"{r['resolution']}:{r['cnt']}" for r in rows_stat)
                log.info(f"SATD table resolution breakdown: {breakdown}")
            else:
                log.info("SATD table is empty — SATDBailiff found no SATD events in this repo")
        except Exception as e:
            log.debug(f"SATD stats query failed: {e}")

        from datetime import datetime as _dt, timezone as _tz
        end_date_str = _dt.now(_tz.utc).strftime("%Y-%m-%d")

        cur = cnx.cursor(dictionary=True)
        # Active SATD query: Uses SATD_ADDED resolution with NOT EXISTS subquery
        # to exclude instances that have been subsequently resolved (SATD_REMOVED or FILE_REMOVED).
        # Joins on second_file (NEW state from Cb) to get real file paths and comment text.
        #
        # SATDBailiff data model (consecutive commit pairs Ca→Cb):
        #   first_file  = SATDInFile from Ca (OLD state — '/dev/null' for new files)
        #   second_file = SATDInFile from Cb (NEW state — the actual introduced location)
        #
        # For SATD_ADDED, the SATD exists in Cb (second_file) but not Ca (first_file).
        # Joining on first_file yields '/dev/null' for every newly-created file.
        # Joining on second_file gives the real file path and actual comment text.
        #
        # satd_age_days  = days from the introducing commit to end_date; MAX per file
        #                  (captures the oldest unresolved debt, i.e. the longest-lived burden)
        # satd_change_count = total SATD_CHANGED events across active instances in the file
        #                     (high value = debt acknowledged repeatedly but never fixed)
        cur.execute(
            """
            SELECT
                sif.f_path                                                 AS file_path,
                COUNT(DISTINCT s.satd_instance_id)                         AS satd_count,
                GROUP_CONCAT(
                    DISTINCT LEFT(sif.f_comment, 200)
                    ORDER BY sif.f_id
                    SEPARATOR ' | '
                )                                                          AS satd_text,
                MAX(DATEDIFF(%s, COALESCE(c_add.commit_date, c_add.author_date)))
                                                                           AS satd_age_days,
                COALESCE(SUM(chg.change_count), 0)                         AS satd_change_count
            FROM SATD s
            INNER JOIN SATDInFile sif ON s.second_file    = sif.f_id
            INNER JOIN Projects   p   ON s.p_id           = p.p_id
            LEFT  JOIN Commits c_add  ON c_add.commit_hash = s.second_commit
                                     AND c_add.p_id        = s.p_id
            LEFT  JOIN (
                SELECT satd_instance_id, p_id, COUNT(*) AS change_count
                FROM   SATD
                WHERE  resolution = 'SATD_CHANGED'
                GROUP  BY satd_instance_id, p_id
            ) chg ON chg.satd_instance_id = s.satd_instance_id
                  AND chg.p_id            = s.p_id
            WHERE (p.p_url = %s OR p.p_url LIKE %s)
              AND s.resolution = 'SATD_ADDED'
              AND s.second_file IS NOT NULL
              AND sif.f_path NOT IN ('dev/null', '/dev/null', '')
              AND NOT EXISTS (
                  SELECT 1 FROM SATD s2
                  WHERE s2.satd_instance_id = s.satd_instance_id
                    AND s2.p_id            = s.p_id
                    AND s2.resolution IN ('SATD_REMOVED', 'FILE_REMOVED')
              )
            GROUP BY sif.f_path
            """,
            (end_date_str, repo_url, url_like),
        )
        rows = cur.fetchall()
        cur.close()
        cnx.close()

        if not rows:
            log.info(
                "No active SATD found for this repo (SATD_ADDED with no SATD_REMOVED). "
                "The project may genuinely have no open SATD at the terminal commit."
            )
            return self._empty_df()

        df = pd.DataFrame(rows)
        # Strip any leading slash that JGit occasionally adds to paths
        df["file_path"] = df["file_path"].str.lstrip("/")

        df["satd_age_days"] = pd.to_numeric(df["satd_age_days"], errors="coerce").fillna(0).astype(int)
        df["satd_change_count"] = pd.to_numeric(df["satd_change_count"], errors="coerce").fillna(0).astype(int)

        log.info(
            f"SATDBailiff: {len(df)} files with active SATD at terminal commit "
            f"({df['satd_count'].sum()} total instances, "
            f"max age {df['satd_age_days'].max()} days, "
            f"{df['satd_change_count'].sum()} total changes)"
        )
        return df[
            ["file_path", "satd_count", "satd_text",
             "satd_age_days", "satd_change_count"]
        ]

    def _empty_df(self) -> pd.DataFrame:
        return pd.DataFrame(
            columns=["file_path", "satd_count", "satd_text",
                     "satd_age_days", "satd_change_count"]
        )

    # ------------------------------------------------------------------ #
    #  Public entry point                                                  #
    # ------------------------------------------------------------------ #

    def run(self, commit_hash: str = "HEAD") -> pd.DataFrame | None:
        """
        Execute the full SATDBailiff pipeline.

        Returns a DataFrame on success (may be empty if no active SATD found).
        Returns None on any infrastructure failure so the caller can fall through
        to the next SATD method.
        """
        if not shutil.which("java"):
            log.info("SATDBailiff: Java not on PATH — skipping")
            return None
        if not shutil.which("docker"):
            log.info("SATDBailiff: Docker not on PATH — skipping")
            return None
        try:
            import mysql.connector  # noqa: F401
        except ImportError:
            log.warning(
                "SATDBailiff: mysql-connector-python not installed — skipping. "
                "Run: pip install mysql-connector-python"
            )
            return None
        if not self.repo_owner or not self.repo_name:
            log.warning("SATDBailiff: repo_owner or repo_name not configured — skipping")
            return None

        # Reuse-existing-container guard: if a previous run was interrupted and
        # left a container with data for this repo, query it instead of destroying
        # the data with a fresh JAR walk. Set SATDBAILIFF_FORCE_RERUN=1 to force
        # a clean re-extraction.
        force_rerun = os.getenv("SATDBAILIFF_FORCE_RERUN", "").lower() in ("1", "true", "yes")
        if not force_rerun and self._existing_container_has_data():
            log.info(
                f"Reusing existing MySQL container '{self.container_name}' — "
                "Projects row already present. "
                "Set SATDBAILIFF_FORCE_RERUN=1 to force a fresh JAR walk."
            )
            try:
                return self._query_results()
            except Exception as e:
                log.warning(
                    f"Query against existing container failed ({e}) — "
                    "proceeding with a fresh JAR run"
                )

        jar = self._find_or_download_jar()
        if jar is None:
            return None

        repos_csv = self._write_repos_csv(commit_hash)
        db_props = self._write_db_properties()

        try:
            if not self._start_mysql():
                return None

            # Give MySQL an extra 5 s to finish creating the grant tables after ping succeeds
            time.sleep(5)

            timeout = int(os.getenv("SATDBAILIFF_TIMEOUT", "7200"))
            if not self._run_jar(jar, repos_csv, db_props, timeout):
                log.warning("SATDBailiff produced no verifiable results — falling through")
                return None

            return self._query_results()

        except Exception as e:
            log.error(f"SATDBailiff pipeline error: {e}", exc_info=True)
            return None
        finally:
            self._stop_mysql()
            (self.results_path / "satdbailiff_repos.csv").unlink(missing_ok=True)
            (self.results_path / "satdbailiff_db.properties").unlink(missing_ok=True)
