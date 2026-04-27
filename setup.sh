#!/usr/bin/env bash
# Setup script for the thesis pipeline.
# Run once before first use: bash setup.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log()  { echo "[setup] $*"; }
warn() { echo "[setup] WARNING: $*" >&2; }
ok()   { echo "[setup] OK: $*"; }

# ------------------------------------------------------------------ #
#  1. Python virtual environment                                       #
# ------------------------------------------------------------------ #
log "Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
# shellcheck disable=SC1091
source venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
ok "Python venv ready (activate with: source venv/bin/activate)"

# ------------------------------------------------------------------ #
#  2. .env file                                                        #
# ------------------------------------------------------------------ #
if [ ! -f ".env" ]; then
    log "Creating .env from template..."
    cp .env .env
    warn ".env created — fill in ANTHROPIC_API_KEY, SONAR_TOKEN, GITHUB_TOKEN before running"
else
    ok ".env already exists"
fi

# ------------------------------------------------------------------ #
#  3. MySQL (required only if using SATDBailiff full JAR)             #
#     The ML classifier (satd_detector.jar) does NOT need MySQL.      #
# ------------------------------------------------------------------ #
NEED_MYSQL=false
if [ -f "tools/SATDBailiff.jar" ] || ls tools/SATDBailiff-*.jar 2>/dev/null | grep -q .; then
    NEED_MYSQL=true
fi

if $NEED_MYSQL; then
    log "SATDBailiff JAR detected — setting up MySQL..."
    OS="$(uname -s)"

    if [ "$OS" = "Darwin" ]; then
        if ! command -v mysql &>/dev/null; then
            log "Installing MySQL via Homebrew..."
            brew install mysql
        fi
        log "Starting MySQL service..."
        brew services start mysql 2>/dev/null || true
        # Give the service a moment to start
        sleep 2
        log "Creating 'satd' database if not exists..."
        mysql -u root --connect-timeout=5 -e "CREATE DATABASE IF NOT EXISTS satd;" 2>/dev/null && \
            ok "MySQL 'satd' database ready" || \
            warn "Could not create MySQL database — set MYSQL_PASSWORD in .env if root has a password"

    elif [ "$OS" = "Linux" ]; then
        if ! command -v mysql &>/dev/null; then
            log "Installing MySQL via apt..."
            sudo apt-get update -qq && sudo apt-get install -y -qq mysql-server
        fi
        sudo service mysql start 2>/dev/null || sudo systemctl start mysql 2>/dev/null || true
        sleep 2
        sudo mysql -e "CREATE DATABASE IF NOT EXISTS satd;" 2>/dev/null && \
            ok "MySQL 'satd' database ready" || \
            warn "Could not create MySQL database automatically — create it manually: mysql -u root -e 'CREATE DATABASE satd;'"
    else
        warn "Unsupported OS ($OS) — install MySQL manually and create a 'satd' database"
    fi
else
    log "Skipping MySQL setup (satd_detector.jar uses ML classifier, no database needed)"
fi

# ------------------------------------------------------------------ #
#  4. Detect SATD extraction method                                   #
# ------------------------------------------------------------------ #
echo ""
log "SATD extraction method detection:"
if [ -f "tools/satd_detector.jar" ] && command -v java &>/dev/null; then
    ok "  ML classifier (satd_detector.jar + Java) — will be used automatically"
elif [ -f "tools/SATDBailiff.jar" ] && command -v java &>/dev/null; then
    ok "  SATDBailiff JAR + MySQL — will be used automatically"
elif command -v docker &>/dev/null; then
    ok "  Docker available — SATDBailiff image will be attempted"
else
    log "  Keyword-based detection (GitHub API) — built-in fallback, no extra tools needed"
fi

# ------------------------------------------------------------------ #
#  5. Done                                                             #
# ------------------------------------------------------------------ #
echo ""
echo "========================================================"
echo " Setup complete."
echo ""
echo " Next steps:"
echo "   1. Edit .env — add your API keys"
echo "   2. Edit projects/commons-lang.yaml — set your project key"
echo "   3. source venv/bin/activate"
echo "   4. python main.py --project commons-lang"
echo "========================================================"
