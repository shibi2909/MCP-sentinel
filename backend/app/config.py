"""Central configuration. Values can be overridden with environment variables."""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent  # backend/
DATA_DIR = Path(os.getenv("MCP_SENTINEL_DATA_DIR", str(BASE_DIR / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.getenv(
    "MCP_SENTINEL_DATABASE_URL", "sqlite:///" + (DATA_DIR / "sentinel.db").as_posix()
)

# Files the demo filesystem MCP server is allowed to serve. Nothing outside this folder is readable.
SANDBOX_FILES_DIR = BASE_DIR / "sandbox_files"
ML_MODEL_PATH = DATA_DIR / "risk_model.joblib"
ML_METRICS_PATH = DATA_DIR / "risk_model_metrics.json"


def _load_jwt_secret() -> str:
    """Use MCP_SENTINEL_JWT_SECRET if set, otherwise a random secret persisted in the data folder.

    Security decision: never ship a hard-coded signing key. A random 256-bit key is generated on
    first start so tokens cannot be forged by anyone who has only read the source code.
    """
    env_secret = os.getenv("MCP_SENTINEL_JWT_SECRET")
    if env_secret:
        return env_secret
    secret_file = DATA_DIR / "jwt_secret.key"
    if not secret_file.exists():
        secret_file.write_text(secrets.token_hex(32), encoding="utf-8")
    return secret_file.read_text(encoding="utf-8").strip()


JWT_SECRET = _load_jwt_secret()
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("MCP_SENTINEL_JWT_EXPIRE_MINUTES", "480"))

# Input validation limits (M4)
MAX_PAYLOAD_BYTES = 8 * 1024
MAX_STRING_LENGTH = 2000

# Output monitoring limits (M8)
MAX_OUTPUT_BYTES = 20 * 1024

# Security modes compared in the evaluation (Section 4 of the project brief)
SECURITY_MODES = {
    "A_STATIC": "Static thresholds, rule-based score only",
    "B_ML": "Rule-based + ML score, static thresholds",
    "C_CONTROLLER": "Rule-based + ML score, PI-controller adaptive thresholds",
}
DEFAULT_SECURITY_MODE = os.getenv("MCP_SENTINEL_MODE", "C_CONTROLLER")

CORS_ORIGINS = os.getenv(
    "MCP_SENTINEL_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
).split(",")
