"""
Attack Logger - CipherGuard Phase 3

Writes structured JSON log files for every attack run.
Each run creates a timestamped .json file in backend/logs/attack_runs/.

Log schema:
  {
    "run_id"      : "uuid",
    "timestamp"   : "ISO-8601",
    "attack_type" : "dictionary",
    "algorithm"   : "md5",
    "config"      : { ... },
    "results"     : { ... AttackReport fields ... },
    "cracked_sample": [ first 10 cracked passwords ],
  }

JSON logs are the primary input to the breach analysis reporter.
"""

import json
import uuid
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from backend.attacks.base_attack import AttackReport

logger = logging.getLogger(__name__)

# Default log directory — relative to project root
_DEFAULT_LOG_DIR = Path(__file__).parents[2] / "backend" / "logs" / "attack_runs"


def _get_log_dir() -> Path:
    """Return the log directory, creating it if needed."""
    log_dir = Path(os.getenv("ATTACK_LOG_DIR", str(_DEFAULT_LOG_DIR)))
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


def log_attack_run(
    report      : AttackReport,
    config      : dict,
    run_id      : Optional[str] = None,
) -> dict:
    """
    Persist an AttackReport as a structured JSON log file.

    Args:
        report : The AttackReport from a completed attack run
        config : Configuration dict (max_attempts, timeout_sec, etc.)
        run_id : Optional UUID string (auto-generated if None)

    Returns:
        The full log dict that was written to disk
    """
    run_id    = run_id or str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    log_dir   = _get_log_dir()

    # Filename: <timestamp>_<attack>_<algo>.json
    safe_ts   = timestamp[:19].replace(":", "-")
    filename  = f"{safe_ts}_{report.attack_type}_{report.algorithm}.json"
    filepath  = log_dir / filename

    # Serialize cracked passwords — limit sample to 20 entries in log
    cracked_sample = [
        {
            "record_id"     : c.record_id,
            "plain_password": c.plain_password,
            "crack_time_ms" : c.crack_time_ms,
            "attempt_number": c.attempt_number,
        }
        for c in report.cracked_passwords[:20]
    ]

    log_entry = {
        "run_id"         : run_id,
        "timestamp"      : timestamp,
        "attack_type"    : report.attack_type,
        "algorithm"      : report.algorithm,
        "config"         : config,
        "results": {
            "target_count"    : report.target_count,
            "cracked_count"   : report.cracked_count,
            "success_rate_pct": report.success_rate_pct,
            "total_time_sec"  : report.total_time_sec,
            "total_attempts"  : report.total_attempts,
            "attempts_per_sec": report.attempts_per_sec,
            "avg_crack_time_ms": report.avg_crack_time_ms,
            "max_crack_time_ms": report.max_crack_time_ms,
            "wordlist_size"   : report.wordlist_size,
            "stopped_early"   : report.stopped_early,
            "notes"           : report.notes,
        },
        "cracked_sample" : cracked_sample,
        "total_cracked_full": len(report.cracked_passwords),
    }

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(log_entry, f, indent=2, ensure_ascii=False)
        logger.info(f"[Logger] Attack log written: {filepath}")
    except Exception as e:
        logger.error(f"[Logger] Failed to write log: {e}")

    return log_entry


def get_recent_logs(limit: int = 20) -> list[dict]:
    """
    Read and return the most recent attack log files.

    Args:
        limit: Maximum number of log files to return

    Returns:
        List of log entry dicts, sorted newest-first
    """
    log_dir = _get_log_dir()
    log_files = sorted(log_dir.glob("*.json"), reverse=True)[:limit]
    logs = []
    for f in log_files:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                logs.append(json.load(fh))
        except Exception as e:
            logger.warning(f"[Logger] Could not read {f}: {e}")
    return logs

