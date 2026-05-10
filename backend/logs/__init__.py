"""CipherGuard Logs Package"""
from backend.logs.attack_logger import log_attack_run, get_recent_logs

__all__ = ["log_attack_run", "get_recent_logs"]
