"""
Attack Utilities — CipherGuard

Standalone helper functions for search space estimation and GPU crack time.
Lives in a separate module to avoid circular imports between:
  backend.attacks   ←→   backend.score_engine

These utilities have NO imports from the rest of CipherGuard.
"""


def estimate_search_space(charset_size: int, max_length: int) -> str:
    """Calculate total search space for brute force and return formatted string."""
    total = sum(charset_size ** l for l in range(1, max_length + 1))
    if total < 1_000:
        return f"{total:,}"
    elif total < 1_000_000:
        return f"{total/1_000:.1f}K"
    elif total < 1_000_000_000:
        return f"{total/1_000_000:.1f}M"
    elif total < 1_000_000_000_000:
        return f"{total/1_000_000_000:.1f}B"
    else:
        return f"{total:.2e}"


def estimate_gpu_crack_time(algorithm: str, search_space_size: int) -> str:
    """
    Estimate real-world GPU crack time for a given algorithm and search space.

    Based on realistic GPU hash rates (RTX 4090 approximate):
      MD5:       68 billion/sec
      SHA1:      24 billion/sec
      SHA256:    10 billion/sec
      bcrypt:    184,000/sec  (cost=12)
      Argon2id:  ~900/sec     (64MB memory cost)
    """
    gpu_rates = {
        "plaintext"    : float("inf"),
        "md5"          : 68_000_000_000,
        "sha1"         : 24_000_000_000,
        "sha256"       : 10_000_000_000,
        "salted_sha256": 5_000_000_000,
        "bcrypt"       : 184_000,
        "argon2id"     : 900,
    }
    rate = gpu_rates.get(algorithm, 1_000_000)
    if rate == float("inf"):
        return "Instant (no hashing required)"

    seconds = search_space_size / rate
    if seconds < 0.001:
        return "< 1 millisecond"
    elif seconds < 1:
        return f"{seconds * 1000:.1f} milliseconds"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    elif seconds < 31_536_000:
        return f"{seconds / 86400:.1f} days"
    elif seconds < 31_536_000 * 100:
        return f"{seconds / 31_536_000:.1f} years"
    else:
        return f"{seconds / 31_536_000:.2e} years (effectively uncrackable)"
