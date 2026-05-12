"""
Streaming Attack Runner — CipherGuard Real-Time Visualization

Generator-based attack engine that yields events in real-time.
Used by the SSE /stream-attack endpoint to push live updates to the browser.

Event types:
  init          — attack session started, targets loaded
  target_list   — all targets with their metadata
  attempt       — a password guess is being tested (throttled for brute force)
  pipeline      — current stage in the hash-compare pipeline
  match         — a password was successfully cracked
  target_status — a target's status changed (waiting/attacking/cracked/failed/timeout)
  stats         — periodic stats snapshot (attempts/sec, crack rate, etc.)
  algo_complete — all targets for one algorithm finished
  done          — entire attack session complete

Architecture:
  - Attacks run synchronously in a background thread
  - Events are pushed into a thread-safe Queue
  - The async SSE generator reads from the queue (non-blocking with asyncio.sleep)
"""

import time
import string
import logging
import itertools
from typing import Generator, Optional
from dataclasses import dataclass, field, asdict

from backend.hashers.hasher_registry import get_hasher
from backend.utils.attack_utils import estimate_search_space, estimate_gpu_crack_time

logger = logging.getLogger(__name__)

# How many brute-force attempts to skip between UI updates (performance)
BRUTE_THROTTLE = 50   # show 1 in every 50 attempts


# ── Event helpers ────────────────────────────────────────────────────────────

def _now() -> float:
    return time.perf_counter()


def _ev(event_type: str, **kwargs) -> dict:
    return {"type": event_type, "ts": round(time.time() * 1000), **kwargs}


# ── Short demo passwords guaranteed to be in brute-force search space ────────

DEMO_PASSWORDS = [
    "abc", "123", "aaa", "bbb", "ccc",
    "xyz", "qwe", "asd", "zxc", "111",
    "1a2", "ab1", "ba2", "dog", "cat",
    "yes", "no", "ok", "hi", "bye",
    "a1b", "z9x", "pw1", "pw2", "abc1",
]


# ── Plaintext shortcut ───────────────────────────────────────────────────────

def _stream_plaintext(targets: list, t0: float) -> Generator[dict, None, None]:
    """Plaintext: every password is instantly exposed — no cracking needed."""
    yield _ev("pipeline", stage="read", guess="(direct read)", note="Plaintext stored — no hash to compute")

    for i, target in enumerate(targets):
        plain = target.hash_value  # hash_value IS the password
        yield _ev("target_status", target_id=target.id, status="attacking",
                  algo="plaintext", hash_preview=plain[:12] + "…" if len(plain) > 12 else plain)
        yield _ev("attempt", guess=plain, attempt_num=i + 1, target_id=target.id)
        yield _ev("pipeline", stage="match", guess=plain, note="No hash to compare — plaintext is directly readable")
        yield _ev("match",
                  target_id=target.id,
                  plain_password=plain,
                  stored_hash=target.hash_value,
                  generated_hash="(plaintext — no hash)",
                  crack_time_ms=0.001,
                  attempt_number=i + 1,
                  algo="plaintext")
        yield _ev("target_status", target_id=target.id, status="cracked", algo="plaintext",
                  plain_password=plain, crack_time_ms=0.001)

    elapsed = (_now() - t0) * 1000
    yield _ev("algo_complete", algo="plaintext", cracked=len(targets), total=len(targets),
              elapsed_ms=elapsed, note="All passwords instantly exposed — plaintext provides ZERO security.")


# ── Dictionary streaming ─────────────────────────────────────────────────────

def stream_dictionary_attack(
    targets: list,
    algorithm: str,
    wordlist: list[str],
    max_attempts: int = 100_000,
    timeout_sec: float = 60.0,
) -> Generator[dict, None, None]:
    """Stream dictionary attack events."""

    if algorithm == "plaintext":
        yield from _stream_plaintext(targets, _now())
        return

    hasher    = get_hasher(algorithm)
    t0        = _now()
    uncracked = {t.id: t for t in targets}
    cracked   = {}
    total_attempts = 0
    stopped_early  = False

    # Initial status
    for t in targets:
        yield _ev("target_status", target_id=t.id, status="waiting", algo=algorithm,
                  hash_preview=t.hash_value[:16] + "…")

    yield _ev("pipeline", stage="load_wordlist",
              note=f"Wordlist loaded: {len(wordlist):,} words")

    for word in wordlist:
        if total_attempts >= max_attempts or (_now() - t0) >= timeout_sec:
            stopped_early = True
            break

        # Emit attempt event (every attempt for dictionary — list is manageable)
        total_attempts += 1
        yield _ev("attempt", guess=word, attempt_num=total_attempts,
                  algo=algorithm)
        yield _ev("pipeline", stage="hash", guess=word,
                  note=f"Computing {algorithm.upper()} hash of '{word}'")

        # Test against remaining targets
        for tid in list(uncracked.keys()):
            target = uncracked[tid]
            try:
                crack_start = _now()
                is_match = hasher.verify_password(word, target.hash_value, salt=target.salt)
                crack_ms  = (_now() - crack_start) * 1000

                yield _ev("pipeline", stage="compare",
                          guess=word, match=is_match,
                          note="Hash match!" if is_match else "No match — continue")

                if is_match:
                    cracked[tid] = word
                    del uncracked[tid]
                    yield _ev("match",
                              target_id=target.id,
                              plain_password=word,
                              stored_hash=target.hash_value,
                              generated_hash="(verified via hasher)",
                              crack_time_ms=round(crack_ms, 4),
                              attempt_number=total_attempts,
                              algo=algorithm)
                    yield _ev("target_status", target_id=target.id, status="cracked",
                              algo=algorithm, plain_password=word,
                              crack_time_ms=round(crack_ms, 4))
            except Exception:
                pass

        if not uncracked:
            break

    # Mark remaining as failed / timeout
    for tid, target in uncracked.items():
        status = "timeout" if stopped_early else "failed"
        yield _ev("target_status", target_id=target.id, status=status, algo=algorithm)

    elapsed = (_now() - t0) * 1000
    yield _ev("algo_complete",
              algo=algorithm,
              cracked=len(cracked),
              total=len(targets),
              elapsed_ms=round(elapsed, 2),
              stopped_early=stopped_early,
              attempts=total_attempts,
              note=_timeout_note(algorithm, stopped_early, len(cracked), len(targets)))


# ── Brute Force streaming ─────────────────────────────────────────────────────

def stream_brute_force_attack(
    targets: list,
    algorithm: str,
    charset: str = string.ascii_lowercase + string.digits,
    min_length: int = 1,
    max_length: int = 5,
    max_attempts: int = 500_000,
    timeout_sec: float = 120.0,
    demo_mode: bool = False,
) -> Generator[dict, None, None]:
    """Stream brute force attack events."""

    if algorithm == "plaintext":
        yield from _stream_plaintext(targets, _now())
        return

    hasher     = get_hasher(algorithm)
    t0         = _now()
    uncracked  = {t.id: t for t in targets}
    cracked    = {}
    total_attempts = 0
    stopped_early  = False
    search_space   = estimate_search_space(len(charset), max_length)
    gpu_time       = estimate_gpu_crack_time(algorithm, sum(len(charset) ** l for l in range(min_length, max_length + 1)))

    for t in targets:
        yield _ev("target_status", target_id=t.id, status="waiting", algo=algorithm,
                  hash_preview=t.hash_value[:16] + "…")

    yield _ev("pipeline", stage="init",
              note=f"Brute force | charset={len(charset)} chars | len {min_length}-{max_length} | space={search_space}")
    yield _ev("stats", algo=algorithm, attempts=0, cracked=0, total=len(targets),
              attempts_per_sec=0, search_space=search_space, gpu_time=gpu_time,
              elapsed_ms=0)

    # Demo mode: try pre-seeded short passwords first
    if demo_mode:
        demo_candidates = [p for p in DEMO_PASSWORDS if min_length <= len(p) <= max_length]
        for candidate in demo_candidates:
            if not uncracked:
                break
            elapsed = _now() - t0
            if elapsed >= timeout_sec or total_attempts >= max_attempts:
                stopped_early = True
                break

            total_attempts += 1
            yield _ev("attempt", guess=candidate, attempt_num=total_attempts,
                      algo=algorithm, mode="demo")
            yield _ev("pipeline", stage="hash", guess=candidate,
                      note=f"[DEMO] Hashing '{candidate}' with {algorithm.upper()}")

            for tid in list(uncracked.keys()):
                target = uncracked[tid]
                try:
                    crack_start = _now()
                    if hasher.verify_password(candidate, target.hash_value, salt=target.salt):
                        crack_ms = (_now() - crack_start) * 1000
                        cracked[tid] = candidate
                        del uncracked[tid]
                        yield _ev("pipeline", stage="match", guess=candidate, match=True)
                        yield _ev("match", target_id=target.id, plain_password=candidate,
                                  stored_hash=target.hash_value, generated_hash="(verified)",
                                  crack_time_ms=round(crack_ms, 4), attempt_number=total_attempts,
                                  algo=algorithm)
                        yield _ev("target_status", target_id=target.id, status="cracked",
                                  algo=algorithm, plain_password=candidate,
                                  crack_time_ms=round(crack_ms, 4))
                except Exception:
                    pass

    # Exhaustive search
    last_stat_time = _now()
    outer_done = False

    for length in range(min_length, max_length + 1):
        if outer_done or not uncracked:
            break

        for combo in itertools.product(charset, repeat=length):
            candidate = "".join(combo)
            total_attempts += 1

            elapsed = _now() - t0
            if elapsed >= timeout_sec or total_attempts >= max_attempts:
                stopped_early = True
                outer_done = True
                break

            # Throttle: only emit attempt events every BRUTE_THROTTLE steps
            if total_attempts % BRUTE_THROTTLE == 0:
                yield _ev("attempt", guess=candidate, attempt_num=total_attempts,
                          algo=algorithm, mode="exhaustive")
                yield _ev("pipeline", stage="hash", guess=candidate,
                          note=f"Hashing '{candidate}'")

            # Periodic stats update every 2 seconds
            if _now() - last_stat_time > 2.0:
                atime = _now() - t0
                aps   = total_attempts / atime if atime > 0 else 0
                yield _ev("stats", algo=algorithm, attempts=total_attempts,
                          cracked=len(cracked), total=len(targets),
                          attempts_per_sec=round(aps, 0),
                          elapsed_ms=round(atime * 1000, 0))
                last_stat_time = _now()

            for tid in list(uncracked.keys()):
                target = uncracked[tid]
                try:
                    crack_start = _now()
                    if hasher.verify_password(candidate, target.hash_value, salt=target.salt):
                        crack_ms = (_now() - crack_start) * 1000
                        cracked[tid] = candidate
                        del uncracked[tid]
                        yield _ev("pipeline", stage="match", guess=candidate, match=True)
                        yield _ev("match", target_id=target.id, plain_password=candidate,
                                  stored_hash=target.hash_value, generated_hash="(verified)",
                                  crack_time_ms=round(crack_ms, 4), attempt_number=total_attempts,
                                  algo=algorithm)
                        yield _ev("target_status", target_id=target.id, status="cracked",
                                  algo=algorithm, plain_password=candidate,
                                  crack_time_ms=round(crack_ms, 4))
                except Exception:
                    pass

            if not uncracked:
                outer_done = True
                break

    for tid, target in uncracked.items():
        status = "timeout" if stopped_early else "failed"
        yield _ev("target_status", target_id=target.id, status=status, algo=algorithm)

    elapsed = (_now() - t0) * 1000
    aps = total_attempts / (elapsed / 1000) if elapsed > 0 else 0
    yield _ev("stats", algo=algorithm, attempts=total_attempts, cracked=len(cracked),
              total=len(targets), attempts_per_sec=round(aps, 0),
              elapsed_ms=round(elapsed, 0))
    yield _ev("algo_complete",
              algo=algorithm, cracked=len(cracked), total=len(targets),
              elapsed_ms=round(elapsed, 2), stopped_early=stopped_early,
              attempts=total_attempts, attempts_per_sec=round(aps, 0),
              note=_timeout_note(algorithm, stopped_early, len(cracked), len(targets)))


# ── Rainbow Table streaming ───────────────────────────────────────────────────

def stream_rainbow_attack(
    targets: list,
    algorithm: str,
    wordlist: list[str],
    max_attempts: int = 200_000,
    timeout_sec: float = 60.0,
) -> Generator[dict, None, None]:
    """Stream rainbow table attack events."""

    if algorithm == "plaintext":
        yield from _stream_plaintext(targets, _now())
        return

    UNSALTED = {"md5", "sha1", "sha256"}
    t0 = _now()

    if algorithm not in UNSALTED:
        yield _ev("pipeline", stage="init", note=f"{algorithm} uses salting — rainbow table defeated")
        for t in targets:
            yield _ev("target_status", target_id=t.id, status="failed", algo=algorithm,
                      note="Salted hash — precomputed tables useless (unique salt per password)")
        yield _ev("algo_complete", algo=algorithm, cracked=0, total=len(targets),
                  elapsed_ms=1.0, stopped_early=False, attempts=0,
                  note="Rainbow table FAILED. Per-password salting defeats precomputed lookup tables.")
        return

    hasher    = get_hasher(algorithm)
    uncracked = {t.id: t for t in targets}
    cracked   = {}

    yield _ev("pipeline", stage="build_table",
              note=f"Building rainbow table: {len(wordlist):,} precomputed {algorithm.upper()} hashes")

    # Build table
    table = {}
    for word in wordlist:
        try:
            result = hasher.hash_password(word)
            table[result.hash_value] = word
        except Exception:
            pass

    yield _ev("pipeline", stage="lookup",
              note=f"Table built: {len(table):,} entries. O(1) lookup — instant per hash")

    for t in targets:
        yield _ev("target_status", target_id=t.id, status="attacking", algo=algorithm,
                  hash_preview=t.hash_value[:16] + "…")
        match_word = table.get(t.hash_value)
        if match_word:
            cracked[t.id] = match_word
            del uncracked[t.id]
            yield _ev("match", target_id=t.id, plain_password=match_word,
                      stored_hash=t.hash_value, generated_hash=t.hash_value,
                      crack_time_ms=0.001, attempt_number=1, algo=algorithm)
            yield _ev("target_status", target_id=t.id, status="cracked", algo=algorithm,
                      plain_password=match_word, crack_time_ms=0.001)
        else:
            yield _ev("target_status", target_id=t.id, status="failed", algo=algorithm)

    elapsed = (_now() - t0) * 1000
    yield _ev("algo_complete", algo=algorithm, cracked=len(cracked), total=len(targets),
              elapsed_ms=round(elapsed, 2), stopped_early=False, attempts=len(targets),
              note=f"{algorithm.upper()} is UNSALTED: identical passwords produce identical hashes — rainbow tables work instantly.")


# ── Hybrid streaming ─────────────────────────────────────────────────────────

def stream_hybrid_attack(
    targets: list,
    algorithm: str,
    wordlist: list[str],
    max_attempts: int = 200_000,
    timeout_sec: float = 120.0,
) -> Generator[dict, None, None]:
    """Stream hybrid attack events (dictionary + mutations)."""

    if algorithm == "plaintext":
        yield from _stream_plaintext(targets, _now())
        return

    SUFFIXES = ["", "1", "12", "123", "!", "@", "2024", "99", "01", "#", "2025", "!@", "123!"]
    PREFIXES = ["", "My", "The", "Super", "Best"]

    hasher    = get_hasher(algorithm)
    t0        = _now()
    uncracked = {t.id: t for t in targets}
    cracked   = {}
    total_attempts = 0
    stopped_early  = False

    for t in targets:
        yield _ev("target_status", target_id=t.id, status="waiting", algo=algorithm,
                  hash_preview=t.hash_value[:16] + "…")

    yield _ev("pipeline", stage="generate_mutations",
              note=f"Generating {len(wordlist) * len(SUFFIXES) * len(PREFIXES):,} mutations from {len(wordlist)} base words")

    for word in wordlist:
        if not uncracked:
            break

        for prefix in PREFIXES:
            for suffix in SUFFIXES:
                if not uncracked:
                    break

                elapsed = _now() - t0
                if elapsed >= timeout_sec or total_attempts >= max_attempts:
                    stopped_early = True
                    break

                candidate = prefix + word + suffix
                total_attempts += 1

                yield _ev("attempt", guess=candidate, attempt_num=total_attempts,
                          algo=algorithm, base_word=word, prefix=prefix, suffix=suffix)
                yield _ev("pipeline", stage="hash", guess=candidate,
                          note=f"Mutation: '{prefix}' + '{word}' + '{suffix}' → '{candidate}'")

                for tid in list(uncracked.keys()):
                    target = uncracked[tid]
                    try:
                        crack_start = _now()
                        if hasher.verify_password(candidate, target.hash_value, salt=target.salt):
                            crack_ms = (_now() - crack_start) * 1000
                            cracked[tid] = candidate
                            del uncracked[tid]
                            yield _ev("pipeline", stage="match", guess=candidate, match=True)
                            yield _ev("match", target_id=target.id, plain_password=candidate,
                                      stored_hash=target.hash_value, generated_hash="(verified)",
                                      crack_time_ms=round(crack_ms, 4),
                                      attempt_number=total_attempts, algo=algorithm)
                            yield _ev("target_status", target_id=target.id, status="cracked",
                                      algo=algorithm, plain_password=candidate,
                                      crack_time_ms=round(crack_ms, 4))
                    except Exception:
                        pass

            if stopped_early:
                break

        if stopped_early:
            break

    for tid, target in uncracked.items():
        status = "timeout" if stopped_early else "failed"
        yield _ev("target_status", target_id=target.id, status=status, algo=algorithm)

    elapsed = (_now() - t0) * 1000
    yield _ev("algo_complete", algo=algorithm, cracked=len(cracked), total=len(targets),
              elapsed_ms=round(elapsed, 2), stopped_early=stopped_early, attempts=total_attempts,
              note=_timeout_note(algorithm, stopped_early, len(cracked), len(targets)))


# ── Dispatcher ───────────────────────────────────────────────────────────────

def stream_attack(
    targets: list,
    algorithm: str,
    attack_type: str,
    wordlist: list[str],
    max_attempts: int = 100_000,
    timeout_sec: float = 60.0,
    demo_mode: bool = False,
) -> Generator[dict, None, None]:
    """Dispatch to the correct streaming attack generator."""

    if attack_type == "dictionary":
        yield from stream_dictionary_attack(targets, algorithm, wordlist, max_attempts, timeout_sec)
    elif attack_type == "brute_force":
        yield from stream_brute_force_attack(
            targets, algorithm,
            max_attempts=max_attempts, timeout_sec=timeout_sec, demo_mode=demo_mode
        )
    elif attack_type == "rainbow_table":
        yield from stream_rainbow_attack(targets, algorithm, wordlist, max_attempts, timeout_sec)
    elif attack_type == "hybrid":
        yield from stream_hybrid_attack(targets, algorithm, wordlist, max_attempts, timeout_sec)
    else:
        yield _ev("error", message=f"Unknown attack type: {attack_type}")


# ── Timeout note ─────────────────────────────────────────────────────────────

def _timeout_note(algorithm: str, stopped_early: bool, cracked: int, total: int) -> str:
    if algorithm == "plaintext":
        return "Plaintext storage provides zero security — all passwords instantly exposed."
    if not stopped_early:
        if cracked == 0:
            return f"{algorithm} resisted all attempts."
        return f"{cracked}/{total} passwords cracked."
    if algorithm in ("md5", "sha1", "sha256"):
        return (
            f"TIMEOUT ≠ SECURE. {algorithm.upper()} remains vulnerable to GPU hardware "
            "100,000x faster than this simulation."
        )
    if algorithm == "salted_sha256":
        return "Timeout. Salted SHA-256 resists rainbow tables but not targeted GPU brute-force."
    if algorithm in ("bcrypt", "argon2id"):
        return f"{algorithm} resisted — adaptive hardness by design, not simulation timeout."
    return "Attack timed out."
