"""
Custom Password Attack SSE Routes — CipherGuard

Implements the Custom Password Attack Mode:

  POST /api/v1/custom-stream-attack
    Body: { password, algorithm, attack_type, timeout_sec }
    Creates an in-memory attack session.
    Returns: { attack_id, algorithm, attack_type, message }

  GET /api/v1/custom-stream-attack/{attack_id}/stream
    Opens an SSE stream for the attack session.
    Pops the session from memory (one-time use).
    Streams exactly the same event types as /api/v1/stream-attack.

Security guarantees:
  - Plaintext password is NEVER stored in SQLite
  - Plaintext password is NEVER written to any log
  - Plaintext password is NEVER included in the target object passed to the engine
  - Sessions are in-memory only (SESSION_STORE dict)
  - Sessions are removed (popped) the moment streaming begins
  - Any remaining session is garbage-collected after stream completes

Architecture:
  EventSource is GET-only, so we use a two-step flow:
    1. POST   → hash password → create SimpleNamespace target → store session → return attack_id
    2. GET    → pop session → spawn attack thread → SSE stream
"""

import json
import uuid
import asyncio
import logging
import math
from types import SimpleNamespace
from threading import Thread
from queue import Queue, Empty
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from backend.schemas.attack_schemas import CustomAttackRequest, CustomAttackSessionResponse
from backend.hashers.hasher_registry import get_hasher
from backend.attacks.streaming_attack_runner import stream_attack
from backend.attacks.dictionary_attack import DictionaryAttack

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Custom Attack"])

# ---------------------------------------------------------------------------
# In-memory session store
# Key:   attack_id (UUID string)
# Value: dict with target, wordlist, attack params
# Sessions are popped (deleted) as soon as the stream starts.
# ---------------------------------------------------------------------------
SESSION_STORE: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CACHED_WORDLIST: Optional[list[str]] = None

def _load_wordlist() -> list[str]:
    """Load dictionary wordlist — reuses existing DictionaryAttack wordlist."""
    global _CACHED_WORDLIST
    if _CACHED_WORDLIST is not None:
        return _CACHED_WORDLIST
    try:
        _CACHED_WORDLIST = DictionaryAttack().wordlist
        return _CACHED_WORDLIST
    except Exception:
        _CACHED_WORDLIST = [
            "password", "123456", "admin", "qwerty", "letmein", "dragon", "monkey",
            "iloveyou", "welcome", "football", "shadow", "master", "abc123", "test",
            "pass", "hello", "login", "admin123", "abc", "secret", "root", "user",
            "hello123", "password1", "111111", "trustno1", "sunshine", "princess",
        ]


def _compute_strength(password: str) -> tuple[str, float]:
    """
    Compute a basic strength category and entropy estimate.
    Used only to populate the target metadata — not for display.
    Returns (strength_category, entropy_bits).
    """
    length = len(password)
    charset = 0
    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(not c.isalnum() for c in password):
        charset += 32
    if charset == 0:
        charset = 26

    entropy = length * math.log2(charset) if charset > 1 else 0.0

    if entropy < 28 or length < 6:
        category = "weak"
    elif entropy < 50 or length < 10:
        category = "moderate"
    else:
        category = "strong"

    return category, round(entropy, 2)


# ---------------------------------------------------------------------------
# POST /api/v1/custom-stream-attack
# ---------------------------------------------------------------------------

@router.post(
    "/custom-stream-attack",
    response_model=CustomAttackSessionResponse,
    summary="Create a custom password attack session",
    description=(
        "Hash the user-supplied password with the chosen algorithm and create "
        "an in-memory attack session. Returns an attack_id. The plaintext password "
        "is NEVER stored in any database, log, or file. Only the derived hash is "
        "used by the attack engine."
    ),
)
async def create_custom_attack_session(body: CustomAttackRequest):
    """
    Step 1 of the two-step SSE flow.

    Hashes the password, creates a SimpleNamespace target (no DB write),
    stores the session in SESSION_STORE, and returns an attack_id.
    """
    algorithm  = body.algorithm
    attack_type = body.attack_type
    password   = body.password        # used to generate hash, then discarded
    timeout_sec = body.timeout_sec

    # ── Hash the password using the existing hasher registry ──────────────
    try:
        hasher = get_hasher(algorithm)
        hash_result = hasher.hash_password(password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error("[CustomAttack] Hashing error for algorithm=%s: %s", algorithm, type(exc).__name__)
        raise HTTPException(status_code=500, detail="Failed to hash password with the selected algorithm.")

    # ── Build strength metadata (no plaintext stored) ─────────────────────
    strength_category, entropy_bits = _compute_strength(password)
    pwd_length = len(password)

    # ── Create in-memory target (NO plaintext password stored here) ────────
    target = SimpleNamespace(
        id               = 1,
        hash_value       = hash_result.hash_value,
        salt             = hash_result.salt,           # None for unsalted algos
        algorithm        = algorithm,
        plain_password   = "",                          # intentionally blank — attacker must crack it
        strength_category= strength_category,
        length           = pwd_length,
        entropy_bits     = entropy_bits,
    )

    # ── Store session (memory only — never touches DB) ─────────────────────
    attack_id = str(uuid.uuid4())
    SESSION_STORE[attack_id] = {
        "target"      : target,
        "wordlist"    : _load_wordlist(),
        "algorithm"   : algorithm,
        "attack_type" : attack_type,
        "timeout_sec" : timeout_sec,
        "pwd_length"  : pwd_length,
        "strength"    : strength_category,
    }

    logger.info(
        "[CustomAttack] Session created: id=%s algo=%s attack=%s strength=%s len=%d",
        attack_id[:8], algorithm, attack_type, strength_category, pwd_length,
    )

    # ── Return attack_id — plaintext password is NOT in the response ───────
    return CustomAttackSessionResponse(
        attack_id   = attack_id,
        algorithm   = algorithm,
        attack_type = attack_type,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/custom-stream-attack/{attack_id}/stream
# ---------------------------------------------------------------------------

@router.get(
    "/custom-stream-attack/{attack_id}/stream",
    summary="Stream custom attack events via Server-Sent Events",
    description=(
        "Step 2 of the two-step SSE flow. Pops the session from memory, "
        "launches the attack in a background thread, and streams events "
        "in the same format as /api/v1/stream-attack. "
        "Session is automatically cleaned up after streaming completes."
    ),
)
async def stream_custom_attack(attack_id: str):
    """
    Step 2 of the two-step SSE flow.

    Pops the session from SESSION_STORE (one-time use — prevents replay),
    spawns a background thread running stream_attack(), and streams events.
    """
    session = SESSION_STORE.pop(attack_id, None)
    if session is None:
        raise HTTPException(
            status_code=404,
            detail=f"Attack session '{attack_id}' not found or already consumed.",
        )

    target      = session["target"]
    wordlist    = session["wordlist"]
    algorithm   = session["algorithm"]
    attack_type = session["attack_type"]
    timeout_sec = session["timeout_sec"]
    pwd_length  = session["pwd_length"]
    strength    = session["strength"]

    # ── Metadata for the initial target_list event ─────────────────────────
    target_list_payload = {
        "type"       : "target_list",
        "algorithm"  : algorithm,
        "attack_type": attack_type,
        "targets"    : [
            {
                "id"              : target.id,
                "algorithm"       : target.algorithm,
                "hash_value"      : target.hash_value,
                "salt"            : target.salt,
                "plain_password"  : "",           # NOT revealed — attacker must crack it
                "length"          : target.length,
                "strength_category": target.strength_category,
                "entropy_bits"    : target.entropy_bits,
            }
        ],
        "wordlist_size" : len(wordlist),
        "search_space"  : f"{len(wordlist):,}",
        "ts"            : 0,
    }

    # ── Queue for events from background thread ────────────────────────────
    q: Queue = Queue(maxsize=5000)

    def attack_thread():
        """Run the attack in a background thread. Puts events into queue."""
        try:
            for event in stream_attack(
                targets      = [target],
                algorithm    = algorithm,
                attack_type  = attack_type,
                wordlist     = wordlist,
                max_attempts = 200_000,
                timeout_sec  = timeout_sec,
                demo_mode    = False,
            ):
                q.put(event)
        except Exception as exc:
            logger.exception("[CustomAttack] Attack thread error for session %s", attack_id[:8])
            q.put({
                "type"   : "error",
                "ts"     : 0,
                "message": f"Attack engine error: {type(exc).__name__}: {exc}",
            })
        finally:
            q.put(None)  # sentinel — signals the SSE generator to close

    Thread(target=attack_thread, daemon=True).start()
    logger.info("[CustomAttack] Attack thread started: id=%s algo=%s type=%s", attack_id[:8], algorithm, attack_type)

    # ── Async SSE generator ────────────────────────────────────────────────
    async def sse_gen():
        import time
        t0 = time.time() * 1000

        # Init event
        init_ev = {
            "type"         : "init",
            "algorithm"    : algorithm,
            "attack_type"  : attack_type,
            "target_count" : 1,
            "demo_mode"    : False,
            "ts"           : int(t0),
            "custom_mode"  : True,
            "pwd_length"   : pwd_length,
            "strength"     : strength,
        }
        target_list_payload["ts"] = int(t0)

        yield f"data: {json.dumps(init_ev)}\n\n"
        yield f"data: {json.dumps(target_list_payload)}\n\n"

        while True:
            try:
                event = q.get_nowait()
                if event is None:
                    # Attack complete — send done event then close
                    yield f"data: {json.dumps({'type': 'done', 'ts': int(time.time() * 1000)})}\n\n"
                    break
                if event.get("ts") == 0:
                    event["ts"] = int(time.time() * 1000)
                yield f"data: {json.dumps(event)}\n\n"
            except Empty:
                # Keep connection alive — use a proper data event (not comment)
                # because some proxies only reset buffer timeout on data: lines
                yield "data: {}\n\n"
                await asyncio.sleep(0.05)

    return StreamingResponse(
        sse_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control"                : "no-cache",
            "X-Accel-Buffering"            : "no",
            "Connection"                   : "keep-alive",
            "Access-Control-Allow-Origin"  : "*",
        },
    )
