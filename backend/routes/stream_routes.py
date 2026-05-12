"""
SSE Streaming Attack Routes — CipherGuard Real-Time Visualization

GET /api/v1/stream-attack
  Streams Server-Sent Events for live attack visualization.

ROOT CAUSE FIX:
  SQLAlchemy ORM objects are bound to the session thread. Passing them to a
  background thread causes DetachedInstanceError when accessing attributes.
  FIX: Convert to plain SimpleNamespace objects before spawning the thread.
"""

import json
import asyncio
import logging
from types import SimpleNamespace
from threading import Thread
from queue import Queue, Empty

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.password_hash_model import PasswordHash
from backend.attacks.streaming_attack_runner import stream_attack
from backend.attacks.dictionary_attack import DictionaryAttack
from backend.utils.attack_utils import estimate_search_space, estimate_gpu_crack_time

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Streaming Attack"])


def _load_wordlist() -> list[str]:
    try:
        return DictionaryAttack().wordlist
    except Exception:
        return [
            "password","123456","admin","qwerty","letmein","dragon","monkey",
            "iloveyou","welcome","football","shadow","master","abc123","test",
            "pass","hello","login","admin123","abc","secret","root","user",
        ]


def _orm_to_ns(t) -> SimpleNamespace:
    """Convert an ORM PasswordHash row to a plain object safe for background threads."""
    return SimpleNamespace(
        id               = t.id,
        hash_value       = t.hash_value or "",
        salt             = t.salt,
        algorithm        = t.algorithm or "",
        plain_password   = t.plain_password or "",
        strength_category= t.strength_category or "unknown",
        length           = t.length or 0,
        entropy_bits     = float(t.entropy_bits or 0.0),
    )


@router.get(
    "/stream-attack",
    summary="Real-time streaming attack via Server-Sent Events",
)
async def stream_attack_sse(
    request     : Request,
    attack_type : str   = Query(...),
    algorithm   : str   = Query(...),
    target_limit: int   = Query(20, ge=1, le=100),
    max_attempts: int   = Query(200_000, ge=100, le=1_000_000),
    timeout_sec : float = Query(60.0, ge=1.0, le=300.0),
    demo_mode   : bool  = Query(False),
    db          : Session = Depends(get_db),
):
    # ── Fetch & immediately detach from session ──────────────────
    orm_targets = (
        db.query(PasswordHash)
        .filter(PasswordHash.algorithm == algorithm)
        .limit(target_limit)
        .all()
    )

    if not orm_targets:
        err_msg = (
            f'No hashes found for algorithm "{algorithm}". '
            'Click "Gen Dataset" first, then Launch.'
        )
        err_payload = json.dumps({"type": "error", "ts": 0, "message": err_msg})
        async def no_data():
            yield f"data: {err_payload}\n\n"
        return StreamingResponse(no_data(), media_type="text/event-stream",
                                 headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

    # Convert to plain objects — safe for background thread
    targets = [_orm_to_ns(t) for t in orm_targets]
    db.close()  # explicitly close session before thread starts

    wordlist = _load_wordlist()

    # Metadata snapshot for the target_list event
    target_list_payload = {
        "type"        : "target_list",
        "algorithm"   : algorithm,
        "attack_type" : attack_type,
        "targets"     : [
            {
                "id"              : t.id,
                "algorithm"       : t.algorithm,
                "hash_value"      : t.hash_value,
                "salt"            : t.salt,
                "plain_password"  : t.plain_password,
                "length"          : t.length,
                "strength_category": t.strength_category,
                "entropy_bits"    : t.entropy_bits,
            }
            for t in targets
        ],
        "wordlist_size" : len(wordlist),
        "search_space"  : estimate_search_space(36, 5) if attack_type == "brute_force" else f"{len(wordlist):,}",
        "gpu_estimate"  : estimate_gpu_crack_time(
            algorithm,
            sum(36**l for l in range(1,6)) if attack_type == "brute_force" else len(wordlist)
        ),
        "ts": 0,
    }

    # ── Queue for events from background thread ───────────────────
    q: Queue = Queue(maxsize=5000)

    def attack_thread():
        try:
            for event in stream_attack(
                targets      = targets,
                algorithm    = algorithm,
                attack_type  = attack_type,
                wordlist     = wordlist,
                max_attempts = max_attempts,
                timeout_sec  = timeout_sec,
                demo_mode    = demo_mode,
            ):
                q.put(event)
        except Exception as e:
            logger.exception("[SSE] Attack thread error")
            q.put({"type": "error", "ts": 0, "message": f"Attack engine error: {str(e)}"})
        finally:
            q.put(None)  # sentinel — signals completion

    Thread(target=attack_thread, daemon=True).start()

    # ── Async SSE generator ───────────────────────────────────────
    async def sse_gen():
        import time
        t0 = time.time() * 1000

        # Send initial metadata immediately
        init_ev = {"type":"init","algorithm":algorithm,"attack_type":attack_type,
                   "target_count":len(targets),"demo_mode":demo_mode,"ts":int(t0)}
        target_list_payload["ts"] = int(t0)

        yield f"data: {json.dumps(init_ev)}\n\n"
        yield f"data: {json.dumps(target_list_payload)}\n\n"

        while True:
            try:
                event = q.get_nowait()
                if event is None:
                    yield f"data: {json.dumps({'type':'done','ts':int(time.time()*1000)})}\n\n"
                    break
                if event.get("ts") == 0:
                    event["ts"] = int(time.time() * 1000)
                yield f"data: {json.dumps(event)}\n\n"
            except Empty:
                # Keep connection alive + yield control to event loop
                yield ": ping\n\n"
                await asyncio.sleep(0.05)

    return StreamingResponse(
        sse_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control"    : "no-cache",
            "X-Accel-Buffering": "no",
            "Connection"       : "keep-alive",
            "Access-Control-Allow-Origin": "*",
        },
    )
