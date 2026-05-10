"""
Attack Registry & Runner - CipherGuard Phase 3

Central factory that maps attack names to instances.
Also contains the orchestrated multi-algorithm benchmark runner.
"""

import logging
from typing import Optional

from backend.attacks.dictionary_attack  import DictionaryAttack
from backend.attacks.brute_force_attack import BruteForceAttack
from backend.attacks.rainbow_table_attack import RainbowTableAttack
from backend.attacks.hybrid_attack      import HybridAttack
from backend.attacks.base_attack        import AttackReport

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Registry: attack-name -> class (not instance, to allow fresh state)
# ---------------------------------------------------------------------------

ATTACK_REGISTRY: dict = {
    "dictionary"   : DictionaryAttack,
    "brute_force"  : BruteForceAttack,
    "rainbow_table": RainbowTableAttack,
    "hybrid"       : HybridAttack,
}

ALL_ATTACK_TYPES = list(ATTACK_REGISTRY.keys())


def get_attack(attack_type: str):
    """
    Retrieve a fresh attack instance by name.

    Args:
        attack_type: One of the keys in ATTACK_REGISTRY

    Returns:
        Attack instance (subclass of BaseAttack)

    Raises:
        ValueError: If attack type is not registered
    """
    key = attack_type.lower().strip()
    if key not in ATTACK_REGISTRY:
        supported = ", ".join(ATTACK_REGISTRY.keys())
        raise ValueError(
            f"Unknown attack type '{attack_type}'. Supported: {supported}"
        )
    return ATTACK_REGISTRY[key]()
