"""
LocalVault Generator Engine
Generates cryptographically secure passwords, EFF-style Diceware passphrases,
and API key tokens with real-time entropy calculation.
"""

import secrets
import string
import math
from typing import Tuple, List

# Embedded EFF-inspired high-entropy wordlist for offline Diceware passphrases
WORDLIST: List[str] = [
    "acorn", "alchemy", "alpine", "amber", "anchor", "anthem", "apex", "apollo",
    "arcade", "arctic", "armor", "arrow", "astral", "atlas", "atom", "aurora",
    "avatar", "azure", "badger", "banner", "beacon", "blaze", "bolt", "boulder",
    "breeze", "bridge", "bronze", "buffer", "cactus", "canyon", "castle", "cedar",
    "cipher", "circuit", "cliff", "clover", "cobalt", "comet", "compass", "copper",
    "coral", "cosmic", "crater", "crest", "crystal", "dagger", "dawn", "delta",
    "denali", "desert", "diamond", "dune", "eagle", "echo", "eclipse", "ember",
    "emerald", "falcon", "feather", "flame", "flint", "forest", "fossil", "frost",
    "galaxy", "garnet", "geyser", "glacier", "glade", "granite", "grove", "harbor",
    "hawk", "haven", "hazard", "helix", "horizon", "iceberg", "impact", "indigo",
    "island", "jaguar", "javelin", "jungle", "jupiter", "kodiak", "lagoon", "lantern",
    "legacy", "legend", "lightning", "lynx", "magnet", "mantle", "maple", "matrix",
    "meadow", "meteor", "mirage", "monolith", "nebula", "neon", "nexus", "nomad",
    "nova", "oasis", "obsidian", "ocean", "olympus", "onyx", "orbit", "orca",
    "orion", "outpost", "paladin", "panther", "pebble", "phantom", "phoenix", "pioneer",
    "planet", "plasma", "polar", "prism", "pulsar", "pyramid", "quartz", "quasar",
    "radar", "radius", "raven", "reef", "relic", "ridge", "river", "rocket",
    "saddle", "safari", "sapphire", "saturn", "savanna", "scarlet", "shadow", "shield",
    "sierra", "signal", "silver", "solstice", "spark", "spectrum", "sphere", "summit",
    "sunset", "talisman", "temple", "timber", "titan", "topaz", "tornado", "tracer",
    "tundra", "twilight", "uranus", "valkyrie", "valley", "vapor", "vector", "velocity",
    "venture", "vertex", "vessel", "viking", "viper", "vortex", "voyage", "vulcan",
    "warrior", "wave", "whisper", "wildcat", "willow", "winter", "wizard", "zenith",
    "zephyr", "zero", "zodiac"
]

AMBIGUOUS_CHARS = "1lI0O"


def evaluate_password_strength(password: str) -> Tuple[float, str, int, str]:
    """
    Evaluates password strength based on strict character-type rules and length thresholds:
    - Character variety: Lowercase (a-z), Uppercase (A-Z), Numbers (0-9), Special characters (!@#$%...)
    - Minimum length for 'Strong': At least 10 characters INCLUDING ALL 4 character types.
    - Threshold for 'Military-Grade': 12 to 14+ characters INCLUDING ALL 4 character types.
    - If any required character type is missing, the password cannot be rated Strong or Military-Grade.
    
    Returns:
        (entropy_bits, rating_label, score_percent, feedback_hint)
    """
    if not password:
        return 0.0, "Empty", 0, "Enter a password"

    length = len(password)
    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digit = any(c in string.digits for c in password)
    has_special = any(c in string.punctuation or (not c.isalnum() and not c.isspace()) for c in password)

    types_count = sum([has_lower, has_upper, has_digit, has_special])

    # Calculate raw pool size and Shannon entropy bits
    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_special:
        pool_size += 32
    if pool_size == 0:
        pool_size = 1

    entropy_bits = round(length * math.log2(pool_size), 1)

    # Missing categories for clear actionable guidance
    missing = []
    if not has_lower:
        missing.append("lowercase (a-z)")
    if not has_upper:
        missing.append("uppercase (A-Z)")
    if not has_digit:
        missing.append("numbers (0-9)")
    if not has_special:
        missing.append("special symbols (!@#$)")

    # Rule-Based Evaluation:
    # Tier 1: All 4 character types present
    if types_count == 4:
        if length >= 14:
            rating = "Military-Grade"
            score_pct = 100
            hint = "All character types present (14+ chars)"
        elif length >= 12:
            rating = "Military-Grade"
            score_pct = 90
            hint = "All character types present (12-14 chars)"
        elif length >= 10:
            rating = "Strong"
            score_pct = 75
            hint = f"All types present. Add {12 - length} more char(s) for Military-Grade"
        elif length >= 8:
            rating = "Moderate"
            score_pct = 55
            hint = f"All types present. Need {10 - length} more char(s) for Strong"
        else:
            rating = "Weak"
            score_pct = 35
            hint = f"Too short. Need {10 - length} more char(s) for Strong"

    # Tier 2: 3 character types present (Missing 1 type -> cannot be Strong or Military-Grade)
    elif types_count == 3:
        missing_str = ", ".join(missing)
        if length >= 12:
            rating = "Moderate"
            score_pct = 55
            hint = f"Need: {missing_str}"
        elif length >= 10:
            rating = "Moderate"
            score_pct = 45
            hint = f"Need: {missing_str}"
        elif length >= 6:
            rating = "Weak"
            score_pct = 30
            hint = f"Need: {missing_str}"
        else:
            rating = "Very Weak"
            score_pct = 15
            hint = f"Need: {missing_str}"

    # Tier 3: 2 character types present
    elif types_count == 2:
        missing_str = ", ".join(missing)
        if length >= 12:
            rating = "Weak"
            score_pct = 35
            hint = f"Need: {missing_str}"
        elif length >= 8:
            rating = "Weak"
            score_pct = 25
            hint = f"Need: {missing_str}"
        else:
            rating = "Very Weak"
            score_pct = 15
            hint = f"Need: {missing_str}"

    # Tier 4: Only 1 character type present (all letters or all digits)
    else:
        missing_str = ", ".join(missing)
        rating = "Very Weak"
        score_pct = 10
        hint = f"Need: {missing_str}"

    return entropy_bits, rating, score_pct, hint


def calculate_entropy(password: str) -> Tuple[float, str]:
    """
    Calculates the Shannon entropy and returns the rule-based rating.
    Returns (entropy_bits, rating_label).
    """
    bits, rating, _, _ = evaluate_password_strength(password)
    return bits, rating


def generate_password(
    length: int = 20,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_special: bool = True,
    avoid_ambiguous: bool = True,
) -> str:
    """
    Generates a cryptographically secure random password guaranteeing at least one
    character from each chosen category.
    """
    pools = []
    guaranteed = []

    if use_lower:
        chars = string.ascii_lowercase
        if avoid_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
        pools.append(chars)
        guaranteed.append(secrets.choice(chars))

    if use_upper:
        chars = string.ascii_uppercase
        if avoid_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
        pools.append(chars)
        guaranteed.append(secrets.choice(chars))

    if use_digits:
        chars = string.digits
        if avoid_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
        pools.append(chars)
        guaranteed.append(secrets.choice(chars))

    if use_special:
        chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        pools.append(chars)
        guaranteed.append(secrets.choice(chars))

    if not pools:
        pools = [string.ascii_letters + string.digits]
        guaranteed = [secrets.choice(pools[0])]

    all_chars = "".join(pools)
    remaining_length = max(0, length - len(guaranteed))
    random_chars = [secrets.choice(all_chars) for _ in range(remaining_length)]

    full_list = guaranteed + random_chars
    # Cryptographically secure in-place shuffle
    for i in range(len(full_list) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        full_list[i], full_list[j] = full_list[j], full_list[i]

    return "".join(full_list)


def generate_passphrase(
    num_words: int = 5,
    separator: str = "-",
    capitalize: bool = True,
) -> str:
    """Generates a memorable Diceware passphrase from the EFF wordlist."""
    selected = [secrets.choice(WORDLIST) for _ in range(num_words)]
    if capitalize:
        selected = [w.capitalize() for w in selected]
    return separator.join(selected)


def generate_api_key(
    prefix: str = "sk_live_",
    length: int = 32,
    mode: str = "hex",  # 'hex', 'base64', 'alphanumeric'
) -> str:
    """
    Generates standard formatted API tokens/keys with custom prefixes.
    e.g. 'sk_live_a3f892c90...'
    """
    if mode == "hex":
        # Each byte generates 2 hex chars
        byte_count = (length + 1) // 2
        token = secrets.token_hex(byte_count)[:length]
    elif mode == "base64":
        token = secrets.token_urlsafe(length)[:length]
    else:
        alphabet = string.ascii_letters + string.digits
        token = "".join(secrets.choice(alphabet) for _ in range(length))

    return f"{prefix}{token}"
