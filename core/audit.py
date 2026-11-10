"""
LocalVault Security Audit Engine (Local Watchtower)
Performs automated offline health checks on vault credentials:
- Identifies weak passwords & insufficient entropy
- Flags reused passwords across multiple accounts
- Detects logins lacking 2FA Authenticator protection
- Alerts on expired API keys and overdue rotation schedules
- Calculates an overall Vault Health Score (0-100) and Letter Grade
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Tuple
from collections import defaultdict

from core.models import VaultData, APIKeyEntry, LoginEntry
from core.generator import evaluate_password_strength


@dataclass
class AuditIssue:
    severity: str  # 'CRITICAL', 'WARNING', 'INFO'
    category: str  # 'Weak Password', 'Reused Password', 'Missing 2FA', 'Expired Key', 'Stale Rotation'
    item_id: str
    item_title: str
    item_type: str  # 'login', 'api_key'
    description: str
    recommendation: str


@dataclass
class AuditReport:
    score: int  # 0 to 100
    grade: str  # A+, A, B, C, F
    total_items_scanned: int
    weak_passwords_count: int
    reused_passwords_count: int
    missing_2fa_count: int
    expired_keys_count: int
    stale_keys_count: int
    issues: List[AuditIssue] = field(default_factory=list)


def run_vault_audit(vault_data: VaultData) -> AuditReport:
    """
    Executes a comprehensive offline security audit across all items in the vault.
    """
    issues: List[AuditIssue] = []

    password_map = defaultdict(list)
    weak_count = 0
    missing_2fa_count = 0
    expired_keys_count = 0
    stale_keys_count = 0

    now_utc = datetime.now(timezone.utc)

    # 1. Inspect Logins
    for login in vault_data.logins:
        # A. Password Strength
        if login.password:
            bits, rating, score_pct, hint = evaluate_password_strength(login.password)
            if rating in ["Weak", "Very Weak"] or score_pct < 50:
                weak_count += 1
                issues.append(
                    AuditIssue(
                        severity="CRITICAL" if rating == "Very Weak" else "WARNING",
                        category="Weak Password",
                        item_id=login.id,
                        item_title=login.title,
                        item_type="login",
                        description=f"Password rated {rating} ({score_pct}%). {hint}",
                        recommendation="Generate a military-grade password with 12+ characters and symbols.",
                    )
                )

            # Map for reuse detection
            password_map[login.password].append(login.title)

        # B. Missing 2FA Authenticator
        if not login.totp_secret:
            missing_2fa_count += 1
            issues.append(
                AuditIssue(
                    severity="INFO",
                    category="Missing 2FA",
                    item_id=login.id,
                    item_title=login.title,
                    item_type="login",
                    description="No two-factor authenticator seed configured for this service.",
                    recommendation="Add a TOTP seed or scan the 2FA QR code to enable built-in rolling codes.",
                )
            )

    # 2. Inspect Password Reuses
    reused_count = 0
    for pwd, titles in password_map.items():
        if len(titles) > 1:
            reused_count += len(titles)
            names_str = ", ".join(titles)
            for title in titles:
                # Find matching item ID
                match_id = next((l.id for l in vault_data.logins if l.title == title), "")
                issues.append(
                    AuditIssue(
                        severity="CRITICAL",
                        category="Reused Password",
                        item_id=match_id,
                        item_title=title,
                        item_type="login",
                        description=f"Shares an identical password with: {names_str}.",
                        recommendation="Use distinct, unique passwords for every service to avoid credential stuffing.",
                    )
                )

    # 3. Inspect API Keys
    for api_key in vault_data.api_keys:
        # Check Expiration
        if api_key.expires_at:
            try:
                exp_dt = datetime.fromisoformat(api_key.expires_at.replace("Z", "+00:00"))
                if now_utc > exp_dt:
                    expired_keys_count += 1
                    issues.append(
                        AuditIssue(
                            severity="CRITICAL",
                            category="Expired Key",
                            item_id=api_key.id,
                            item_title=api_key.name,
                            item_type="api_key",
                            description=f"API Key expired on {exp_dt.strftime('%Y-%m-%d')}.",
                            recommendation="Rotate this credential immediately and delete obsolete tokens.",
                        )
                    )
                elif now_utc + timedelta(days=14) > exp_dt:
                    issues.append(
                        AuditIssue(
                            severity="WARNING",
                            category="Expiring Soon",
                            item_id=api_key.id,
                            item_title=api_key.name,
                            item_type="api_key",
                            description=f"API Key will expire within 14 days ({exp_dt.strftime('%Y-%m-%d')}).",
                            recommendation="Plan token rotation before service disruption.",
                        )
                    )
            except Exception:
                pass

        # Check Stale Rotation Schedule
        if api_key.last_rotated_at:
            try:
                rotated_dt = datetime.fromisoformat(api_key.last_rotated_at.replace("Z", "+00:00"))
                max_days = api_key.rotation_interval_days or 90
                days_since = (now_utc - rotated_dt).days
                if days_since > max_days:
                    stale_keys_count += 1
                    issues.append(
                        AuditIssue(
                            severity="WARNING",
                            category="Stale Rotation",
                            item_id=api_key.id,
                            item_title=api_key.name,
                            item_type="api_key",
                            description=f"Key has not been rotated in {days_since} days (policy: {max_days} days).",
                            recommendation="Rotate key in your provider console and update the record.",
                        )
                    )
            except Exception:
                pass

    total_scanned = len(vault_data.logins) + len(vault_data.api_keys)

    # Score Calculation: Start with 100 and apply deductions
    score = 100
    score -= weak_count * 15
    score -= (reused_count // 2) * 20
    score -= expired_keys_count * 20
    score -= stale_keys_count * 10
    score -= missing_2fa_count * 5

    score = max(0, min(100, score))

    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 50:
        grade = "C"
    else:
        grade = "F"

    # Sort issues by severity: CRITICAL first, then WARNING, then INFO
    severity_order = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
    issues.sort(key=lambda x: severity_order.get(x.severity, 3))

    return AuditReport(
        score=score,
        grade=grade,
        total_items_scanned=total_scanned,
        weak_passwords_count=weak_count,
        reused_passwords_count=reused_count,
        missing_2fa_count=missing_2fa_count,
        expired_keys_count=expired_keys_count,
        stale_keys_count=stale_keys_count,
        issues=issues,
    )
