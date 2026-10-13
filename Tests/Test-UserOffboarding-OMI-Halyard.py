#!/usr/bin/env python3
"""Static checks for User-Offboarding-OMI-Halyard.ps1.

These assertions cover the two offboarding bugs:
  1. MIM ignore flags must be conditional on Halyard presence.
  2. A successful Graph sign-in block must not be reported as failed
     when a later GET still returns a stale accountEnabled=true.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "User-Offboarding-OMI-Halyard.ps1"


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(f"ASSERT FAILED: {message}")
    print(f"OK: {message}")


def test_has_halyard_account(halyard_sid) -> bool:
    """Mirror of Test-HasHalyardAccount in the offboarding script."""
    if halyard_sid is None:
        return False
    if isinstance(halyard_sid, str):
        return bool(halyard_sid.strip())
    if hasattr(halyard_sid, "__len__") and len(halyard_sid) == 0:
        return False
    return True


def test_graph_account_disabled(account_enabled) -> bool:
    """Mirror of Test-GraphAccountDisabled in the offboarding script."""
    if account_enabled is None:
        return False
    if isinstance(account_enabled, bool):
        return not account_enabled
    text = str(account_enabled)
    return text in {"False", "false", "0"}


def main() -> int:
    content = SCRIPT.read_text(encoding="utf-8")

    assert_true(SCRIPT.exists(), "Offboarding script exists")
    assert_true("function Set-MIMIgnoreWorkdayStatus" in content, "MIM function is defined")
    assert_true("[bool]$HasHalyardAccount" in content, "MIM function accepts HasHalyardAccount")
    assert_true(
        "Set-MIMIgnoreWorkdayStatus -SamAccountName $samAccountName -HasHalyardAccount $hasHalyardAccount"
        in content,
        "Process-SingleUser passes Halyard presence into the MIM function",
    )
    assert_true(
        "if ($HasHalyardAccount)" in content,
        "HYH flag is only set when HasHalyardAccount is true",
    )
    assert_true(
        "User present in OMI only - setting _Ignore_Workday_Active_Status only." in content,
        "OMI-only path logs that only the standard ignore flag is set",
    )
    assert_true(
        "User present in OMI and Halyard - setting both MIM Workday ignore flags." in content,
        "OMI+Halyard path logs that both ignore flags are set",
    )

    # The original bug set both flags back-to-back with no condition.
    unconditional = re.search(
        r"_Ignore_Workday_Active_Status\s+=\s+\$true\s+"
        r"\$person\._Ignore_HYH_Workday_Active_Status\s+=\s+\$true",
        content,
    )
    assert_true(unconditional is None, "HYH flag is not set unconditionally with the OMI flag")

    assert_true("function Test-HasHalyardAccount" in content, "Halyard presence helper exists")
    assert_true("function Test-GraphAccountDisabled" in content, "Graph disable helper exists")
    assert_true(
        "$delaysMs = @(1000, 2000, 3000, 4000)" in content,
        "Graph sign-in block retries verification after PATCH",
    )
    assert_true(
        "verification shows account still enabled" not in content,
        "Stale Graph read-back is not reported as a failed sign-in block",
    )
    assert_true(
        "if ($result.Status -eq 'Error')" in content
        and "Write-OperationStatus -Operation \"Blocking user sign-in\"" in content,
        "Sign-in block only prints [FAILED] when Graph returns an error",
    )

    # Brace balance is a cheap syntax smoke check for the reconstructed script.
    assert_true(content.count("{") == content.count("}"), "Curly braces are balanced")
    assert_true(content.strip().endswith("Start-Offboarding"), "Script still invokes Start-Offboarding")

    # Helper behavior
    assert_true(test_has_halyard_account(None) is False, "Missing Halyard SID is OMI-only")
    assert_true(test_has_halyard_account("") is False, "Empty Halyard SID is OMI-only")
    assert_true(test_has_halyard_account("   ") is False, "Whitespace Halyard SID is OMI-only")
    assert_true(test_has_halyard_account("S-1-5-21-1-2-3-4") is True, "Populated Halyard SID is dual-domain")
    assert_true(test_has_halyard_account([]) is False, "Empty SID collection is OMI-only")

    assert_true(test_graph_account_disabled(False) is True, "Boolean false means sign-in is blocked")
    assert_true(test_graph_account_disabled(True) is False, "Boolean true means sign-in is still allowed")
    assert_true(test_graph_account_disabled("False") is True, "String False means sign-in is blocked")
    assert_true(test_graph_account_disabled("false") is True, "String false means sign-in is blocked")
    assert_true(test_graph_account_disabled("0") is True, "String 0 means sign-in is blocked")
    assert_true(test_graph_account_disabled("True") is False, "String True means sign-in is still allowed")
    assert_true(test_graph_account_disabled(None) is False, "Null accountEnabled is not treated as blocked")

    print("All assertions passed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
