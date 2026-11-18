"""One private host ledger per signed grant, independent of vault/imported records."""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import pwd
import stat
from decimal import Decimal
from pathlib import Path

from hyperresearch.core.x_artifacts import atomic_write
from hyperresearch.models.x_evidence import canonical_bytes, validate_definition


class BudgetError(PermissionError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def host_budget_root() -> Path:
    # HOME/XDG and proposed plan/config fields cannot select a fresh spend ledger.
    return Path(pwd.getpwuid(os.getuid()).pw_dir) / ".local" / "state" / "hyperresearch" / "x" / "budgets"


def _private(path: Path, *, directory: bool) -> None:
    details = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(details.st_mode) or details.st_uid != os.getuid() or details.st_mode & 0o077:
        raise BudgetError("unsafe_host_budget_path")


def _ancestors(path: Path) -> None:
    for component in reversed([path, *path.parents]):
        if component.is_symlink():
            raise BudgetError("symlinked_host_budget_path")
        if component.exists() and not component.is_dir():
            raise BudgetError("invalid_host_budget_ancestor")


def _unique_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate budget ledger key")
        result[key] = value
    return result


def _cell(decimal: bool = False) -> dict:
    zero = "0" if decimal else 0
    return {"reserved": zero, "actual": zero, "unknown": zero}


class GrantBudget:
    def __init__(self, grant: dict):
        self.digest, self.approval_id = grant["grant_digest"], grant["approval_id"]
        if len(self.digest) != 64 or any(character not in "0123456789abcdef" for character in self.digest):
            raise BudgetError("invalid_grant_ledger_identity")
        self.root = host_budget_root()
        self.path = self.root / (self.digest + ".json")
        self.lock_path = self.root / (self.digest + ".lock")
        self.state = None

    @contextlib.contextmanager
    def locked(self):
        _ancestors(self.root)
        self.root.mkdir(parents=True, mode=0o700, exist_ok=True)
        _private(self.root, directory=True)
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = os.open(self.lock_path, flags, 0o600)
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid() or details.st_mode & 0o077:
                raise BudgetError("unsafe_host_budget_lock")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            if self.path.exists() or self.path.is_symlink():
                _private(self.path, directory=False)
                source = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    with os.fdopen(source, "r", encoding="utf-8") as stream:
                        self.state = validate_definition("grant-ledger", json.load(stream, object_pairs_hook=_unique_pairs))
                except Exception:
                    # fdopen owns the descriptor even when parsing fails. Never
                    # substitute an empty balance for corrupt/missing history.
                    raise BudgetError("invalid_host_budget_ledger") from None
                if self.state["grant_digest"] != self.digest or self.state["approval_id"] != self.approval_id:
                    raise BudgetError("host_budget_identity_mismatch")
            else:
                self.state = {"schema_version": 1, "purpose": "x-research-budget-ledger",
                              "grant_digest": self.digest, "approval_id": self.approval_id, "revision": 1,
                              "accounting": {"analysis": {"requests": _cell(), "tokens": _cell(), "cost_usd": _cell(True)},
                                             "observations": {"requests": _cell()}},
                              "model_request_ids": [], "observation_request_ids": []}
                self.state = validate_definition("grant-ledger", self.state)
            yield self
        finally:
            self.state = None
            os.close(descriptor)

    def total(self, section: str, key: str) -> Decimal:
        return sum((Decimal(str(value)) for value in self.state["accounting"][section][key].values()), Decimal(0))

    def change(self, section: str, key: str, bucket: str, amount) -> None:
        cell = self.state["accounting"][section][key]
        result = Decimal(str(cell[bucket])) + Decimal(str(amount))
        if not result.is_finite() or result < 0 or (not isinstance(cell[bucket], str) and result != result.to_integral_value()):
            raise BudgetError("host_budget_accounting_underflow_or_fraction")
        cell[bucket] = format(result, "f") if isinstance(cell[bucket], str) else int(result)

    def save(self) -> None:
        self.state["revision"] += 1
        validated = validate_definition("grant-ledger", self.state)
        atomic_write(self.path, canonical_bytes(validated))
        _private(self.path, directory=False)
