"""Bounded GitHub operations for the CyberShield terminal.

Uses the official GitHub CLI (gh) only. No arbitrary shell is exposed.
Destructive repository operations (delete, force-push, visibility changes) are
not supported here.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


class GitHubTerminalError(RuntimeError):
    pass


def _gh() -> str:
    path = shutil.which("gh")
    if not path:
        raise GitHubTerminalError("GitHub CLI (gh) is not installed or is not on PATH.")
    return path


def _run(args: list[str], cwd: str | Path | None = None, timeout: int = 45) -> dict[str, Any]:
    if not args or args[0] not in {"gh", "git"}:
        raise GitHubTerminalError("Invalid GitHub command.")
    env = os.environ.copy()
    env["GH_PROMPT_DISABLED"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    p = subprocess.run(args, cwd=str(cwd) if cwd else None, capture_output=True,
                       text=True, encoding="utf-8", errors="replace", timeout=timeout,
                       env=env, shell=False)
    out = (p.stdout or "").strip()
    err = (p.stderr or "").strip()
    # Never return environment variables or auth headers; gh normally masks tokens,
    # but the terminal layer should still avoid exposing sensitive-looking strings.
    return {"ok": p.returncode == 0, "code": p.returncode, "stdout": out, "stderr": err[-4000:]}


def github_command(args: list[str], cwd: str | Path | None = None) -> dict[str, Any]:
    """Execute one allowlisted gh operation."""
    if not args:
        return {"ok": True, "commands": [
            "github auth", "github status", "github open", "github publish [name] [--private|--public]",
            "github commit <message>", "github push", "github pull", "github clone <OWNER/REPO> [dir]",
        ]}
    op = args[0].lower()
    rest = args[1:]
    base = _gh()
    if op == "auth":
        return _run([base, "auth", "status"], cwd)
    if op == "status":
        return _run([base, "repo", "view"], cwd)
    if op == "open":
        return _run([base, "repo", "view", "--web"], cwd)
    if op == "pull" and not rest:
        return _run(["git", "pull", "--ff-only"], cwd) if shutil.which("git") else {"ok": False, "stderr": "git not installed"}
    if op == "push" and not rest:
        return _run(["git", "push"], cwd) if shutil.which("git") else {"ok": False, "stderr": "git not installed"}
    if op == "commit":
        if not rest:
            raise GitHubTerminalError("Usage: github commit <message>")
        if not shutil.which("git"):
            raise GitHubTerminalError("git is not installed or not on PATH.")
        msg = " ".join(rest).strip()
        if len(msg) > 200:
            raise GitHubTerminalError("Commit message is too long.")
        add = _run(["git", "add", "-A"], cwd)
        if not add["ok"]:
            return add
        return _run(["git", "commit", "-m", msg], cwd)
    if op == "publish":
        name = rest[0] if rest and not rest[0].startswith("--") else Path(cwd or Path.cwd()).name
        visibility = "--private"
        if "--public" in rest:
            visibility = "--public"
        elif "--private" in rest:
            visibility = "--private"
        # gh_repo_create handles an existing source directory and can push the initial branch.
        return _run([base, "repo", "create", name, visibility, "--source", ".", "--remote", "origin", "--push"], cwd, timeout=90)
    if op == "clone":
        if not rest or len(rest) > 2:
            raise GitHubTerminalError("Usage: github clone OWNER/REPO [directory]")
        cmd = [base, "repo", "clone", rest[0]] + ([rest[1]] if len(rest) == 2 else [])
        return _run(cmd, cwd, timeout=120)
    raise GitHubTerminalError("Unsupported GitHub operation. Use: github auth|status|open|publish|commit|push|pull|clone")
