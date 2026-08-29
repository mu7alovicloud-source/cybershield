"""CyberShield CIBER Operator.

A small, auditable agent layer for useful developer/security tasks.  It never
passes user text to a shell.  Every external tool invocation is argv-based,
allowlisted, bounded by time, and followed by verification where possible.
"""
from __future__ import annotations
import re
import shutil
import subprocess
import json
import os
from pathlib import Path
from urllib.parse import urlparse

class ActionError(RuntimeError):
    pass

ALLOWED_TOOLS = {"gh", "git", "vercel", "pyinstaller", "python"}
MAX_OUTPUT = 12000


def _run(argv: list[str], cwd: Path | None = None, timeout: int = 180) -> dict:
    if not argv or argv[0].lower() not in ALLOWED_TOOLS:
        raise ActionError("BLOCKED: tool is not in the safe operator allowlist")
    exe = shutil.which(argv[0])
    if not exe:
        return {"ok": False, "code": 127, "stdout": "", "stderr": f"required tool not installed: {argv[0]}"}
    try:
        p = subprocess.run([exe, *argv[1:]], cwd=str(cwd) if cwd else None,
                           text=True, capture_output=True, timeout=timeout,
                           shell=False, check=False)
        return {"ok": p.returncode == 0, "code": p.returncode,
                "stdout": p.stdout[-MAX_OUTPUT:], "stderr": p.stderr[-MAX_OUTPUT:]}
    except subprocess.TimeoutExpired as exc:
        return {"ok": False, "code": 124,
                "stdout": str(exc.stdout or "")[-MAX_OUTPUT:],
                "stderr": "TIMEOUT: operation exceeded safety timeout"}


def _git_repo(root: Path) -> bool:
    return (root / ".git").is_dir()


def _verified_git_push(root: Path) -> bool:
    r = _run(["git", "push", "-u", "origin", "HEAD"], root)
    return r["ok"]


def _normalize_github_repo(value: str | None, root: Path) -> str | None:
    """Normalize OWNER/REPO or a GitHub repository URL without guessing credentials."""
    raw = (value or os.environ.get("CYBERSHIELD_GITHUB_REPO", "mu7alovicloud-source/CyberShield")).strip()
    if not raw:
        return None
    if raw.startswith(("https://", "http://")):
        parsed = urlparse(raw)
        if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
            raise ActionError("GitHub repository URL must point to github.com")
        parts = [x for x in parsed.path.strip("/").split("/") if x]
        if len(parts) == 1:
            # A GitHub account URL is useful as a destination hint; publish
            # the canonical CyberShield repository under that owner.
            return parts[0] + "/CyberShield"
        if len(parts) < 2:
            raise ActionError("Provide a repository URL such as https://github.com/OWNER/REPO")
        return "/".join(parts[:2]).removesuffix(".git")
    raw = raw.removeprefix("github.com/").strip("/")
    if raw.endswith(".git"):
        raw = raw[:-4]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", raw):
        raise ActionError("Repository must be OWNER/REPO or a GitHub repository URL")
    return raw


def _ensure_git_commit(root: Path, attempts: list[dict]) -> dict:
    """Create a local commit when needed; never include ignored .env/secrets."""
    if not _git_repo(root):
        init = _run(["git", "init", "-b", "main"], root, timeout=60)
        attempts.append({"strategy": "bootstrap", "name": "git-init", "result": init})
        if not init["ok"]:
            # Older Git versions may not support -b on init.
            init = _run(["git", "init"], root, timeout=60)
            attempts.append({"strategy": "bootstrap", "name": "git-init-fallback", "result": init})
        if not init["ok"]:
            return init

    add = _run(["git", "add", "-A"], root, timeout=90)
    attempts.append({"strategy": "bootstrap", "name": "stage", "result": add})
    if not add["ok"]:
        return add
    status = _run(["git", "status", "--porcelain"], root, timeout=30)
    attempts.append({"strategy": "bootstrap", "name": "staged-status", "result": status})
    if not status["ok"]:
        return status
    if status["stdout"].strip():
        commit = _run(["git", "commit", "-m", "CyberShield update"], root, timeout=90)
        attempts.append({"strategy": "bootstrap", "name": "commit", "result": commit})
        if not commit["ok"]:
            return commit
    return {"ok": True, "code": 0, "stdout": "working tree ready", "stderr": ""}


def github_publish(root: Path, repo: str | None = None, private: bool = True) -> dict:
    """Publish the current CyberShield project and verify the remote result.

    Accepted repository targets are OWNER/REPO or a full github.com URL.  The
    command uses only fixed argv-based git/gh operations; it never invokes a
    user-supplied shell command. Authentication is taken from the user's normal
    GitHub CLI/git credential setup.
    """
    root = root.resolve()
    attempts: list[dict] = []
    try:
        target = _normalize_github_repo(repo, root)
    except ActionError as exc:
        return {"ok": False, "error": str(exc), "attempts": attempts}

    # Existing origin: commit changes, push, then verify remote heads.
    if _git_repo(root):
        remote = _run(["git", "remote", "get-url", "origin"], root, timeout=30)
        attempts.append({"strategy": 1, "name": "existing-origin-check", "result": remote})
        if remote["ok"]:
            ready = _ensure_git_commit(root, attempts)
            if ready["ok"]:
                push = _run(["git", "push", "-u", "origin", "HEAD"], root, timeout=240)
                attempts.append({"strategy": 1, "name": "verified-git-push", "result": push})
                if push["ok"]:
                    verify = _run(["git", "ls-remote", "--heads", "origin"], root, timeout=60)
                    attempts.append({"strategy": 1, "name": "remote-verification", "result": verify})
                    if verify["ok"] and verify["stdout"].strip():
                        return {"ok": True, "passed_strategy": 1, "repository": remote["stdout"].strip(), "attempts": attempts}

    # gh is the preferred authenticated path for creating a repository.
    gh = shutil.which("gh")
    if gh:
        ready = _ensure_git_commit(root, attempts)
        if not ready["ok"]:
            return {"ok": False, "passed_strategy": None, "attempts": attempts}
        name = target or root.name
        visibility = "--private" if private else "--public"
        create = _run(["gh", "repo", "create", name, visibility, "--source", ".", "--remote", "origin", "--push"], root, timeout=300)
        attempts.append({"strategy": 2, "name": "gh-create-and-push", "result": create})
        if create["ok"]:
            verify = _run(["gh", "repo", "view", name, "--json", "nameWithOwner,url,visibility"], root, timeout=60)
            attempts.append({"strategy": 2, "name": "github-verification", "result": verify})
            if verify["ok"]:
                return {"ok": True, "passed_strategy": 2, "repository": name, "attempts": attempts}
    else:
        attempts.append({"strategy": 2, "name": "gh-create-and-push", "result": {
            "ok": False, "code": 127, "stdout": "", "stderr":
            "GitHub CLI (gh) is not installed. Install it and run `gh auth login`, or configure an existing git origin."
        }})

    # If gh is installed, explicitly report whether authentication exists.
    if gh:
        auth = _run(["gh", "auth", "status"], root, timeout=60)
        attempts.append({"strategy": 3, "name": "github-auth-verification", "result": auth})

    attempts.append({"strategy": 4, "name": "safe-handoff", "result": {
        "ok": False, "code": -1, "stdout": "",
        "stderr": "GitHub publish was not verified. No fake PASS was reported and no source reset/delete was performed."
    }})
    return {"ok": False, "passed_strategy": None, "repository": target, "attempts": attempts}

def _extract_deploy_url(text: str) -> str | None:
    # Vercel CLI normally prints an https://*.vercel.app URL.  Only treat a
    # deployment as verified when an actual URL is present.
    matches = re.findall(r"https://[A-Za-z0-9._~-]+\.vercel\.app(?:/[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%~-]*)?", text)
    return matches[-1] if matches else None


def _verify_vercel_url(url: str, root: Path) -> dict:
    # `vercel inspect <url>` is a read-only verification step.  It is used only
    # after the CLI reports a deployment URL.
    r = _run(["vercel", "inspect", url], root, timeout=120)
    r["url"] = url
    return r


def vercel_deploy(root: Path, production: bool = False) -> dict:
    """Try bounded deployment strategies; PASS requires a verifiable deployment URL."""
    attempts = []; root = root.resolve()
    primary = ["vercel", "--yes"] + (["--prod"] if production else [])

    def attempt(strategy: int, name: str, argv: list[str], timeout: int = 300) -> dict | None:
        r = _run(argv, root, timeout=timeout)
        text = (r.get("stdout", "") + "\n" + r.get("stderr", "")).strip()
        url = _extract_deploy_url(text)
        record = {"strategy": strategy, "name": name, "result": r, "deployment_url": url}
        attempts.append(record)
        if r["ok"] and url:
            verify = _verify_vercel_url(url, root)
            attempts.append({"strategy": strategy, "name": "verify-deployment", "result": verify, "deployment_url": url})
            if verify["ok"]:
                return {"ok": True, "passed_strategy": strategy, "deployment_url": url, "attempts": attempts}
        return None

    for strategy, name, argv in (
        (1, "direct-cli", primary),
        (2, "link-project", ["vercel", "link", "--yes"]),
        (3, "production-retry", ["vercel", "--yes", "--prod"]),
    ):
        if strategy == 2:
            linked = _run(argv, root, timeout=180)
            attempts.append({"strategy": strategy, "name": name, "result": linked})
            if linked["ok"]:
                result = attempt(strategy, "linked-deploy", primary)
                if result:
                    return result
        else:
            result = attempt(strategy, name, argv)
            if result:
                return result

    if (root / "vercel.json").exists() or (root / "package.json").exists():
        result = attempt(4, "configured-project", ["vercel", "--yes"] + (["--prod"] if production else []))
        if result:
            return result

    attempts.append({"strategy": 5, "name": "manual-handoff", "result": {
        "ok": False, "code": -1, "stdout": "",
        "stderr": "No deployment was verified. No fake PASS is reported."
    }})
    return {"ok": False, "passed_strategy": None, "attempts": attempts}


def build_exe(root: Path, onefile: bool = True) -> dict:
    entry = root / "launch_cybershield.py"
    if not entry.exists(): entry = root / "main.py"
    if not entry.exists(): return {"ok": False, "error": "No supported launcher found"}
    args = ["pyinstaller", "--noconfirm", "--clean"] + (["--onefile"] if onefile else [])
    args += ["--name", "CyberShield", "--distpath", str(root / "dist"), str(entry)]
    icon = root / "cibershield.ico"
    if icon.exists(): args += ["--icon", str(icon)]
    r = _run(args, root, timeout=900)
    exe = root / "dist" / "CyberShield.exe"
    r["verified_output"] = str(exe) if r["ok"] and exe.exists() else None
    r["ok"] = bool(r["ok"] and exe.exists())
    return r




def _git_readonly(root: Path, args: list[str]) -> dict:
    return _run(["git", *args], root, timeout=90)

def git_status(root: Path) -> dict:
    r = _run(["git", "status", "--short", "--branch"], root, timeout=60)
    if not r["ok"]:
        return r
    return {"ok": True, "code": 0, "status": r.get("stdout", ""), "stderr": r.get("stderr", "")}


def run_project_tests(root: Path) -> dict:
    """Run pytest only through a fixed argv; no shell, no user-supplied flags."""
    exe = shutil.which("python") or shutil.which("py")
    if not exe:
        return {"ok": False, "code": 127, "stderr": "Python executable not found"}
    try:
        p = subprocess.run([exe, "-m", "pytest", "-q"], cwd=str(root), text=True,
                           capture_output=True, timeout=900, shell=False, check=False)
        return {"ok": p.returncode == 0, "code": p.returncode,
                "stdout": p.stdout[-MAX_OUTPUT:], "stderr": p.stderr[-MAX_OUTPUT:],
                "verified": p.returncode == 0}
    except subprocess.TimeoutExpired:
        return {"ok": False, "code": 124, "stderr": "TIMEOUT: test suite exceeded 900 seconds"}

def _bounded_project_files(root: Path, limit: int = 400) -> list[Path]:
    root = root.resolve()
    skip = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build", ".pytest_cache"}
    files=[]
    for p in root.rglob("*"):
        if len(files) >= limit:
            break
        try:
            rel=p.relative_to(root)
        except ValueError:
            continue
        if any(part in skip for part in rel.parts):
            continue
        if p.is_file():
            files.append(p)
    return files


def project_map(root: Path) -> dict:
    rows=[]
    for p in _bounded_project_files(root):
        try:
            size=p.stat().st_size
        except OSError:
            continue
        rows.append({"path": str(p.relative_to(root)), "size": size, "suffix": p.suffix.lower()})
    return {"ok": True, "root": str(root.resolve()), "files": rows, "count": len(rows), "bounded": True}


def search_project(root: Path, query: str, limit: int = 40) -> dict:
    q=query.strip().lower()
    if not q:
        return {"ok": False, "error": "search query is empty"}
    hits=[]
    for p in _bounded_project_files(root):
        if p.suffix.lower() not in {".py", ".md", ".txt", ".json", ".toml", ".yaml", ".yml", ".bat", ".ps1", ".js", ".ts", ".html", ".css"}:
            continue
        try:
            text=p.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            continue
        for n,line in enumerate(text.splitlines(), 1):
            if q in line.lower():
                hits.append({"path": str(p.relative_to(root)), "line": n, "text": line.strip()[:500]})
                if len(hits) >= limit:
                    return {"ok": True, "query": query, "hits": hits, "truncated": True}
    return {"ok": True, "query": query, "hits": hits, "truncated": False}


def read_project_file(root: Path, raw: str, max_bytes: int = 262144) -> dict:
    root=root.resolve(); p=Path(raw).expanduser()
    if not p.is_absolute():
        p=root / p
    p=p.resolve()
    try:
        p.relative_to(root)
    except ValueError:
        return {"ok": False, "error": "file is outside the active project root"}
    if not p.is_file():
        return {"ok": False, "error": "file not found"}
    if p.stat().st_size > max_bytes:
        return {"ok": False, "error": f"file exceeds safe read limit of {max_bytes} bytes"}
    try:
        return {"ok": True, "path": str(p.relative_to(root)), "content": p.read_text(encoding="utf-8", errors="replace")}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}


def check_dependencies(root: Path) -> dict:
    required=[]
    req=root/"requirements.txt"
    if req.is_file():
        for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
            line=line.strip()
            if line and not line.startswith("#") and not line.startswith("-"):
                required.append(line.split("[",1)[0].split("=",1)[0].split(">",1)[0].strip())
    result=[]
    for name in required[:80]:
        module=name.replace("-", "_")
        try:
            __import__(module)
            ok=True
        except Exception:
            ok=False
        result.append({"package": name, "importable": ok})
    return {"ok": all(x["importable"] for x in result), "dependencies": result, "checked": len(result)}


def open_cybershield_panel(root: Path, panel: str) -> dict:
    """Launch CyberShield itself with an allowlisted panel target.

    This is an application-to-application handoff, not arbitrary shell execution.
    Only known CyberShield panels are accepted.
    """
    allowed = {"settings", "home", "dashboard", "ai", "monitoring", "incidents", "malware", "phishing", "sandbox", "forensics"}
    key = panel.strip().lower()
    if key not in allowed:
        return {"ok": False, "error": "panel is not in the CyberShield allowlist"}
    launcher = root / "main.py"
    if not launcher.exists():
        launcher = root / "launch_cybershield.py"
    if not launcher.exists():
        return {"ok": False, "error": "CyberShield launcher not found"}
    import sys
    try:
        p = subprocess.Popen([sys.executable, str(launcher), "desktop", "--panel", key],
                             cwd=str(root), shell=False, close_fds=True)
        return {"ok": True, "action": "open-panel", "panel": key, "pid": p.pid, "verified": p.poll() is None}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}


def operator_status(root: Path) -> dict:
    return {"git": bool(shutil.which("git")), "gh": bool(shutil.which("gh")),
            "vercel": bool(shutil.which("vercel")), "pyinstaller": bool(shutil.which("pyinstaller")),
            "repo_initialized": _git_repo(root), "root": str(root.resolve())}


def dispatch(action: str, root: Path, args: list[str]) -> dict:
    a = action.lower().strip()
    if a in {"status", "operator-status"}: return operator_status(root)
    if a in {"github-publish", "github-push", "publish-github"}: return github_publish(root, args[0] if args else None, private=True)
    if a in {"vercel-deploy", "deploy-vercel"}: return vercel_deploy(root, production=("--prod" in args or any(x.lower() == "production" for x in args)))
    if a in {"build-exe", "make-exe", "exe"}: return build_exe(root, onefile=("--onedir" not in args))
    if a in {"git-status", "git-status-safe"}: return git_status(root)
    if a in {"git-diff", "git-diff-safe"}: return _git_readonly(root, ["diff", "--no-ext-diff", "--unified=3"])
    if a in {"git-log", "git-log-safe"}: return _git_readonly(root, ["log", "-10", "--oneline", "--decorate"])
    if a in {"run-tests", "tests"}: return run_project_tests(root)
    if a in {"open-panel", "open-cybershield-panel"}: return open_cybershield_panel(root, args[0] if args else "settings")
    if a in {"project-map", "map-project", "project-tree"}: return project_map(root)
    if a in {"search-project", "find-project", "grep-project"}: return search_project(root, " ".join(args))
    if a in {"read-file", "cat-safe"}: return read_project_file(root, " ".join(args))
    if a in {"check-dependencies", "deps", "dependencies"}: return check_dependencies(root)
    raise ActionError("unknown operator action")
