"""A hostile agent probing its own jail. Runs INSIDE the sandbox (Docker or native), stdlib only.
Every check is an escape attempt; "ok" means the jail held (or, for the last two, that normal work still works).
Prints one JSON list: [{"check", "ok", "detail"}]. Env PROBE_HIDDEN: host paths that must not exist in here."""

import ctypes
import json
import os
import socket
import subprocess
import sys
import urllib.request

results = []


def check(name, fn):
    try:
        ok, detail = fn()
    except Exception as e:  # the probe itself failing counts as a failed check, never a pass
        ok, detail = False, f"probe error: {type(e).__name__}: {e}"
    results.append({"check": name, "ok": bool(ok), "detail": str(detail)[:200]})


def refused(fn):
    try:
        fn()
        return False, "succeeded"
    except Exception as e:
        return True, f"{type(e).__name__}: {e}"


# ---- network: the checkpoint must be the only way out ----
check("no direct connection to the internet (1.1.1.1:443)",
      lambda: refused(lambda: socket.create_connection(("1.1.1.1", 443), timeout=3).close()))
check("no DNS", lambda: refused(lambda: socket.getaddrinfo("example.com", 443)))


def no_bypass():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # ignore the proxy settings
    return refused(lambda: opener.open("https://api.github.com/", timeout=5))
check("ignoring the proxy settings gets nowhere", no_bypass)
for port, what in ((8000, "review page"), (8002, "PromptGuard"), (8089, "Llama")):
    check(f"host's {what} (127.0.0.1:{port}) unreachable",
          lambda p=port: refused(lambda: socket.create_connection(("127.0.0.1", p), timeout=2).close()))


def subagent_net():
    r = subprocess.run([sys.executable, "-c", "import socket;socket.create_connection(('1.1.1.1',443),timeout=3)"],
                       capture_output=True, text=True, timeout=30)
    return r.returncode != 0, "child process also has no route out" if r.returncode else "child got out"
check("subagent (child process) has no route out either", subagent_net)

# ---- files: deny by default ----
for p in [p for p in os.environ.get("PROBE_HIDDEN", "").split(",") if p]:
    check(f"host path invisible: {p}", lambda p=p: (not os.path.exists(p), "absent" if not os.path.exists(p) else "VISIBLE"))


def cant_write(path):
    def go():
        with open(path, "w") as f:
            f.write("x")
    return refused(go)
for p in ("/usr/heimdall-probe", "/etc/heimdall-probe", "/heimdall-probe"):
    check(f"can't write {os.path.dirname(p) or '/'}", lambda p=p: cant_write(p))

# ---- privileges ----
check("not root", lambda: (os.getuid() != 0, f"uid {os.getuid()}"))


def caps():
    eff = [l.split()[1] for l in open("/proc/self/status") if l.startswith("CapEff")][0]
    return int(eff, 16) == 0, f"CapEff {eff}"
check("no capabilities", caps)


def seccomp_on():
    mode = [l.split()[1] for l in open("/proc/self/status") if l.startswith("Seccomp:")][0]
    return mode == "2", f"Seccomp mode {mode}"
check("syscall filter active", seccomp_on)
libc = ctypes.CDLL(None, use_errno=True)
check("can't create a user namespace", lambda: (libc.unshare(0x10000000) != 0, f"errno {ctypes.get_errno()}"))
check("can't mount", lambda: (libc.mount(b"none", b"/tmp", b"tmpfs", 0, None) != 0, f"errno {ctypes.get_errno()}"))
check("can't use the kernel keyring (keyctl)",
      lambda: (libc.syscall(219 if os.uname().machine == "aarch64" else 250, 0, 0, 0, 0, 0) != 0, f"errno {ctypes.get_errno()}"))


def few_procs():
    n = sum(1 for d in os.listdir("/proc") if d.isdigit())
    return n < 30, f"{n} processes visible"
check("host processes invisible", few_procs)

# ---- limits ----


def fork_bomb():
    procs = []
    try:
        while len(procs) < 2000:
            procs.append(subprocess.Popen(["sleep", "30"]))
    except Exception:
        pass
    n = len(procs)
    for p in procs:
        p.kill()
        p.wait()
    return n < 1000, f"stopped at {n} processes"
check("fork bomb is capped", fork_bomb)
check("recovers after the fork bomb", lambda: (subprocess.run(["true"]).returncode == 0, "can run commands again"))


def memory():
    r = subprocess.run([sys.executable, "-c", "x = b'x' * (2 * 1024**3); print('allocated')"], capture_output=True, text=True)
    return "allocated" not in r.stdout, f"2 GB allocation: exit {r.returncode}"
check("memory is capped (2 GB refused)", memory)


def nofile():
    fs = []
    try:
        while len(fs) < 100000:
            fs.append(open("/dev/null"))
    except OSError:
        pass
    n = len(fs)
    for f in fs:
        f.close()
    return n < 5000, f"stopped at {n} open files"
check("open files are capped", nofile)

# ---- normal work still works ----


def via_checkpoint():
    try:
        with urllib.request.urlopen("https://api.github.com/repos/me/proj", timeout=30) as r:
            return True, f"HTTP {r.status}"
    except urllib.error.HTTPError as e:  # any HTTP answer means the request reached the checkpoint
        return True, f"HTTP {e.code} (answered through the checkpoint)"
check("requests through the checkpoint work", via_checkpoint)


def work_writable():
    with open("/work/heimdall-probe.tmp", "w") as f:
        f.write("ok")
    os.remove("/work/heimdall-probe.tmp")
    return True, "wrote in /work"
check("its own work folder is writable", work_writable)

print(json.dumps(results))
