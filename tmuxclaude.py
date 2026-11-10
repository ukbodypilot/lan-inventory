"""Drive a standing interactive Claude Code session in tmux and read its replies from the session transcript.

Why a transcript and not screen scraping: Claude Code appends every message to
~/.claude/projects/<cwd>/<session>.jsonl as structured JSON, so wrapped lines and TUI rendering cannot corrupt a reply.

Submitting is the part that has bitten before (the manager's daily run, 2026-08): a large paste is collapsed by the TUI into
"[Pasted text #N]" and an Enter fired in the same breath is swallowed, leaving the prompt unsent. So: C-u to clear stale input,
bracketed paste (tmux paste-buffer -p), settle, Enter, then verify the input line against an idle baseline, retrying.
"""
import glob
import json
import os
import re
import subprocess
import tempfile
import time

SESSION = os.environ.get("RESEARCH_TMUX_SESSION", "lan-research")


def tmux(*args, check=True, timeout=10):
    return subprocess.run(["tmux"] + list(args), capture_output=True, text=True, check=check, timeout=timeout)


def alive():
    return tmux("has-session", "-t", SESSION, check=False).returncode == 0


def pane(scroll=0):
    args = ["capture-pane", "-p", "-t", SESSION] + (["-S", "-%d" % scroll] if scroll else [])
    try:
        return tmux(*args, check=False, timeout=5).stdout
    except Exception:
        return ""


def prompt_line():
    """Contents of the TUI input line, or None if it is not on screen (None = Claude is busy answering)."""
    for line in pane().splitlines():
        ls = line.strip().strip("\u2502").strip()  # the input box may be framed with box-drawing bars
        for marker in ("\u276f", ">"):
            if ls.startswith(marker):
                return ls[len(marker):].strip()
    return None


def wait_ready(timeout=90):
    """Wait for an idle prompt; accept the one-time folder-trust dialog if it appears."""
    end = time.time() + timeout
    while time.time() < end:
        p = pane()
        if "Yes, I trust this folder" in p:  # dialog defaults to "No, exit": move down first
            tmux("send-keys", "-t", SESSION, "Down")
            time.sleep(0.5)
            tmux("send-keys", "-t", SESSION, "Enter")
            time.sleep(3)
            continue
        if prompt_line() is not None:
            return True
        time.sleep(2)
    return False


def ensure_session(cwd, claude_cmd):
    """Create the session if it is not running. Returns True if it was freshly created."""
    if alive():
        return False
    os.makedirs(cwd, exist_ok=True)
    tmux("new-session", "-d", "-s", SESSION, "-x", "220", "-y", "50", "-c", cwd, claude_cmd)
    if not wait_ready():
        raise RuntimeError("claude did not reach an idle prompt in tmux session %s:\n%s" % (SESSION, pane()[-600:]))
    return True


def busy():
    """True while Claude is working (the TUI shows 'esc to interrupt'). The input line stays visible when busy, so the
    input line alone cannot tell idle from busy."""
    return "esc to interrupt" in pane()


def wait_idle(timeout=1500, poll=5):
    end = time.time() + timeout
    while time.time() < end:
        if not busy():
            return True
        time.sleep(poll)
    return False


def sent(cwd, nonce):
    """True once a user entry containing nonce is in the transcript - the only reliable proof the prompt was submitted."""
    path = newest_transcript(cwd)
    if not path:
        return False
    for line in open(path, errors="replace"):
        if nonce in line and '"type":"user"' in line.replace(" ", ""):
            return True
    return False


def submit(text, cwd, nonce, settle=1.5, attempts=3):
    """Paste text into an IDLE session and make sure it was actually sent (proved by the transcript). True once submitted."""
    if not wait_idle():
        return False
    tmux("send-keys", "-t", SESSION, "C-u")
    time.sleep(0.3)
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write(text)
        path = f.name
    try:
        tmux("load-buffer", "-b", "lanresearch", path)
        tmux("paste-buffer", "-p", "-d", "-b", "lanresearch", "-t", SESSION)  # -p: real bracketed paste
    finally:
        os.unlink(path)
    for _ in range(attempts):
        time.sleep(settle)
        tmux("send-keys", "-t", SESSION, "Enter")  # a plain Enter right after a big paste is often swallowed: hence the retries
        for _ in range(8):
            time.sleep(1)
            if sent(cwd, nonce):
                return True
    return False


def slash(command):
    """Run a slash command (e.g. /clear) and confirm the prompt is idle again."""
    tmux("send-keys", "-t", SESSION, "C-u")
    time.sleep(0.3)
    tmux("send-keys", "-t", SESSION, "-l", command)
    time.sleep(1.0)
    tmux("send-keys", "-t", SESSION, "Enter")
    time.sleep(2.0)
    return wait_ready(30)


# ---------------------------------------------------------------- transcript
def transcript_dir(cwd):
    enc = re.sub(r"[^A-Za-z0-9]", "-", os.path.realpath(cwd))
    d = os.path.expanduser("~/.claude/projects/" + enc)
    return d if os.path.isdir(d) else None


def newest_transcript(cwd):
    d = transcript_dir(cwd)
    files = glob.glob(os.path.join(d, "*.jsonl")) if d else []
    return max(files, key=os.path.getmtime) if files else None


def _texts(content):
    if isinstance(content, str):
        return [content]
    return [b.get("text", "") for b in content or [] if isinstance(b, dict) and b.get("type") == "text"]


def read_after(cwd, nonce):
    """(assistant_text_joined, web_tool_calls) for everything after the user message containing nonce."""
    path = newest_transcript(cwd)
    if not path:
        return "", 0
    seen, texts, tools = False, [], 0
    for line in open(path, errors="replace"):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        msg = e.get("message") or {}
        if e.get("type") == "user" and any(nonce in t for t in _texts(msg.get("content"))):
            seen, texts, tools = True, [], 0  # restart if the same nonce was sent twice
            continue
        if not seen or e.get("type") != "assistant":
            continue
        texts += _texts(msg.get("content"))
        tools += sum(1 for b in (msg.get("content") or []) if isinstance(b, dict) and b.get("type") == "tool_use"
                     and b.get("name") in ("WebSearch", "WebFetch"))
    return "\n".join(texts), tools


MARKED = re.compile(r"RESULT_START[^\n]*\n(.*?)RESULT_END", re.S)


def wait_reply(cwd, nonce, timeout=1500, poll=6):
    """Block until the assistant has written a RESULT_START...RESULT_END block after our prompt. Returns (text, web_tool_calls).

    The nonce only locates OUR message in the transcript (it is in the user entry we sent). The model is not required to echo it:
    it mangles random hex when copying it back (seen: sent lr9ae42ff18b, replied lraff4b640aa)."""
    end = time.time() + timeout
    while time.time() < end:
        text, tools = read_after(cwd, nonce)
        if MARKED.search(text):
            return text, tools
        time.sleep(poll)
    raise TimeoutError("no RESULT_START/RESULT_END block within %ds; pane tail:\n%s" % (timeout, pane()[-500:]))


def extract_json(text, nonce=None):
    blocks = MARKED.findall(text)
    if not blocks:
        raise ValueError("markers not found")
    body = re.sub(r"```(?:json)?", "", blocks[-1])  # last block wins
    i, j = body.find("["), body.rfind("]")
    if i < 0 or j < i:
        raise ValueError("no JSON array between markers")
    return json.loads(body[i:j + 1])
