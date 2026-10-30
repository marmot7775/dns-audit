"""Close the loop after the nightly fix run.

Reads .nightly/results.json, which Claude Code writes in the shape

  {"threads": {"<thread_id>": {"status": "fixed|skipped|needs_neil",
                               "note": "one or two sentences"}},
   "sentry":  {"<short_id>":  {"status": "...", "note": "..."}},
   "alerts":  {"<alert_key>": {"status": "...", "note": "..."}}}

and replies on each review thread so the next run skips it and the thread
itself records what happened. Replies start with "nightly:" because
collect.py uses that prefix to recognise a handled thread.

Usage: report.py [--pr-url URL] [--summary FILE]

Environment: GH_TOKEN with pull request write access.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

OUT_DIR = Path(".nightly")

REPLY_MUTATION = """
mutation($thread: ID!, $body: String!) {
  addPullRequestReviewThreadReply(input: {pullRequestReviewThreadId: $thread, body: $body}) {
    comment { url }
  }
}
"""

LABELS = {
    "fixed": "fixed",
    "skipped": "skipped",
    "needs_neil": "needs a decision from Neil",
}


def reply(thread_id: str, body: str) -> bool:
    cmd = [
        "gh", "api", "graphql",
        "-f", f"query={REPLY_MUTATION}",
        "-f", f"thread={thread_id}",
        "-f", f"body={body}",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        print(f"reply failed for {thread_id}: {proc.stderr.strip()}", file=sys.stderr)
        return False
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pr-url", default="")
    ap.add_argument("--summary", default="")
    args = ap.parse_args()

    results_path = OUT_DIR / "results.json"
    threads_path = OUT_DIR / "threads.json"
    if not threads_path.exists():
        print("no threads.json, nothing to report")
        return 0
    inputs = json.loads(threads_path.read_text(encoding="utf-8"))
    results = {"threads": {}, "sentry": {}, "alerts": {}}
    if results_path.exists():
        try:
            results = json.loads(results_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"results.json is not valid JSON: {exc}", file=sys.stderr)

    by_id = {t["id"]: t for t in inputs.get("threads", [])}
    summary: list[str] = []
    replied = 0
    for thread_id, t in by_id.items():
        r = results.get("threads", {}).get(thread_id)
        if not r:
            summary.append(f"PR #{t['pr']} {t['path']}:{t['line']}: no result recorded")
            continue
        status = r.get("status", "skipped")
        note = (r.get("note") or "").strip()
        label = LABELS.get(status, status)
        if status == "fixed" and args.pr_url:
            body = f"nightly: {label} in {args.pr_url}"
        else:
            body = f"nightly: {label}"
        if note:
            body += f". {note}"
        if reply(thread_id, body):
            replied += 1
        summary.append(f"PR #{t['pr']} {t['path']}:{t['line']}: {label}. {note}".rstrip())

    for s in inputs.get("sentry", []):
        r = results.get("sentry", {}).get(s["short_id"])
        if r:
            summary.append(f"Sentry {s['short_id']}: {LABELS.get(r.get('status'), r.get('status'))}. {r.get('note', '')}".rstrip())
        else:
            summary.append(f"Sentry {s['short_id']}: no result recorded")

    for a in inputs.get("alerts", []):
        r = results.get("alerts", {}).get(a["key"])
        if r:
            summary.append(f"Alert {a['key']}: {LABELS.get(r.get('status'), r.get('status'))}. {r.get('note', '')}".rstrip())
        else:
            summary.append(f"Alert {a['key']}: no result recorded")

    text = "\n".join(summary) if summary else "No findings."
    print(text)
    print(f"replied on {replied} thread(s)")
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write("## Nightly fix run\n\n")
            if args.pr_url:
                fh.write(f"Pull request: {args.pr_url}\n\n")
            fh.writelines(f"{line}\n\n" for line in summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
