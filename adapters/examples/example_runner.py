#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def main() -> None:
    payload = json.loads(sys.stdin.read() or "{}")
    work_dir = Path(payload.get("workDir") or ".")
    work_dir.mkdir(parents=True, exist_ok=True)

    proof = work_dir / "submission-proof.txt"
    proof.write_text(
        "example adapter run\n"
        f"task={payload.get('taskId')}\n"
        f"finding={payload.get('findingId')}\n"
        f"action={payload.get('action')}\n",
        encoding="utf-8",
    )

    result = {
        "status": "waiting_email_verification",
        "summary": "Example submission simulated. Email verification required.",
        "artifacts": [
            {
                "type": "raw_json",
                "path": str(proof),
                "label": "submission-proof",
                "contentType": "text/plain"
            }
        ],
        "nextStep": {
            "type": "manual",
            "instructions": "Open mailbox and click verification link within 24h"
        },
        "raw": {
            "simulated": True,
            "adapter": payload.get("adapter", {})
        }
    }
    print(json.dumps(result))


if __name__ == "__main__":
    main()
