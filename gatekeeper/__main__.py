"""`python3 -m gatekeeper`            → PreToolUse hook (JSON on stdin, decision on stdout)
`python3 -m gatekeeper check TOOL X` → print the policy decision for one action, without logging."""
import json
import sys

from . import gatekeeper

if len(sys.argv) >= 4 and sys.argv[1] == "check":
    tool, target = sys.argv[2], " ".join(sys.argv[3:])
    args = {"command": target} if tool == "Bash" else {"file_path": target}
    print(json.dumps(dict(zip(("decision", "reason"), gatekeeper.decide(tool, args)))))
else:
    gatekeeper.hook_main()
