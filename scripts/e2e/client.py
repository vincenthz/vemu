"""Socket client for scripts/e2e.sh.

usage: client.py unix PATH       SEND EXPECT TIMEOUT [READY]
       client.py tcp  HOST PORT  SEND EXPECT TIMEOUT [READY]

Connects (retrying until TIMEOUT seconds have passed), waits until READY has
been received (if given), sends SEND (backslash escapes such as \\n are
expanded) and copies everything received to stdout until the peer closes or
TIMEOUT passes. Exits 0 if EXPECT was among the received bytes.
"""
import socket
import sys
import time

kind = sys.argv[1]
if kind == "unix":
    target, rest = sys.argv[2], sys.argv[3:]
    family = socket.AF_UNIX
else:
    target, rest = (sys.argv[2], int(sys.argv[3])), sys.argv[4:]
    family = socket.AF_INET
send, expect, timeout = rest[0].encode().decode("unicode_escape").encode(), rest[1].encode(), float(rest[2])
ready = rest[3].encode() if len(rest) > 3 else b""

deadline = time.monotonic() + timeout
while True:
    s = socket.socket(family, socket.SOCK_STREAM)
    try:
        s.connect(target)
        break
    except OSError:
        s.close()
        if time.monotonic() > deadline:
            sys.exit("client: cannot connect")
        time.sleep(0.05)

s.settimeout(0.2)
got = b""
sent = False
while time.monotonic() < deadline:
    if not sent and ready in got:
        s.sendall(send)
        sent = True
    try:
        data = s.recv(65536)
    except socket.timeout:
        continue
    except OSError:
        break
    if not data:
        break
    got += data
    sys.stdout.buffer.write(data)
    sys.stdout.flush()
sys.exit(0 if expect in got else 1)
