import re
import sys

f = sys.argv[1]
s = open(f, encoding="utf-8", errors="replace").read()
for m in re.finditer(
    r'<testcase[^>]*name="([^"]+)"[^>]*>\s*<(failure|error)[^>]*?(?:message="([^"]*)")?[^>]*>(.*?)</\2>',
    s,
    re.S,
):
    name, kind, msg, body = m.groups()
    body = re.sub(r"\s+", " ", body or "").strip()
    print(f"::error::{kind.upper()} {name}")
    if msg:
        print(f"::error::  msg: {msg[:450]}")
    if body:
        for chunk in [body[i : i + 450] for i in range(0, min(len(body), 1350), 450)]:
            print(f"::error::  at: {chunk}")
