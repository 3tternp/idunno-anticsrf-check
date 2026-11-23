#!/usr/bin/env python3
"""
anticsrf_check.py - read-only check for Idunno.AntiCsrf (CVE-2026-131914, CVSS 9.3).
Vairav advisory VTS-SA-2026-1123-IDUNNO-ANTICSRF.

The flaw: the Idunno.AntiCsrf ASP.NET HTTP module deserializes the CSRF form token with an unkeyed
ObjectStateFormatter and no MAC, so one unauthenticated POST gives code execution as the IIS worker (w3wp.exe).
No patch exists and the project has been abandoned since 2008: ANY copy of the module is treated as vulnerable.

Modes
  scan   (default)  PATH [PATH ...]   look for Idunno.AntiCsrf.dll and module references in web.config / applicationHost.config
  logs   --logs DIR                   hunt IIS W3C logs for exploitation leads (POST to .aspx with 500/302, long CSRF cookie values)
  remote --url URL                    passive fingerprint of a site (no payload sent): ASP.NET WebForms + anti-CSRF cookie/field hints

Verdicts
  VULNERABLE   module DLL present, or module referenced in config
  REVIEW       reference found but DLL missing (or DLL found outside any web root): confirm manually
  CLEAN        nothing found in the scanned paths
  INDICATOR    remote only: site shows hints of the module. Not proof; run scan on the server

Exit codes: 0 clean, 1 vulnerable, 2 review/indicator/log leads only, 3 usage error.
Python 3.6+, standard library only. Makes no changes and sends no exploit traffic.
"""
import argparse, glob, hashlib, json, os, re, ssl, sys, urllib.request, datetime, collections

ADVISORY = "VTS-SA-2026-1123-IDUNNO-ANTICSRF"
DLL = "idunno.anticsrf.dll"
CFG_NAMES = ("web.config", "applicationhost.config", "machine.config", "app.config")
REF = re.compile(r"Idunno\.AntiCsrf|AntiCsrfModule|AntiCSRF\.csrfSettings|csrfSettings", re.I)
ATTR = re.compile(r'(cookieName|formFieldName|detectionMethod|tokenLifetime)\s*=\s*"([^"]*)"', re.I)
COLOR = sys.stdout.isatty()
def c(t, code): return "\033[%sm%s\033[0m" % (code, t) if COLOR else t
TAG = {"VULNERABLE": "1;31", "REVIEW": "1;33", "CLEAN": "1;32", "INDICATOR": "1;33"}

def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for ch in iter(lambda: f.read(1 << 20), b""): h.update(ch)
    return h.hexdigest()

def pe_version(p):
    """FileVersion string from the PE resource, without extra libraries."""
    try:
        data = open(p, "rb").read(4 << 20)
    except Exception:
        return None
    key = "FileVersion".encode("utf-16-le") + b"\x00\x00"
    i = data.find(key)
    if i < 0: return None
    j = i + len(key)
    while data[j:j+2] == b"\x00\x00": j += 2
    end = j
    while end + 1 < len(data) and data[end:end+2] != b"\x00\x00": end += 2
    try: return data[j:end].decode("utf-16-le").strip() or None
    except Exception: return None

def scan_paths(paths, maxdepth):
    findings = []
    for root in paths:
        if not os.path.exists(root):
            findings.append({"type": "error", "path": root, "note": "path not found"}); continue
        base_depth = root.rstrip(os.sep).count(os.sep)
        for dp, dn, fn in os.walk(root, onerror=lambda e: None):
            if maxdepth and dp.count(os.sep) - base_depth >= maxdepth: dn[:] = []
            for name in fn:
                low = name.lower(); full = os.path.join(dp, name)
                if low == DLL:
                    findings.append({"type": "dll", "path": full, "sha256": sha256(full), "version": pe_version(full),
                                     "size": os.path.getsize(full), "mtime": datetime.datetime.fromtimestamp(os.path.getmtime(full)).strftime("%Y-%m-%d %H:%M")})
                elif low in CFG_NAMES:
                    try:
                        txt = open(full, "r", errors="ignore").read()
                    except Exception:
                        continue
                    m = REF.search(txt)
                    if m:
                        lines = [l.strip() for l in txt.splitlines() if REF.search(l)][:5]
                        attrs = dict(ATTR.findall(txt))
                        findings.append({"type": "config", "path": full, "lines": lines, "settings": attrs})
    return findings

def verdict_for(findings):
    dlls = [f for f in findings if f["type"] == "dll"]; cfgs = [f for f in findings if f["type"] == "config"]
    if dlls: return "VULNERABLE", "Idunno.AntiCsrf.dll found: no patch exists, remove or replace the module"
    if cfgs: return "REVIEW", "module referenced in configuration but the DLL was not found in the scanned paths (GAC or another folder?)"
    return "CLEAN", "no Idunno.AntiCsrf DLL or configuration reference in the scanned paths"

def iis_logs(logdir, days, minbytes):
    cutoff = datetime.datetime.now() - datetime.timedelta(days=days)
    files = [f for f in glob.glob(os.path.join(logdir, "**", "*.log"), recursive=True) if datetime.datetime.fromtimestamp(os.path.getmtime(f)) >= cutoff]
    hits = collections.Counter(); long_cookie = []; scanned = 0
    for f in files:
        fields = None
        for line in open(f, "r", errors="ignore"):
            if line.startswith("#Fields:"): fields = line.split()[1:]; continue
            if line.startswith("#") or not fields: continue
            row = line.rstrip("\n").split(" ")
            if len(row) != len(fields): continue
            d = dict(zip(fields, row)); scanned += 1
            if d.get("cs-method") == "POST" and d.get("cs-uri-stem", "").lower().endswith((".aspx", ".ashx", ".asmx")) and d.get("sc-status") in ("500", "302"):
                big = int(d.get("cs-bytes", "0") or 0) >= minbytes if d.get("cs-bytes", "-").isdigit() else False
                hits[(d.get("c-ip", d.get("X-Forwarded-For", "?")), d["cs-uri-stem"], d["sc-status"], big)] += 1
            ck = d.get("cs(Cookie)", "")
            for m in re.finditer(r"(?i)(__?csrf\w*)=([A-Za-z0-9%+/=_-]{300,})", ck):
                long_cookie.append((os.path.basename(f), d.get("date"), d.get("time"), d.get("c-ip"), d.get("cs-uri-stem"), m.group(1), len(m.group(2))))
    return scanned, files, hits, long_cookie

def remote(url, insecure, timeout):
    if "://" not in url: url = "https://" + url
    ctx = ssl.create_default_context()
    if insecure: ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "Vairav-anticsrf-check/1.0"})
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx); body = r.read(400000).decode("utf-8", "ignore"); hdr = r.headers
    except urllib.error.HTTPError as e:
        body = e.read(400000).decode("utf-8", "ignore"); hdr = e.headers
    except Exception as e:
        return {"url": url, "status": "UNKNOWN", "notes": ["request failed: %s" % e]}
    notes = []; score = 0
    if hdr.get("X-AspNet-Version") or "ASP.NET" in (hdr.get("X-Powered-By") or ""): notes.append("ASP.NET detected (%s)" % (hdr.get("X-AspNet-Version") or hdr.get("X-Powered-By")))
    if "__VIEWSTATE" in body: notes.append("WebForms page (__VIEWSTATE present)")
    for ck in hdr.get_all("Set-Cookie") or []:
        n = ck.split("=", 1)[0]
        if re.search(r"csrf", n, re.I): notes.append("cookie named '%s' (anti-CSRF style)" % n); score += 1
    for m in set(re.findall(r'<input[^>]+name="([^"]*csrf[^"]*)"', body, re.I)): notes.append("hidden field '%s' (anti-CSRF style)" % m); score += 1
    status = "INDICATOR" if score else "UNKNOWN"
    if not score: notes.append("no anti-CSRF cookie or field seen on this page. This does not prove the module is absent: scan the server")
    return {"url": url, "status": status, "notes": notes}

def main():
    ap = argparse.ArgumentParser(description="Check for Idunno.AntiCsrf (CVE-2026-131914). Read-only.")
    ap.add_argument("paths", nargs="*", help="web roots or folders to scan (e.g. C:\\inetpub\\wwwroot D:\\apps)")
    ap.add_argument("--logs", help="IIS log folder to hunt (e.g. C:\\inetpub\\logs\\LogFiles)")
    ap.add_argument("--days", type=int, default=45, help="log files modified within N days (default 45)")
    ap.add_argument("--min-bytes", type=int, default=2000, help="cs-bytes threshold used to mark large POSTs (default 2000)")
    ap.add_argument("--url", action="append", help="remote passive fingerprint (repeatable)")
    ap.add_argument("-k", "--insecure", action="store_true"); ap.add_argument("--timeout", type=float, default=10)
    ap.add_argument("--max-depth", type=int, default=0, help="limit folder depth (0 = unlimited)")
    ap.add_argument("--json", metavar="FILE")
    a = ap.parse_args()
    if not (a.paths or a.logs or a.url): ap.print_usage(); sys.exit(3)
    print("\nIdunno.AntiCsrf check (CVE-2026-131914) | Vairav %s\n" % ADVISORY)
    code = 0; out = {}
    if a.paths:
        f = scan_paths(a.paths, a.max_depth); v, why = verdict_for([x for x in f if x["type"] != "error"]); out["scan"] = {"verdict": v, "findings": f}
        print("%s %s" % (c("[%s]" % v, TAG[v]), why))
        for x in f:
            if x["type"] == "dll":
                print("    DLL: %s\n         version %s | sha256 %s | %s bytes | modified %s" % (x["path"], x["version"] or "unknown", x["sha256"], x["size"], x["mtime"]))
            elif x["type"] == "config":
                print("    CONFIG: %s" % x["path"])
                for l in x["lines"]: print("         %s" % l[:160])
                if x["settings"]: print("         settings: %s" % x["settings"])
            else: print("    note: %s: %s" % (x["path"], x["note"]))
        print("    Next: no patch exists. Follow advisory section 6: remove the module, replace with supported anti-forgery, then review for compromise.\n")
        code = 1 if v == "VULNERABLE" else (2 if v == "REVIEW" else 0)
    if a.logs:
        scanned, files, hits, lc = iis_logs(a.logs, a.days, a.min_bytes); out["logs"] = {"files": len(files), "rows": scanned, "leads": len(hits), "long_cookie": len(lc)}
        print("IIS log hunt: %d files, %d rows scanned" % (len(files), scanned))
        if lc:
            print(c("[LEADS] long anti-CSRF-style cookie values (300+ chars), strongest indicator:", "1;31"))
            for r in lc[:25]: print("    %s %s %s ip=%s uri=%s cookie=%s len=%d" % r)
            code = max(code, 2)
        if hits:
            print(c("[LEADS] POST to .aspx/.ashx/.asmx returning 500 or 302 (weak signal, review by source and time):", "1;33"))
            for (ip, uri, st, big), n in hits.most_common(25): print("    %-16s %-40s status=%s large_post=%s count=%d" % (ip, uri[:40], st, big, n))
            code = max(code, 2)
        if not lc and not hits: print("    no leads")
        print("    Hits are leads, not proof. Enable cs(Cookie) logging in IIS to make the cookie test possible.\n")
    for u in a.url or []:
        r = remote(u, a.insecure, a.timeout); out.setdefault("remote", []).append(r)
        print("%s %s" % (c("[%s]" % r["status"], TAG.get(r["status"], "0")), r["url"]))
        for n in r["notes"]: print("    %s" % n)
        print()
        if r["status"] == "INDICATOR": code = max(code, 2)
    if a.json: json.dump(out, open(a.json, "w"), indent=2)
    sys.exit(code)

if __name__ == "__main__":
    main()
