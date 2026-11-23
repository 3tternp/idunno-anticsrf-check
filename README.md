<div align="center">

# 🕷️ Idunno.AntiCsrf Checker (CVE-2026-131914)

**Find the abandoned ASP.NET anti-CSRF module that gives unauthenticated remote code execution, before someone else does.**

![python](https://img.shields.io/badge/python-3.6%2B-3776AB?logo=python&logoColor=white)
![powershell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)
![cvss](https://img.shields.io/badge/CVSS%204.0-9.3%20Critical-red)
![patch](https://img.shields.io/badge/patch-none%20(project%20abandoned%202008)-critical)
![mode](https://img.shields.io/badge/mode-read--only-blue)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

Built by **Astra**
</div>

---

## 📚 Contents

[🎯 The flaw](#-the-flaw) · [🚀 Quick start](#-quick-start) · [🔎 What it checks](#-what-it-checks) · [🧮 Verdicts](#-verdicts) · [🪵 IIS log hunt](#-iis-log-hunt) · [🌐 Remote fingerprint](#-remote-fingerprint) · [🩹 What to do if found](#-what-to-do-if-found) · [🖨️ Example output](#️-example-output) · [⚠️ Limits](#️-limits) · [🛡️ Safety](#️-safety)

## 🎯 The flaw

`Idunno.AntiCsrf` is an old third-party **ASP.NET WebForms HTTP module** that adds double-submit-cookie CSRF protection. It deserializes the CSRF form token with an **unkeyed `ObjectStateFormatter` and no MAC check**. One unauthenticated `POST` with a non-empty CSRF cookie and a Base64 gadget chain in the CSRF form field runs code as the **IIS worker process (`w3wp.exe`)**.

| Fact | Detail |
|---|---|
| 🆔 CVE | **CVE-2026-131914** (CVSS 4.0: **9.3**, assigned by Mandiant) |
| 📦 Affected | Idunno.AntiCsrf **0.9.1.0** and **0.9.1 Beta**; treat **every copy** as affected |
| 🚫 Fix | **None.** The project has not been updated since December 2008 |
| 🔥 Status | Mandiant reports exploitation in the wild (per The Hacker News) |
| 🔑 Needs | Network access only. No authentication, no valid CSRF token |

> ℹ️ Some CVE aggregator pages list "0.9.1.0" under *patched versions*. That conflicts with Mandiant's reporting and with the project being abandoned, so this tool treats **any** copy as vulnerable.

## 🚀 Quick start

### 🪟 On the Windows / IIS server (recommended)

```powershell
git clone https://github.com/<your-org>/idunno-anticsrf-check.git
cd idunno-anticsrf-check
powershell -ExecutionPolicy Bypass -File .\anticsrf_check_windows.ps1 -HuntLogs
```

Run as **Administrator** so every site folder is readable. It scans all IIS site and application roots automatically, plus the global `applicationHost.config` and the .NET GAC.

### 🐍 Anywhere (Linux, macOS, Windows): Python

```bash
python3 anticsrf_check.py "C:\inetpub\wwwroot" "D:\apps"            # scan web roots (or a copied/mounted share)
python3 anticsrf_check.py --logs "C:\inetpub\logs\LogFiles" --days 60
python3 anticsrf_check.py --url https://portal.example.com          # passive remote fingerprint
python3 anticsrf_check.py D:\apps --json report.json
```

No `pip install` needed.

## 🔎 What it checks

| Check | How |
|---|---|
| 📦 **The module DLL** | Finds `Idunno.AntiCsrf.dll` in every `bin` folder, the GAC and any extra path; reports **version, SHA-256, size and modified date** |
| ⚙️ **Configuration** | Finds `AntiCsrfModule`, `Idunno.AntiCsrf` or `csrfSettings` in `web.config`, `applicationHost.config`, `machine.config`; shows the lines and any `cookieName` / `formFieldName` settings |
| 🪵 **IIS logs** | Optional hunt for exploitation leads (see below) |
| 🌐 **Remote hints** | Optional passive fingerprint of a site (Python only) |

## 🧮 Verdicts

| Verdict | Meaning |
|---|---|
| 🔴 **VULNERABLE** | The module DLL is present. No patch exists: remove or replace it |
| 🟡 **REVIEW** | Config references the module but no DLL was found in the scanned paths (GAC, another folder, or a leftover entry) |
| 🟢 **CLEAN** | Nothing found **in the paths you scanned** |
| 🟠 **INDICATOR** | Remote only: the site shows anti-CSRF-style cookie or field names. Not proof |

**Exit codes:** `0` clean · `1` vulnerable · `2` review, indicator or log leads · `3` usage error

## 🪵 IIS log hunt

`-HuntLogs` (PowerShell) or `--logs DIR` (Python) reads W3C logs and reports:

| Lead | Strength |
|---|---|
| 🔴 **Anti-CSRF-style cookie value of 300+ characters** in `cs(Cookie)` | Strong. A normal token is short; an object gadget chain is long |
| 🟡 `POST` to `.aspx`, `.ashx` or `.asmx` returning **500 or 302** | Weak. Group by source address and time |

⚠️ IIS does **not** log cookies by default. Enable the `Cookie` field in *IIS Manager → Logging → Select Fields → Custom Fields / Standard Fields* so the strong check works going forward. Without it only the weak signal is available.

## 🌐 Remote fingerprint

`--url` sends one normal `GET` and looks for ASP.NET WebForms (`__VIEWSTATE`, `X-AspNet-Version`) and **anti-CSRF-style cookie or hidden field names**. It sends **no payload** and cannot prove the module is present or absent. It is useful for listing candidates in a large estate; confirm each on the server.

## 🩹 What to do if found

1. 🧹 **Remove the module.** Delete the `AntiCsrfModule` entry from `<httpModules>` / `<modules>` and the `csrfSettings` section, then delete `Idunno.AntiCsrf.dll` from `bin`.
2. 🔁 **Replace it** with a supported control: `System.Web.Helpers.AntiForgery`, `ViewStateUserKey` with MAC-protected ViewState, or ASP.NET Core `IAntiforgery`. Test every POST form.
3. 🔍 **Look for compromise first or in parallel**: IIS logs (this tool), new `.aspx` / `.dll` files in web roots, `w3wp.exe` starting `cmd.exe`, `powershell.exe` or other shells.
4. 🔑 **Rotate secrets** if exploitation is possible: `machineKey`, connection strings, API and encryption keys in `Web.config` and `applicationHost.config`.
5. 🛡️ **Meanwhile:** run the app pool as a low-privilege identity, deny outbound traffic from the web server, and use a WAF or reverse proxy to block POSTs with an abnormally long CSRF cookie or field.

## 🖨️ Example output

```text
Idunno.AntiCsrf check (CVE-2026-131914) | Vairav VTS-SA-2026-1123-IDUNNO-ANTICSRF

[VULNERABLE] Idunno.AntiCsrf.dll found: no patch exists, remove or replace the module
    CONFIG: D:\apps\siteA\web.config
         <add name="AntiCsrfModule" type="Idunno.AntiCsrf.AntiCsrfModule, Idunno.AntiCsrf"/>
         settings: {'cookieName': '__CSRFCOOKIE', 'formFieldName': '__CSRFTOKEN'}
    DLL: D:\apps\siteA\bin\Idunno.AntiCsrf.dll
         version 0.9.1.0 | sha256 8f8f8884e59c... | 192 bytes | modified 2026-11-23 11:45

IIS log hunt: 1 files, 3 rows scanned
[LEADS] long anti-CSRF-style cookie values (300+ chars), strongest indicator:
    u_ex261120.log 2026-11-20 10:00:00 ip=1.2.3.4 uri=/Login.aspx cookie=__CSRFCOOKIE len=400
```

## ⚠️ Limits

- 🔭 It only sees the paths it scans. Applications in unusual folders, other servers in a farm and containers need their own run.
- 🏷️ The default cookie and field names (`__CSRFCOOKIE`, `__CSRFTOKEN`) are **unconfirmed**; the tool reads the names from your config and also matches any name containing "csrf". Mandiant's advisory was not available to us when this was written.
- 🧬 A renamed or merged copy of the code (compiled into your own assembly) will not be found by file name. Search source code for `AntiCsrfModule` and `ObjectStateFormatter` use.
- 🪵 Log hunting depends on what IIS logs. No cookie logging means no strong indicator.
- 🧪 **Testing:** Python tested on fixture folders, fake logs and a mock site (`tests/fixtures`). The PowerShell script was **not executed** in our environment (no PowerShell available); run it on a test server first.

## 🛡️ Safety

Read-only. The scripts read files and logs, compute hashes and (Python `--url`) make one normal HTTP GET. No exploit payloads, no changes, no uploads. Use only on systems you are authorised to assess.

## 📜 License

MIT, see [LICENSE](LICENSE). Provided as is; verify results before acting.
