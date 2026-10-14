# Security & Architecture Guidelines

1. **No Hardcoded Credentials:** Never hardcode API keys, passwords, or secrets in code.
2. **SQL Injection Prevention:** All SQL queries must use parameterized inputs or ORMs.
3. **Rate Limiting & Auth:** Publicly exposed API routes must include authentication middleware or rate limiting.
4. **Error Handling:** Avoid printing raw exception traces or sensitive data in API responses.
5. **No Dangerous System Calls:** Avoid raw `eval()`, `exec()`, or unformatted `os.system()` calls with dynamic user inputs.
6. **Command Injection:** Never pass user input to `subprocess` with `shell=True`, `os.popen()`, or `child_process.exec()`; use argument lists and validate inputs.
7. **Cross-Site Scripting (XSS):** Never insert untrusted data into HTML using `innerHTML`, `dangerouslySetInnerHTML`, `document.write()`, or unescaped template output (e.g. `|safe`, `{!! !!}`); always escape or sanitize output.
8. **Path Traversal:** Never build file paths directly from user input; normalize paths, block `../` sequences, and restrict access to an allowed directory.
9. **Insecure Deserialization:** Never use `pickle.load()`, `yaml.load()` without `SafeLoader`, `marshal`, or Java native deserialization on untrusted data; prefer JSON or `yaml.safe_load()`.
10. **Weak Password Hashing:** Never store passwords in plain text or hash them with `md5`, `sha1`, or unsalted `sha256`; use `bcrypt`, `argon2`, or `scrypt`.
11. **Weak Cryptography:** Avoid outdated algorithms such as DES, RC4, and AES in ECB mode, and never hardcode encryption keys or IVs.
12. **Insecure Randomness:** Never use `random`, `Math.random()`, or similar for tokens, OTPs, session IDs, or password resets; use `secrets`, `crypto.randomBytes()`, or `SecureRandom`.
13. **TLS Verification Disabled:** Never disable certificate checks (e.g. `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`) in production code.
14. **Debug Mode in Production:** Never ship code with `DEBUG = True`, `app.run(debug=True)`, or verbose debug endpoints enabled.
15. **Sensitive Data in Logs:** Never log passwords, tokens, API keys, session cookies, card numbers, or personal data.
16. **Server-Side Request Forgery (SSRF):** Never fetch URLs supplied by users without validating them against an allowlist; block internal addresses such as `localhost`, `127.0.0.1`, `169.254.169.254`, and private IP ranges.
17. **Overly Permissive CORS:** Do not use `Access-Control-Allow-Origin: *` together with credentials, or on APIs that return private data.
18. **Broken Access Control:** Every request that reads or changes data must verify that the logged-in user owns or is allowed to access that resource (prevent IDOR, e.g. `/user/123` accessible by anyone).
19. **Insecure JWT Handling:** Always verify JWT signatures, reject the `none` algorithm, use strong secrets, and set expiry times.
20. **Insecure File Uploads:** Validate file type, size, and extension on the server, rename uploaded files, and never store them in an executable or publicly served directory.
21. **Missing Input Validation:** Validate type, length, format, and range of all user input on the server side; never trust client-side validation alone.
22. **NoSQL and LDAP Injection:** Never pass raw user input into MongoDB queries (e.g. `$where`, `$ne`) or LDAP filters; sanitize and use safe query builders.
23. **Insecure Cookies and Sessions:** Session cookies must use `HttpOnly`, `Secure`, and `SameSite` flags, and sessions must expire and be invalidated on logout.
24. **Secrets in Config Files:** Never commit `.env` files, private keys (`.pem`, `id_rsa`), or cloud credentials; load secrets from environment variables or a secrets manager.
25. **Unsafe Regular Expressions (ReDoS):** Avoid regex patterns with nested quantifiers such as `(a+)+` on user input, as they can freeze the server.
26. **Open Redirects:** Never redirect users to a URL taken directly from a query parameter without checking it against an allowlist.
27. **XML External Entities (XXE):** Disable external entity processing when parsing XML; use safe parsers such as `defusedxml` in Python.
28. **Vulnerable Dependencies:** Avoid adding packages with known vulnerabilities or unpinned versions; pin dependency versions in requirements files.
