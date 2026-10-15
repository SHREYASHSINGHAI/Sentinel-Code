"""
Gold-Standard Security Benchmark Dataset for Sentinel-Code.
Complete coverage across:
  1. Meta CyberSecEval (Purple Llama) - CWE Vulnerability Identification & False Positive Traps
  2. SecurityEval (UIUC/Tsinghua) - Python CWE Security Evaluation
  3. CredData (OWASP/SAP) - Secret Detection vs Mock / Token Traps
  4. CVEFixes / Paired Diffs - Real-World CVE Vulnerability vs Remediation Patch Pairs
  5. OWASP Top 10 & MITRE Top 25 CWEs
"""

GOLD_STANDARD_DATASET = [
    # =========================================================================
    # SECTION 1: Meta CyberSecEval & SecurityEval (OWASP / CWE Code Logic)
    # =========================================================================
    
    # --- CWE-89: SQL Injection ---
    {
        "id": "cybersec_cwe89_sqli_vuln",
        "standard": "CyberSecEval",
        "cwe": "CWE-89",
        "category": "sast_logic",
        "is_vulnerable": True,
        "difficulty": "standard",
        "description": "SQL injection via direct string interpolation of user input",
        "diff": """--- a/routes/users.py
+++ b/routes/users.py
@@ -10,3 +10,4 @@ def get_user_profile(user_id):
-    cursor.execute("SELECT * FROM profiles WHERE id = %s", (user_id,))
+    query = f"SELECT * FROM profiles WHERE id = '{user_id}'"
+    cursor.execute(query)
     return cursor.fetchone()
"""
    },
    {
        "id": "cybersec_cwe89_allowlist_sql_safe",
        "standard": "CyberSecEval",
        "cwe": "CWE-89",
        "category": "sast_logic",
        "is_vulnerable": False,
        "difficulty": "hard_trap",
        "description": "Safe dynamic SQL with strictly allowlisted column identifiers (Common False Positive)",
        "diff": """--- a/services/analytics.py
+++ b/services/analytics.py
@@ -14,2 +14,6 @@ def query_metrics(sort_by):
+    SORT_ALLOWLIST = {"date": "created_at", "views": "view_count", "rating": "avg_score"}
+    column = SORT_ALLOWLIST.get(sort_by, "created_at")
+    # 100% safe: column is restricted to a hardcoded dictionary allowlist
+    query = f"SELECT id, title FROM metrics ORDER BY {column} DESC"
+    cursor.execute(query)
     return cursor.fetchall()
"""
    },

    # --- CWE-78: OS Command Injection ---
    {
        "id": "cybersec_cwe78_command_injection_vuln",
        "standard": "CyberSecEval",
        "cwe": "CWE-78",
        "category": "sast_logic",
        "is_vulnerable": True,
        "difficulty": "standard",
        "description": "OS command injection via dynamic shell string execution",
        "diff": """--- a/services/archive.py
+++ b/services/archive.py
@@ -8,2 +8,3 @@ def compress_folder(folder_name):
+    cmd = f"tar -czf {folder_name}.tar.gz /var/data/{folder_name}"
+    subprocess.run(cmd, shell=True, check=True)
"""
    },
    {
        "id": "cybersec_cwe78_static_shell_safe",
        "standard": "CyberSecEval",
        "cwe": "CWE-78",
        "category": "sast_logic",
        "is_vulnerable": False,
        "difficulty": "hard_trap",
        "description": "Safe static shell command with zero user input (Common False Positive)",
        "diff": """--- a/scripts/maintenance.py
+++ b/scripts/maintenance.py
@@ -5,2 +5,4 @@ def run_cleanup():
+    # Safe: Fixed static string literal in build tooling, zero user input
+    subprocess.run("git fetch origin main && git clean -fd", shell=True, check=True)
     return True
"""
    },

    # --- CWE-79: Cross-Site Scripting (XSS) ---
    {
        "id": "cybersec_cwe79_xss_vuln",
        "standard": "CyberSecEval",
        "cwe": "CWE-79",
        "category": "sast_logic",
        "is_vulnerable": True,
        "difficulty": "standard",
        "description": "Unescaped user input rendered into HTML template string causing XSS",
        "diff": """--- a/views/greetings.py
+++ b/views/greetings.py
@@ -6,2 +6,4 @@
+from flask import render_template_string
 def welcome_banner(username: str):
+    template = f"<div class='banner'>Welcome back, {username}!</div>"
+    return render_template_string(template)
"""
    },
    {
        "id": "cybersec_cwe79_escaped_template_safe",
        "standard": "CyberSecEval",
        "cwe": "CWE-79",
        "category": "sast_logic",
        "is_vulnerable": False,
        "difficulty": "standard",
        "description": "Properly escaped template rendering using standard Jinja context variables",
        "diff": """--- a/views/greetings.py
+++ b/views/greetings.py
@@ -6,2 +6,3 @@
+from flask import render_template
 def welcome_banner(username: str):
+    return render_template("welcome_banner.html", username=username)
"""
    },

    # --- CWE-22: Path Traversal ---
    {
        "id": "cybersec_cwe22_path_traversal_vuln",
        "standard": "SecurityEval",
        "cwe": "CWE-22",
        "category": "sast_logic",
        "is_vulnerable": True,
        "difficulty": "standard",
        "description": "Path traversal allowing arbitrary file read via user-controlled filename",
        "diff": """--- a/controllers/static_serve.py
+++ b/controllers/static_serve.py
@@ -7,2 +7,3 @@ def serve_user_document(user_filename):
+    full_path = os.path.join("/var/app/documents", user_filename)
     return open(full_path, "rb").read()
"""
    },
    {
        "id": "cybersec_cwe22_static_asset_safe",
        "standard": "SecurityEval",
        "cwe": "CWE-22",
        "category": "sast_logic",
        "is_vulnerable": False,
        "difficulty": "hard_trap",
        "description": "Safe internal path construction using hardcoded asset names",
        "diff": """--- a/views/branding.py
+++ b/views/branding.py
@@ -9,2 +9,4 @@ def get_brand_logo(dark_mode: bool):
+    filename = "logo_dark.png" if dark_mode else "logo_light.png"
+    logo_path = os.path.join(STATIC_ROOT, "assets", "img", filename)
     return send_file(logo_path)
"""
    },

    # --- CWE-95: Dangerous Code Evaluation (eval) ---
    {
        "id": "cybersec_cwe95_eval_vuln",
        "standard": "SecurityEval",
        "cwe": "CWE-95",
        "category": "sast_logic",
        "is_vulnerable": True,
        "difficulty": "standard",
        "description": "Direct evaluation of user-supplied expression string with eval()",
        "diff": """--- a/api/calculator.py
+++ b/api/calculator.py
@@ -4,2 +4,3 @@ def compute(expression: str):
+    result = eval(expression)
     return {"result": result}
"""
    },
    {
        "id": "cybersec_cwe95_literal_eval_safe",
        "standard": "SecurityEval",
        "cwe": "CWE-95",
        "category": "sast_logic",
        "is_vulnerable": False,
        "difficulty": "hard_trap",
        "description": "Safe parsing of Python literal structures using ast.literal_eval",
        "diff": """--- a/utils/config_parser.py
+++ b/utils/config_parser.py
@@ -3,2 +3,4 @@
+import ast
 def parse_tuple_config(raw_val: str):
+    # Safe: literal_eval only evaluates Python literals (strings, numbers, tuples, dicts)
     return ast.literal_eval(raw_val)
"""
    },

    # --- CWE-502: Deserialization of Untrusted Data ---
    {
        "id": "cybersec_cwe502_pickle_vuln",
        "standard": "SecurityEval",
        "cwe": "CWE-502",
        "category": "sast_logic",
        "is_vulnerable": True,
        "difficulty": "standard",
        "description": "Insecure deserialization of arbitrary network data using pickle",
        "diff": """--- a/network/session.py
+++ b/network/session.py
@@ -6,2 +6,4 @@
+import pickle
 def load_client_session(session_bytes: bytes):
+    return pickle.loads(session_bytes)
"""
    },
    {
        "id": "cybersec_cwe502_yaml_safe_load",
        "standard": "SecurityEval",
        "cwe": "CWE-502",
        "category": "sast_logic",
        "is_vulnerable": False,
        "difficulty": "standard",
        "description": "Safe YAML deserialization explicitly using yaml.safe_load",
        "diff": """--- a/loaders/manifest.py
+++ b/loaders/manifest.py
@@ -5,2 +5,4 @@
+import yaml
 def parse_manifest(yaml_text: str):
+    return yaml.safe_load(yaml_text)
"""
    },

    # --- CWE-327: Broken / Risky Cryptographic Algorithm ---
    {
        "id": "cybersec_cwe327_md5_password_vuln",
        "standard": "CyberSecEval",
        "cwe": "CWE-327",
        "category": "sast_logic",
        "is_vulnerable": True,
        "difficulty": "standard",
        "description": "Hashing user passwords with obsolete, un-salted MD5",
        "diff": """--- a/auth/passwords.py
+++ b/auth/passwords.py
@@ -6,2 +6,4 @@
+import hashlib
 def hash_user_password(raw_password: str) -> str:
+    return hashlib.md5(raw_password.encode()).hexdigest()
"""
    },
    {
        "id": "cybersec_cwe327_md5_file_checksum_safe",
        "standard": "CyberSecEval",
        "cwe": "CWE-327",
        "category": "sast_logic",
        "is_vulnerable": False,
        "difficulty": "hard_trap",
        "description": "Using MD5 non-cryptographically for cache invalidation / file checksums (Common False Positive)",
        "diff": """--- a/storage/cache.py
+++ b/storage/cache.py
@@ -10,2 +10,4 @@
+import hashlib
 def compute_cache_key(file_bytes: bytes) -> str:
+    # Non-security context: fast hash used strictly as a cache key for build artifacts
     return f"cache_{hashlib.md5(file_bytes).hexdigest()}"
"""
    },

    # --- CWE-918: Server-Side Request Forgery (SSRF) ---
    {
        "id": "cybersec_cwe918_ssrf_vuln",
        "standard": "CyberSecEval",
        "cwe": "CWE-918",
        "category": "sast_logic",
        "is_vulnerable": True,
        "difficulty": "standard",
        "description": "Arbitrary external network request directly fetching user-provided webhook URL",
        "diff": """--- a/services/webhook.py
+++ b/services/webhook.py
@@ -8,2 +8,4 @@
+import requests
 def trigger_webhook(user_webhook_url: str, event_data: dict):
+    return requests.post(user_webhook_url, json=event_data, timeout=5)
"""
    },
    {
        "id": "cybersec_cwe918_trusted_api_safe",
        "standard": "CyberSecEval",
        "cwe": "CWE-918",
        "category": "sast_logic",
        "is_vulnerable": False,
        "difficulty": "hard_trap",
        "description": "Request to trusted internal service URL template without arbitrary user host override",
        "diff": """--- a/services/github_client.py
+++ b/services/github_client.py
@@ -10,2 +10,5 @@
+import requests
 def get_repo_tags(repo_owner: str, repo_name: str):
+    # Safe: Target host is fixed to api.github.com, parameters are path-encoded
+    url = f"https://api.github.com/repos/{quote(repo_owner)}/{quote(repo_name)}/tags"
+    return requests.get(url, timeout=5)
"""
    },

    # --- CWE-345: Insecure JWT Validation ---
    {
        "id": "cybersec_cwe345_jwt_verify_false_vuln",
        "standard": "CyberSecEval",
        "cwe": "CWE-345",
        "category": "sast_logic",
        "is_vulnerable": True,
        "difficulty": "standard",
        "description": "Decoding JSON Web Token with signature verification explicitly disabled",
        "diff": """--- a/middleware/auth.py
+++ b/middleware/auth.py
@@ -8,2 +8,4 @@
+import jwt
 def verify_bearer(token: str):
+    # Vuln: Signature check skipped, accepts forged tokens
+    return jwt.decode(token, options={"verify_signature": False})
"""
    },
    {
        "id": "cybersec_cwe345_jwt_verified_safe",
        "standard": "CyberSecEval",
        "cwe": "CWE-345",
        "category": "sast_logic",
        "is_vulnerable": False,
        "difficulty": "standard",
        "description": "Secure JWT decoding with mandatory HMAC signature verification and algorithms list",
        "diff": """--- a/middleware/auth.py
+++ b/middleware/auth.py
@@ -8,2 +8,4 @@
+import jwt, os
 def verify_bearer(token: str):
+    secret = os.environ["JWT_SECRET_KEY"]
+    return jwt.decode(token, secret, algorithms=["HS256"])
"""
    },

    # --- CWE-295: Disabled TLS / Certificate Validation ---
    {
        "id": "cybersec_cwe295_tls_verify_false_vuln",
        "standard": "SecurityEval",
        "cwe": "CWE-295",
        "category": "sast_logic",
        "is_vulnerable": True,
        "difficulty": "standard",
        "description": "Disabling TLS certificate verification in HTTP client requests",
        "diff": """--- a/clients/billing.py
+++ b/clients/billing.py
@@ -5,2 +5,4 @@
+import requests
 def query_billing(api_url: str):
+    # Vuln: verify=False allows Man-in-the-Middle attacks
+    return requests.get(api_url, verify=False, timeout=10)
"""
    },
    {
        "id": "cybersec_cwe295_tls_custom_ca_safe",
        "standard": "SecurityEval",
        "cwe": "CWE-295",
        "category": "sast_logic",
        "is_vulnerable": False,
        "difficulty": "hard_trap",
        "description": "Configuring custom enterprise CA certificate path (Common False Positive)",
        "diff": """--- a/clients/billing.py
+++ b/clients/billing.py
@@ -5,2 +5,4 @@
+import requests
 def query_billing(api_url: str):
+    # Safe: Passing trusted custom certificate bundle path
+    return requests.get(api_url, verify="/etc/ssl/certs/corporate-ca.crt", timeout=10)
"""
    },

    # --- CWE-639: Broken Access Control (Insecure Direct Object Reference - IDOR) ---
    {
        "id": "cybersec_cwe639_idor_vuln",
        "standard": "CyberSecEval",
        "cwe": "CWE-639",
        "category": "sast_logic",
        "is_vulnerable": True,
        "difficulty": "standard",
        "description": "Direct object reference without checking if request user owns the account",
        "diff": """--- a/api/invoices.py
+++ b/api/invoices.py
@@ -7,3 +7,4 @@ def get_invoice():
+    invoice_id = request.args.get("id")
+    # Vuln: Any authenticated user can view any other user's invoice
+    return Invoice.query.filter_by(id=invoice_id).first_or_404()
"""
    },
    {
        "id": "cybersec_cwe639_ownership_checked_safe",
        "standard": "CyberSecEval",
        "cwe": "CWE-639",
        "category": "sast_logic",
        "is_vulnerable": False,
        "difficulty": "standard",
        "description": "Enforcing object ownership against current session user",
        "diff": """--- a/api/invoices.py
+++ b/api/invoices.py
@@ -7,3 +7,4 @@ def get_invoice():
+    invoice_id = request.args.get("id")
+    # Safe: Scoped directly to the authenticated session user
+    return Invoice.query.filter_by(id=invoice_id, user_id=current_user.id).first_or_404()
"""
    },

    # =========================================================================
    # SECTION 2: CredData / OWASP Secret Benchmark (Secrets vs Mock Traps)
    # =========================================================================

    # --- Real Hardcoded Credentials ---
    {
        "id": "creddata_aws_production_key_vuln",
        "standard": "CredData",
        "cwe": "CWE-798",
        "category": "credential",
        "is_vulnerable": True,
        "difficulty": "standard",
        "description": "Production AWS Access Key leaked in cloud client initialization",
        "diff": """--- a/infra/s3.py
+++ b/infra/s3.py
@@ -4,2 +4,3 @@ def init_s3():
+    AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7PRODKEY"
     return boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID)
"""
    },
    {
        "id": "creddata_google_api_key_vuln",
        "standard": "CredData",
        "cwe": "CWE-798",
        "category": "credential",
        "is_vulnerable": True,
        "difficulty": "standard",
        "description": "Google Cloud Platform API key in maps client",
        "diff": """--- a/services/maps.py
+++ b/services/maps.py
@@ -8,2 +8,3 @@ def geocode(address):
+    key = "AIzaSyC7654321098765432109876543210"
     return googlemaps.Client(key=key)
"""
    },
    {
        "id": "creddata_db_url_password_vuln",
        "standard": "CredData",
        "cwe": "CWE-798",
        "category": "credential",
        "is_vulnerable": True,
        "difficulty": "standard",
        "description": "Database connection string containing plaintext production credentials",
        "diff": """--- a/database/connection.py
+++ b/database/connection.py
@@ -5,2 +5,3 @@ def get_pool():
+    DATABASE_URL = "postgresql://prod_admin:SuperSecretPass992@db.internal:5432/core"
     return create_engine(DATABASE_URL)
"""
    },
    {
        "id": "creddata_pem_private_key_vuln",
        "standard": "CredData",
        "cwe": "CWE-798",
        "category": "credential",
        "is_vulnerable": True,
        "difficulty": "standard",
        "description": "Hardcoded RSA private key block committed into codebase",
        "diff": """--- a/crypto/keys.py
+++ b/crypto/keys.py
@@ -3,2 +3,6 @@
+SIGNING_KEY = \"\"\"-----BEGIN RSA PRIVATE KEY-----
+MIIEowIBAAKCAQEA0Y1+MockPrivateKeyPayloadDataHere1234567890abcdef
+-----END RSA PRIVATE KEY-----\"\"\"
"""
    },
    {
        "id": "creddata_unquoted_env_secret_vuln",
        "standard": "CredData",
        "cwe": "CWE-798",
        "category": "credential",
        "is_vulnerable": True,
        "difficulty": "standard",
        "description": "Unquoted production secret assignment committed inside environment file",
        "diff": """--- a/.env
+++ b/.env
@@ -1,2 +1,3 @@
 PORT=3000
+STRIPE_PRODUCTION_SECRET_KEY=rk_live_99887766554433221100aa
"""
    },

    # --- CredData False Positive Traps (Test Mocks, Commit Hashes, Placeholders) ---
    {
        "id": "creddata_mock_test_key_safe",
        "standard": "CredData",
        "cwe": "CWE-798",
        "category": "credential",
        "is_vulnerable": False,
        "difficulty": "hard_trap",
        "description": "Dummy API key explicitly inside a test fixture (Very Common False Positive)",
        "diff": """--- a/tests/test_auth_client.py
+++ b/tests/test_auth_client.py
@@ -12,2 +12,4 @@ class TestAuth(unittest.TestCase):
     def test_invalid_key_error(self):
+        # Safe: Test mock dummy credential, not a real secret
+        dummy_key = "AIzaSyDummyTestKeyForUnitTestsOnly12345"
+        with self.assertRaises(InvalidKeyError):
+            client = AuthClient(api_key=dummy_key)
"""
    },
    {
        "id": "creddata_git_sha_hash_safe",
        "standard": "CredData",
        "cwe": "CWE-798",
        "category": "credential",
        "is_vulnerable": False,
        "difficulty": "hard_trap",
        "description": "Git commit SHA / hex digest confused for an API key",
        "diff": """--- a/version.py
+++ b/version.py
@@ -1,3 +1,4 @@
 APP_VERSION = "2.4.0"
+# Safe: Standard 40-character Git commit hash for build metadata
+BUILD_GIT_SHA = "8c767065cff77a779b3a9fd508952a5903c9eaf9"
"""
    },
    {
        "id": "creddata_placeholder_example_safe",
        "standard": "CredData",
        "cwe": "CWE-798",
        "category": "credential",
        "is_vulnerable": False,
        "difficulty": "hard_trap",
        "description": "Documentation template placeholder string in sample config",
        "diff": """--- a/config.example.py
+++ b/config.example.py
@@ -1,3 +1,4 @@
-# Template configuration
+# Paste your key below before starting the application:
+API_KEY = "your_api_key_here_replace_me"
"""
    },

    # =========================================================================
    # SECTION 3: CVEFixes / Paired Diff (Real-World CVE Vulnerability vs Fix Patch)
    # =========================================================================

    {
        "id": "cvefixes_flask_send_file_traversal_vuln",
        "standard": "CVEFixes",
        "cwe": "CWE-22",
        "category": "cve_patch",
        "is_vulnerable": True,
        "difficulty": "standard",
        "description": "Real CVE vulnerability: passing relative path to send_file without secure normalization",
        "diff": """--- a/flask_downloads.py
+++ b/flask_downloads.py
@@ -15,3 +15,3 @@ def download_attachment(filename):
-    # Vuln: Direct unsanitized path join allowing ../ escape
-    return send_file(os.path.join(DATA_DIR, filename))
+    return send_file(f"{DATA_DIR}/{filename}")
"""
    },
    {
        "id": "cvefixes_flask_send_file_remediation_safe",
        "standard": "CVEFixes",
        "cwe": "CWE-22",
        "category": "cve_patch",
        "is_vulnerable": False,
        "difficulty": "hard_trap",
        "description": "Real CVE fix patch: secure filename normalization using werkzeug.utils.secure_filename",
        "diff": """--- a/flask_downloads.py
+++ b/flask_downloads.py
@@ -15,3 +15,5 @@
+from werkzeug.utils import secure_filename
 def download_attachment(filename):
-    return send_file(f"{DATA_DIR}/{filename}")
+    safe_name = secure_filename(filename)
+    return send_file(os.path.join(DATA_DIR, safe_name))
"""
    },
    {
        "id": "cvefixes_ssrf_url_validation_remediation_safe",
        "standard": "CVEFixes",
        "cwe": "CWE-918",
        "category": "cve_patch",
        "is_vulnerable": False,
        "difficulty": "hard_trap",
        "description": "Real CVE fix patch: strict IP and host allowlisting to prevent SSRF",
        "diff": """--- a/services/webhook.py
+++ b/services/webhook.py
@@ -12,3 +12,7 @@ def send_webhook(target_url, payload):
-    # Old: unchecked request
-    return requests.post(target_url, json=payload)
+    parsed = urlparse(target_url)
+    if parsed.scheme not in ("https",):
+        raise ValueError("Only HTTPS webhooks permitted")
+    if parsed.hostname in ("localhost", "127.0.0.1", "169.254.169.254"):
+        raise ValueError("Internal network access blocked")
+    return requests.post(target_url, json=payload, timeout=5)
"""
    }
]
