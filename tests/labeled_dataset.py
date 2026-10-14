"""
Dataset of labeled code diffs for precision and recall benchmark.
Labels:
  - is_vulnerable: True / False
  - category: "credential" | "sql_injection" | "command_injection" | "xss" | "path_traversal" | "auth" | "clean"
  - expected_rule: Expected security rule violated, or None
"""

LABELED_DIFF_DATASET = [
    # --- 1. HARDCODED CREDENTIALS (VULNERABLE) ---
    {
        "id": "vuln_google_key",
        "description": "Hardcoded Google API key",
        "is_vulnerable": True,
        "category": "credential",
        "gitleaks_detectable": True,
        "semgrep_detectable": True,
        "diff": """--- a/services/maps.py
+++ b/services/maps.py
@@ -5,2 +5,3 @@
 def get_geocode(address):
+    api_key = "AIzaSyD1234567890SecretKeyHere123"
     return client.lookup(address, key=api_key)
"""
    },
    {
        "id": "vuln_aws_secret",
        "description": "Hardcoded AWS Access Key",
        "is_vulnerable": True,
        "category": "credential",
        "gitleaks_detectable": True,
        "semgrep_detectable": True,
        "diff": """--- a/storage/s3.py
+++ b/storage/s3.py
@@ -10,2 +10,3 @@
 def init_client():
+    aws_key = "AKIAIOSFODNN7EXAMPLE"
     return boto3.client('s3', aws_access_key_id=aws_key)
"""
    },
    {
        "id": "vuln_db_url_password",
        "description": "Hardcoded Database password in connection URL",
        "is_vulnerable": True,
        "category": "credential",
        "gitleaks_detectable": True,
        "semgrep_detectable": True,
        "diff": """--- a/database.py
+++ b/database.py
@@ -8,2 +8,3 @@
 def get_engine():
+    db_url = "postgresql://postgres:SuperSecretP@ss123@prod-db.internal:5432/main"
     return create_engine(db_url)
"""
    },
    {
        "id": "vuln_unquoted_env_secret",
        "description": "App secret key in environment file",
        "is_vulnerable": True,
        "category": "credential",
        "gitleaks_detectable": True,
        "semgrep_detectable": False,
        "diff": """--- a/.env
+++ b/.env
@@ -1,2 +1,3 @@
 PORT=8080
+SERVICE_APP_SECRET_TOKEN=mock_secret_token_val_9988
"""
    },

    # --- 2. SQL INJECTION (VULNERABLE) ---
    {
        "id": "vuln_sqli_raw_format",
        "description": "SQL Injection via string formatting",
        "is_vulnerable": True,
        "category": "sql_injection",
        "gitleaks_detectable": False,
        "semgrep_detectable": True,
        "diff": """--- a/users.py
+++ b/users.py
@@ -12,3 +12,4 @@
 def find_user(username):
-    return db.execute("SELECT * FROM users WHERE username = %s", (username,))
+    query = f"SELECT * FROM users WHERE username = '{username}'"
+    return db.execute(query)
"""
    },
    {
        "id": "vuln_sqli_concatenation",
        "description": "SQL Injection via string concatenation",
        "is_vulnerable": True,
        "category": "sql_injection",
        "gitleaks_detectable": False,
        "semgrep_detectable": True,
        "diff": """--- a/repositories/order_repo.py
+++ b/repositories/order_repo.py
@@ -20,2 +20,3 @@
 def get_order_by_id(order_id):
+    sql = "SELECT * FROM orders WHERE id = " + str(order_id)
     cursor.execute(sql)
"""
    },

    # --- 3. DANGEROUS SYSTEM CALLS & COMMAND INJECTION (VULNERABLE) ---
    {
        "id": "vuln_eval_dynamic",
        "description": "Dangerous eval with dynamic user input",
        "is_vulnerable": True,
        "category": "command_injection",
        "gitleaks_detectable": False,
        "semgrep_detectable": True,
        "diff": """--- a/calculator.py
+++ b/calculator.py
@@ -5,2 +5,3 @@
 def calculate_expression(user_expr):
+    return eval(user_expr)
"""
    },
    {
        "id": "vuln_subprocess_shell_true",
        "description": "Subprocess call with shell=True and user input",
        "is_vulnerable": True,
        "category": "command_injection",
        "gitleaks_detectable": False,
        "semgrep_detectable": True,
        "diff": """--- a/tasks.py
+++ b/tasks.py
@@ -14,2 +14,3 @@
 def ping_host(target_host):
+    subprocess.run(f"ping -c 1 {target_host}", shell=True)
"""
    },

    # --- 4. PATH TRAVERSAL (VULNERABLE) ---
    {
        "id": "vuln_path_traversal",
        "description": "Reading file directly from user-controlled filename",
        "is_vulnerable": True,
        "category": "path_traversal",
        "gitleaks_detectable": False,
        "semgrep_detectable": True,
        "diff": """--- a/handlers/downloads.py
+++ b/handlers/downloads.py
@@ -7,2 +7,3 @@
 def download_report(user_filename):
+    filepath = os.path.join("/var/reports", user_filename)
     return open(filepath, "rb").read()
"""
    },

    # --- 5. CLEAN CODE (BENIGN CHANGES / NON-VULNERABLE) ---
    {
        "id": "clean_env_variable_usage",
        "description": "Safe loading of credentials via os.getenv",
        "is_vulnerable": False,
        "category": "clean",
        "gitleaks_detectable": False,
        "semgrep_detectable": False,
        "diff": """--- a/auth.py
+++ b/auth.py
@@ -8,3 +8,4 @@
 def get_stripe_key():
-    return "hardcoded_old"
+    key = os.getenv("STRIPE_API_KEY")
+    return key
"""
    },
    {
        "id": "clean_parameterized_query",
        "description": "Safe parameterized SQL query",
        "is_vulnerable": False,
        "category": "clean",
        "gitleaks_detectable": False,
        "semgrep_detectable": False,
        "diff": """--- a/database/queries.py
+++ b/database/queries.py
@@ -15,2 +15,3 @@
 def fetch_profile(account_id):
+    cursor.execute("SELECT name, email FROM accounts WHERE id = %s", (account_id,))
     return cursor.fetchone()
"""
    },
    {
        "id": "clean_math_logic",
        "description": "Pure algorithmic math logic update",
        "is_vulnerable": False,
        "category": "clean",
        "gitleaks_detectable": False,
        "semgrep_detectable": False,
        "diff": """--- a/math_utils.py
+++ b/math_utils.py
@@ -1,5 +1,6 @@
 def fibonacci(n):
     if n <= 1:
         return n
-    return fibonacci(n-1) + fibonacci(n-2)
+    a, b = 0, 1
+    for _ in range(n): a, b = b, a + b
+    return a
"""
    },
    {
        "id": "clean_safe_subprocess",
        "description": "Safe subprocess call with explicit argument list and no shell",
        "is_vulnerable": False,
        "category": "clean",
        "gitleaks_detectable": False,
        "semgrep_detectable": False,
        "diff": """--- a/tools/git_helper.py
+++ b/tools/git_helper.py
@@ -10,2 +10,3 @@
 def get_git_tag():
+    return subprocess.check_output(["git", "describe", "--tags"]).decode().strip()
"""
    },
    {
        "id": "clean_input_sanitization",
        "description": "Safe path normalization and basename extraction",
        "is_vulnerable": False,
        "category": "clean",
        "gitleaks_detectable": False,
        "semgrep_detectable": False,
        "diff": """--- a/files.py
+++ b/files.py
@@ -12,2 +12,4 @@
 def get_safe_file(raw_name):
+    safe_name = os.path.basename(raw_name)
+    return os.path.join(ALLOWED_DIR, safe_name)
"""
    },
    {
        "id": "clean_docstring_and_type_hints",
        "description": "Type hint annotations and docstrings",
        "is_vulnerable": False,
        "category": "clean",
        "gitleaks_detectable": False,
        "semgrep_detectable": False,
        "diff": """--- a/models/user.py
+++ b/models/user.py
@@ -3,2 +3,4 @@
-def serialize_user(user):
+def serialize_user(user: dict) -> dict:
+    \"\"\"Converts user object to JSON serializable dictionary.\"\"\"
     return {"id": user.get("id"), "username": user.get("username")}
"""
    }
]
