import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Optional

SENTINEL_HOME = Path(__file__).resolve().parent.parent
SENTINEL_RULES = SENTINEL_HOME / "rules" / "security_rules.md"
FALLBACK = "Standard Secure Coding Guidelines: Avoid hardcoded secrets, SQL injection, and unhandled exceptions."

STARTER_RULES_TEMPLATE = """# Custom Security & Architecture Guidelines

> **Project Guidelines for Sentinel-Code Audits**
> Customize, add, or remove rules below to match your project's security and architecture standards.
> Sentinel-Code audits your staged code changes (`git diff --staged`) against these guidelines.

## 1. Secrets & Credentials
1. **No Hardcoded Credentials:** Never hardcode API keys, passwords, bearer tokens, private keys, or secrets. Always use environment variables or secret management services.

## 2. Injection & Input Validation
2. **SQL Injection Prevention:** All SQL queries must use parameterized inputs or ORMs. Never format or concatenate raw strings into queries.
3. **Command Injection Prevention:** Never pass unvalidated user input to `subprocess` with `shell=True`, `os.system()`, or `os.popen()`.
4. **Cross-Site Scripting (XSS):** Never insert untrusted user input directly into HTML without escaping or sanitization.
5. **Path Traversal Prevention:** Normalize file paths, validate against an allowlist, and block `../` sequences in user-supplied filenames.
6. **NoSQL & LDAP Injection:** Never pass raw user input into MongoDB query objects or LDAP filters; sanitize and use safe query builders.
7. **XML External Entities (XXE):** Disable external entity processing when parsing XML; use safe parsers like `defusedxml`.
8. **Insecure Deserialization:** Avoid `pickle.load()` or `yaml.load()` on untrusted data; use `yaml.safe_load()` or JSON.

## 3. Authentication & API Security
9. **Authentication & Rate Limiting:** All public API endpoints must enforce authentication, authorization, and rate limiting.
10. **Broken Object-Level Authorization (IDOR):** Verify that the authenticated user owns or has permission to access the requested resource.
11. **Secure Session & Cookie Handling:** Session cookies must use `HttpOnly`, `Secure`, and `SameSite` flags.
12. **Insecure JWT Handling:** Always verify JWT signatures, reject the `none` algorithm, use strong secrets, and set expiration times.
13. **CORS Configuration:** Do not use `Access-Control-Allow-Origin: *` together with credentials or on endpoints returning private data.
14. **Server-Side Request Forgery (SSRF):** Never fetch URLs supplied by users without validating them against an allowlist; block internal IPs (`localhost`, `127.0.0.1`, `169.254.169.254`).

## 4. Cryptography & Data Protection
15. **Strong Password Hashing:** Use Argon2, bcrypt, or scrypt. Never use plain MD5, SHA-1, or unsalted SHA-256 for passwords.
16. **Modern Cryptography:** Avoid deprecated ciphers (DES, RC4, AES in ECB mode). Never hardcode encryption keys or IVs.
17. **Cryptographically Secure Randomness:** Use `secrets` or `crypto.randomBytes()`; never use `random` or `Math.random()` for tokens or OTPs.
18. **TLS / HTTPS Verification:** Never disable certificate validation (`verify=False`, `rejectUnauthorized: false`) in production code.

## 5. Operations & Error Handling
19. **Safe Error Handling:** Avoid exposing raw stack traces, database schema details, or system internals in error responses.
20. **No Sensitive Data in Logs:** Never log passwords, tokens, API keys, session cookies, or personal data (PII).
21. **Production Debug Mode Disabled:** Never commit code with `DEBUG = True` or verbose debug endpoints enabled for production.
22. **Vulnerable Dependencies:** Pin dependency versions and avoid adding packages with known vulnerabilities.
"""


def get_project_root() -> Path:
    """Finds the root directory of the current git repository, falling back to cwd."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True
        )
        root = res.stdout.strip()
        if root and os.path.isdir(root):
            return Path(root).resolve()
    except Exception:
        pass
    return Path.cwd().resolve()


def get_standard_rules_content() -> str:
    """Loads the global standard Sentinel rules file, falling back to default string."""
    if SENTINEL_RULES.is_file():
        return SENTINEL_RULES.read_text(encoding="utf-8").strip()
    return FALLBACK


def find_project_rules_file(project_root: Optional[Path] = None) -> Optional[Path]:
    """
    Checks if the project defines its own custom security rules file.
    
    Searches for:
      - rules/security_rules.md
      - .sentinel/security_rules.md
      - .sentinel/rules.md
      - security_rules.md
    """
    root = (project_root or get_project_root()).resolve()
    candidates = [
        root / "rules" / "security_rules.md",
        root / ".sentinel" / "security_rules.md",
        root / ".sentinel" / "rules.md",
        root / "security_rules.md",
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def get_rules_preference(project_root: Optional[Path] = None) -> Optional[dict]:
    """
    Checks if the user has already configured rules preference for this project.
    Reads from .sentinelrc, .sentinelrc.json, or .sentinel/config.json.
    """
    root = (project_root or get_project_root()).resolve()
    candidates = [
        root / ".sentinelrc",
        root / ".sentinelrc.json",
        root / ".sentinel" / "config.json",
    ]
    for c in candidates:
        if c.is_file():
            try:
                data = json.loads(c.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
            except Exception:
                text = c.read_text(encoding="utf-8").strip().lower()
                if "standard" in text:
                    return {"rules": "standard"}
                if "custom" in text:
                    return {"rules": "custom"}
    return None


def save_rules_preference(
    preference: str,
    project_root: Optional[Path] = None,
    rules_path: Optional[str] = None
) -> Path:
    """Saves the user's project rules choice into .sentinelrc so they aren't asked repeatedly."""
    root = (project_root or get_project_root()).resolve()
    config_file = root / ".sentinelrc"
    data = {
        "rules": preference,
        "configured_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    if rules_path:
        data["rules_path"] = rules_path
    config_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return config_file


def create_custom_rules_template(project_root: Optional[Path] = None) -> Path:
    """Generates a starter custom rules file in the target project and records the preference."""
    root = (project_root or get_project_root()).resolve()
    rules_dir = root / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    target_file = rules_dir / "security_rules.md"

    if not target_file.exists():
        target_file.write_text(STARTER_RULES_TEMPLATE, encoding="utf-8")

    save_rules_preference("custom", project_root=root, rules_path="rules/security_rules.md")
    return target_file


def prompt_rules_setup(
    project_root: Optional[Path] = None,
    input_func: Callable[[str], str] = input,
    print_func: Callable[..., None] = print
) -> tuple[str, Optional[Path]]:
    """
    Prompts the user interactively when running Sentinel for the very first time
    in a project that has no custom rules file.
    
    Returns:
        (rules_content, created_file_path_or_None)
    """
    root = (project_root or get_project_root()).resolve()
    
    print_func("\n" + "=" * 60)
    print_func("🛡️  Sentinel-Code: Project Rules Setup")
    print_func("=" * 60)
    print_func("No custom rules file found for this project (`rules/security_rules.md`).\n")
    print_func("Would you like to:")
    print_func("  [1] Set up custom rules for this project (generates `rules/security_rules.md`)")
    print_func("  [2] Use Sentinel's standard security & architecture rules")
    print_func("=" * 60)

    try:
        choice = input_func("Select an option [1/2] (default: 2): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        choice = "2"
        print_func("")

    if choice in ("1", "custom", "y", "yes"):
        target_file = create_custom_rules_template(root)
        rel_path = "rules/security_rules.md"
        try:
            rel_path = str(target_file.relative_to(root))
        except ValueError:
            pass
        print_func(f"\n✅ Created custom rules template at: {rel_path}")
        print_func("   You can edit or add rules in this file anytime.")
        print_func("=" * 60 + "\n")
        return target_file.read_text(encoding="utf-8").strip(), target_file
    else:
        save_rules_preference("standard", project_root=root)
        print_func("\n✅ Using Sentinel's standard security & architecture rules.")
        print_func("   (Saved preference to .sentinelrc — you won't be prompted again)")
        print_func("=" * 60 + "\n")
        return get_standard_rules_content(), None


def resolve_project_rules(
    custom_path: Optional[str] = None,
    interactive: bool = True,
    project_root: Optional[Path] = None,
    input_func: Callable[[str], str] = input,
    print_func: Callable[..., None] = print
) -> tuple[str, str]:
    """
    Resolves the security rules to be used for the current audit:
    1. If custom_path is provided via CLI, uses it directly.
    2. If project defines its own rules file, loads it.
    3. If preference is already recorded in .sentinelrc, respects it without asking.
    4. If first time (no rules & no preference) and interactive, prompts user.
    5. In non-interactive environments, defaults to Sentinel standard rules.
    
    Returns:
        (rules_content, rules_source_description)
    """
    root = (project_root or get_project_root()).resolve()

    # 1. Explicit CLI argument overrides everything
    if custom_path:
        p = Path(custom_path)
        if not p.is_absolute():
            p = (root / p).resolve()
        if p.is_file():
            return p.read_text(encoding="utf-8").strip(), f"Custom file: {custom_path}"
        print_func(f"⚠️ Specified rules file '{custom_path}' not found. Falling back to project detection.")

    # 2. Check if project already has a custom rules file
    custom_file = find_project_rules_file(root)
    # If project is Sentinel-Code itself, its rules/security_rules.md is the global standard
    is_sentinel_repo = (root == SENTINEL_HOME)
    if custom_file and not is_sentinel_repo:
        try:
            rel_name = str(custom_file.relative_to(root))
        except ValueError:
            rel_name = custom_file.name
        return custom_file.read_text(encoding="utf-8").strip(), f"Project custom rules: {rel_name}"

    # In Sentinel-Code's own repository, use its rules directly
    if is_sentinel_repo and custom_file:
        return custom_file.read_text(encoding="utf-8").strip(), "Standard Sentinel rules (Sentinel repository)"

    # 3. Check if user already made a choice for this project in .sentinelrc
    pref = get_rules_preference(root)
    if pref is not None:
        pref_mode = pref.get("rules", "standard")
        if pref_mode == "custom" and pref.get("rules_path"):
            c_path = root / pref["rules_path"]
            if c_path.is_file():
                return c_path.read_text(encoding="utf-8").strip(), f"Project custom rules: {pref['rules_path']}"
        return get_standard_rules_content(), "Standard Sentinel rules (configured preference in .sentinelrc)"

    # 4. First time in this project without rules: prompt if interactive
    if input_func is input:
        can_prompt = interactive and sys.stdin.isatty() and sys.stdout.isatty()
    else:
        can_prompt = interactive

    if can_prompt:
        rules_text, created_path = prompt_rules_setup(
            project_root=root,
            input_func=input_func,
            print_func=print_func
        )
        if created_path:
            return rules_text, f"Project custom rules (newly created: {created_path.name})"
        return rules_text, "Standard Sentinel rules (newly selected)"

    # 5. Non-interactive or automated environment: default cleanly to standard rules
    return get_standard_rules_content(), "Standard Sentinel rules"


def load_security_rules(
    rules_path: Optional[str] = None,
    project_root: Optional[Path] = None
) -> str:
    """
    Backwards-compatible rule loader.
    Checks:
      1. Explicit rules_path (relative to project_root or absolute)
      2. Project custom rules
      3. Global Sentinel rules
      4. Fallback string
    """
    root = (project_root or get_project_root()).resolve()

    if rules_path is not None:
        p = Path(rules_path)
        if not p.is_absolute():
            p = root / p
        if p.is_file():
            return p.read_text(encoding="utf-8").strip()

    custom = find_project_rules_file(root)
    if custom and custom.is_file():
        return custom.read_text(encoding="utf-8").strip()

    if SENTINEL_RULES.is_file():
        return SENTINEL_RULES.read_text(encoding="utf-8").strip()

    return FALLBACK