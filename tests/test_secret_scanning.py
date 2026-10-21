from core.redact import (
    find_added_secret_matches, find_secret_matches, mask_preview, redact_diff_secrets, redact_secrets,
)

GOOGLE = "AIzaSyD1234567890SecretKeyHere"
DB_PASS = "SuperSecretPass992"


def d(body, path="auth.py"):
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,3 +1,3 @@\n{body}\n"


# ---------------------- masked previews (first chars + *) -------------------- #

def test_mask_preview_shows_few_leading_chars_then_stars():
    assert mask_preview(GOOGLE) == "AIza********"
    assert mask_preview(DB_PASS) == "Supe********"


def test_mask_preview_never_reveals_more_than_a_quarter_and_hides_length():
    assert mask_preview("abcdefgh") == "ab********"             # 8 chars -> 2 visible
    assert mask_preview("abc") == "********"                    # too short -> nothing visible
    assert mask_preview("x" * 10) == "xx********"
    assert len(mask_preview("a" * 20)) == len(mask_preview("a" * 400))


def test_previews_never_contain_the_full_secret():
    text = (
        f'+ api_key = "{GOOGLE}"\n'
        f'+ db = "postgresql://prod_admin:{DB_PASS}@localhost:5432/x"\n'
        '+ aws = "AKIAIOSFODNN7EXAMPLE"\n'
        "+ DB_PASSWORD=mySuperSecretPass123\n"
        '+ s = "unrecognized_custom_token_987654321"\n'
    )
    findings = find_secret_matches(text)
    assert findings
    blob = " ".join(p for _, p in findings)
    for secret in (GOOGLE, DB_PASS, "AKIAIOSFODNN7EXAMPLE", "mySuperSecretPass123", "unrecognized_custom_token_987654321"):
        assert secret not in blob


def test_preview_shapes():
    by_label = {}
    for label, preview in find_secret_matches(
        f'+ db = "postgresql://prod_admin:{DB_PASS}@localhost/x"\n+ DB_PASSWORD=mySuperSecretPass123\n'
    ):
        by_label.setdefault(label, preview)
    assert by_label["url_password"] == "postgresql://prod_admin:Supe********@"
    assert by_label["env_secret"] == "DB_PASSWORD=mySu********"


# ------------------- deletions are never findings; additions are -------------- #

def test_removing_a_secret_is_not_a_finding():
    fix = d(f'-api_key = "{GOOGLE}"\n+api_key = os.getenv("API_KEY")')
    assert find_added_secret_matches(fix) == []


def test_removing_a_whole_env_file_secret_or_pem_is_not_a_finding():
    env = d("-DB_PASSWORD=mySuperSecretPass123\n-STRIPE=rk_live_1234567890123456", path=".env")
    pem = d("-----BEGIN RSA PRIVATE KEY-----\n-MIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----")
    assert find_added_secret_matches(env) == []
    assert find_added_secret_matches(pem) == []


def test_unchanged_context_line_with_secret_is_not_a_finding():
    diff = d(f' api_key = "{GOOGLE}"\n+x = 1')
    assert find_added_secret_matches(diff) == []


def test_adding_a_secret_is_still_a_finding():
    diff = d(f'-api_key = os.getenv("K")\n+api_key = "{GOOGLE}"')
    labels = [l for l, _ in find_added_secret_matches(diff)]
    assert "google_api_key" in labels and "quoted_secret" in labels


def test_new_file_with_secret_is_a_finding():
    diff = ("diff --git a/n.py b/n.py\nnew file mode 100644\n--- /dev/null\n+++ b/n.py\n"
            f'@@ -0,0 +1 @@\n+key = "{GOOGLE}"\n')
    assert find_added_secret_matches(diff)


def test_plain_find_secret_matches_behaviour_is_unchanged_for_non_diff_text():
    doc = f"Here is the setup key: {GOOGLE}\nAWS: AKIAIOSFODNN7EXAMPLE\n"
    assert {"google_api_key", "aws_access_key"} <= {l for l, _ in find_secret_matches(doc)}


# ----------------------- masking before the LLM is diff-aware ----------------- #

def test_redact_diff_labels_added_vs_not_added_and_leaks_nothing():
    diff = d(f'-api_key = "{GOOGLE}"\n+api_key = "AIzaSyD9999999999OtherSecretKey"\n x = "{DB_PASS}"')
    masked, n = redact_diff_secrets(diff)
    assert "[REDACTED:google_api_key]" in masked                 # added line
    assert "[REDACTED-NOT-ADDED:google_api_key]" in masked       # removed line
    assert GOOGLE not in masked and "OtherSecretKey" not in masked
    assert n >= 2


def test_redact_diff_removed_secret_never_gets_the_violation_placeholder():
    masked, n = redact_diff_secrets(d(f'-api_key = "{GOOGLE}"\n+api_key = os.getenv("K")'))
    assert n >= 1 and "[REDACTED:" not in masked and "[REDACTED-NOT-ADDED:" in masked


def test_redact_diff_removed_pem_block_is_fully_masked():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecretbody\n-----END RSA PRIVATE KEY-----"
    masked, n = redact_diff_secrets(d("\n".join("-" + l for l in pem.split("\n"))))
    assert n >= 1 and "secretbody" not in masked and "[REDACTED-NOT-ADDED:private_key]" in masked


def test_redact_diff_clean_diff_roundtrips_exactly():
    diff = d("+def add(a, b):\n+    return a + b\n-old = 1\n context")
    assert redact_diff_secrets(diff) == (diff, 0)
    assert redact_diff_secrets("") == ("", 0)


def test_redact_secrets_original_function_is_untouched():
    masked, n = redact_secrets('+ api_key = "AIzaSyD1234567890SecretKeyHere"')
    assert n == 1 and "[REDACTED:google_api_key]" in masked
