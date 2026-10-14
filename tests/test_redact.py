import sys
from pathlib import Path

# Add project root to path so script can run directly or via pytest
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.redact import redact_secrets

def test_redact_google_api_key():
    diff = '+ api_key = "AIzaSyD1234567890SecretKeyHere"'
    masked, count = redact_secrets(diff)
    assert count == 1
    assert "AIzaSyD1234567890SecretKeyHere" not in masked
    assert "[REDACTED:google_api_key]" in masked

def test_redact_aws_key():
    diff = '+ aws_access_key = "AKIAIOSFODNN7EXAMPLE"'
    masked, count = redact_secrets(diff)
    assert count >= 1
    assert "AKIAIOSFODNN7EXAMPLE" not in masked
    assert "[REDACTED:aws_access_key]" in masked

def test_redact_url_password():
    diff = '+ db_url = "postgresql://admin:superSecret123@localhost:5432/mydb"'
    masked, count = redact_secrets(diff)
    assert count >= 1
    assert "superSecret123" not in masked
    assert "[REDACTED:password]" in masked
    assert "postgresql://admin:[REDACTED:password]@localhost:5432/mydb" in masked

def test_redact_quoted_fallback():
    diff = '+ secret_key = "unrecognized_custom_token_987654321"'
    masked, count = redact_secrets(diff)
    assert count == 1
    assert "unrecognized_custom_token_987654321" not in masked
    assert "[REDACTED:secret]" in masked

def test_redact_clean_code_unchanged():
    diff = '+ def add(a, b):\n+     return a + b'
    masked, count = redact_secrets(diff)
    assert count == 0
    assert masked == diff


def test_redact_env_unquoted_assignment():
    diff = (
        "+ STRIPE_SECRET=whsec_abcdef1234567890\n"
        "+ DB_PASSWORD=mySuperSecretPass123\n"
        "+ export API_KEY=someUnquotedCustomApiKey123\n"
        "+ OAUTH_TOKEN=tokenValueWithoutQuotes\n"
        "+ DB_PASSWD=pass_12345678"
    )
    masked, count = redact_secrets(diff)
    assert count == 5
    assert "whsec_abcdef1234567890" not in masked
    assert "mySuperSecretPass123" not in masked
    assert "someUnquotedCustomApiKey123" not in masked
    assert "tokenValueWithoutQuotes" not in masked
    assert "pass_12345678" not in masked
    assert "+ STRIPE_SECRET=[REDACTED:secret]" in masked
    assert "+ DB_PASSWORD=[REDACTED:secret]" in masked
    assert "+ export API_KEY=[REDACTED:secret]" in masked
    assert "+ OAUTH_TOKEN=[REDACTED:secret]" in masked
    assert "+ DB_PASSWD=[REDACTED:secret]" in masked

if __name__ == "__main__":
    test_redact_google_api_key()
    test_redact_aws_key()
    test_redact_url_password()
    test_redact_quoted_fallback()
    test_redact_clean_code_unchanged()
    test_redact_env_unquoted_assignment()
    print("[PASS] All 6 redact tests passed successfully!")


