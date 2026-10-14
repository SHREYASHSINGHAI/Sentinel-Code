#!/usr/bin/env sh
# Sentinel-Code Git Pre-commit Hook
# Place this in your repository's .git/hooks/pre-commit and make it executable (chmod +x)

echo "[Sentinel-Code] Running pre-commit security audit..."

# Run sentinel CLI gating on high severity violations
if command -v sentinel >/dev/null 2>&1; then
    sentinel --fail-on high
else
    # Fallback to python execution if sentinel launcher is not in system PATH
    python -m interfaces.cli --fail-on high
fi

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "❌ [Pre-Commit Blocked]: Sentinel-Code detected security violations."
    echo "   Fix the issues listed above or commit with '--no-verify' if intentionally bypassing."
    exit $EXIT_CODE
fi

exit 0
