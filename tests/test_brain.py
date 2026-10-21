import pytest
pytest.importorskip('dotenv')
pytest.importorskip('langchain_core')
import asyncio
from core.auditor_agent import CodeAuditorBrain

# Test Diff containing a deliberate secret vulnerability
sample_diff = """
--- a/auth.py
+++ b/auth.py
@@ -10,3 +10,4 @@ def connect_db():
-    api_key = os.getenv("API_KEY")
+    api_key = "AIzaSyD1234567890SecretKeyHere"
+    db_url = "postgresql://admin:password123@localhost:5432/mydb"
"""

async def main():
    brain = CodeAuditorBrain()
    print("🤖 Running Audit Test on Sample Diff...\n")
    report = await brain.run_audit(sample_diff)
    print(report)
    print('-'*60)

if __name__ == "__main__":
    asyncio.run(main())