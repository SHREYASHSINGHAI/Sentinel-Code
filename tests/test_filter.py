from core.filter import parse_diff_metadata, extract_meaningful_diff

def d(path, body, new=False):
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,3 +1,3 @@\n{body}\n"

def meaningful(diff): return parse_diff_metadata(diff)[1]

def test_empty():
    assert parse_diff_metadata("") == ([], False)
    assert parse_diff_metadata("   \n") == ([], False)

def test_readme_skipped():
    assert not meaningful(d("README.md", "+new docs line"))

def test_lockfile_skipped():
    assert not meaningful(d("package-lock.json", '+  "x": 1'))
    assert not meaningful(d("uv.lock", "+version = 1"))

def test_image_skipped():
    assert not meaningful("diff --git a/a.png b/a.png\nBinary files a/a.png and b/a.png differ\n")

def test_comment_only_python():
    assert not meaningful(d("a.py", "+# just a comment\n+\n"))

def test_code_change_kept():
    assert meaningful(d("a.py", "+x = 1"))

def test_secret_in_comment_kept():
    assert meaningful(d("a.py", '+# api_key = "AIzaSyD1234567890SecretKeyHere"'))

def test_whitespace_only_reindent_c_like():
    # In languages with explicit braces (e.g., .js, .c), pure whitespace formatting is squashed/ignored
    assert not meaningful(d("a.js", "-    x = 1;\n+        x = 1;"))

def test_spacing_reformat_c_like():
    assert not meaningful(d("a.js", "-x=1;\n+x = 1;"))

def test_whitespace_preserved_for_indentation_sensitive():
    # .py, .yaml, .yml, and Makefile changes are semantic and should NOT be squashed
    assert meaningful(d("a.py", "-    x = 1\n+        x = 1"))
    assert meaningful(d("config.yaml", "-  key: value\n+    key: value"))
    assert meaningful(d("config.yml", "-  port: 80\n+    port: 80"))
    assert meaningful(d("Makefile", "-\tall\n+  all"))

def test_real_change_with_same_line_count():
    assert meaningful(d("a.py", "-x = 1\n+x = 2"))

def test_reorder_is_kept():
    assert meaningful(d("a.py", "-a()\n-b()\n+b()\n+a()"))

def test_c_pointer_not_comment():
    assert meaningful(d("a.c", "+*ptr = 1;"))

def test_c_block_comment_ignored():
    assert not meaningful(d("a.c", "+/* note */\n+ * more\n+ */"))

def test_hash_in_c_is_code():
    assert meaningful(d("a.c", "+#include <stdio.h>"))

def test_yaml_config_kept():
    assert meaningful(d("config.yaml", "+password: hunter2"))

def test_env_file_kept():
    assert meaningful(d(".env", "+API_KEY=abc"))

def test_unknown_extension_kept():
    assert meaningful(d("script.xyz", "+# something"))

def test_deleted_file():
    diff = "diff --git a/a.py b/a.py\ndeleted file mode 100644\n--- a/a.py\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-import os\n-x = 1\n"
    paths, m = parse_diff_metadata(diff)
    assert m and paths == ["a.py"]

def test_new_file():
    diff = "diff --git a/n.py b/n.py\nnew file mode 100644\n--- /dev/null\n+++ b/n.py\n@@ -0,0 +1 @@\n+x = 1\n"
    assert parse_diff_metadata(diff) == (["n.py"], True)

def test_pure_rename_not_meaningful():
    diff = "diff --git a/a.py b/b.py\nsimilarity index 100%\nrename from a.py\nrename to b.py\n"
    assert not meaningful(diff)

def test_multi_file_only_code_kept():
    diff = d("README.md", "+docs") + d("core/a.py", "+x = 1")
    paths, m = parse_diff_metadata(diff)
    assert m and paths == ["core/a.py"]
    out = extract_meaningful_diff(diff)
    assert "core/a.py" in out and "README.md" not in out

def test_plain_unified_diff_without_git_header():
    diff = '--- a/auth.py\n+++ b/auth.py\n@@ -10,3 +10,4 @@ def f():\n-    k = os.getenv("K")\n+    k = "AIzaSyD1234567890SecretKeyHere"\n'
    assert parse_diff_metadata(diff) == (["auth.py"], True)

def test_plain_unified_two_files():
    diff = ('--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+b\n'
            '--- a/y.md\n+++ b/y.md\n@@ -1 +1 @@\n-a\n+b\n')
    assert parse_diff_metadata(diff) == (["x.py"], True)

def test_removed_line_starting_with_dashes_is_content():
    # a removed SQL "-- note" line looks like '--- note' in a diff; must not break parsing
    diff = d("q.sql", "--- note\n+SELECT 1;")
    assert meaningful(diff)

def test_commit_message_prefix_ignored():
    diff = "commit abc\nAuthor: x\n\n    + fake plus in message\n\n" + d("a.py", "+x = 1")
    assert parse_diff_metadata(diff) == (["a.py"], True)