import json
import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest

from core.rules_loader import (
    SENTINEL_RULES,
    STARTER_RULES_TEMPLATE,
    create_custom_rules_template,
    find_project_rules_file,
    get_project_root,
    get_rules_preference,
    get_standard_rules_content,
    load_security_rules,
    prompt_rules_setup,
    resolve_project_rules,
    save_rules_preference,
)


def test_standard_rules_loaded():
    content = get_standard_rules_content()
    assert "No Hardcoded Credentials" in content or "Security" in content
    assert len(content) > 50


def test_find_project_rules_file(tmp_path: Path):
    # None when empty
    assert find_project_rules_file(tmp_path) is None

    # Found in rules/security_rules.md
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_file = rules_dir / "security_rules.md"
    rule_file.write_text("Custom Rule 1: Always validate input", encoding="utf-8")

    found = find_project_rules_file(tmp_path)
    assert found == rule_file
    assert found.read_text(encoding="utf-8") == "Custom Rule 1: Always validate input"


def test_find_project_rules_in_dot_sentinel(tmp_path: Path):
    dot_dir = tmp_path / ".sentinel"
    dot_dir.mkdir()
    rule_file = dot_dir / "security_rules.md"
    rule_file.write_text("Custom Rule in .sentinel", encoding="utf-8")

    found = find_project_rules_file(tmp_path)
    assert found == rule_file


def test_get_and_save_rules_preference(tmp_path: Path):
    assert get_rules_preference(tmp_path) is None

    save_rules_preference("standard", project_root=tmp_path)
    pref = get_rules_preference(tmp_path)
    assert pref is not None
    assert pref.get("rules") == "standard"

    save_rules_preference("custom", project_root=tmp_path, rules_path="rules/security_rules.md")
    pref2 = get_rules_preference(tmp_path)
    assert pref2.get("rules") == "custom"
    assert pref2.get("rules_path") == "rules/security_rules.md"


def test_create_custom_rules_template(tmp_path: Path):
    created = create_custom_rules_template(tmp_path)
    assert created.exists()
    assert created == tmp_path / "rules" / "security_rules.md"
    content = created.read_text(encoding="utf-8")
    assert "Custom Security & Architecture Guidelines" in content
    assert "No Hardcoded Credentials" in content

    # Verifies preference was also saved
    pref = get_rules_preference(tmp_path)
    assert pref is not None
    assert pref.get("rules") == "custom"


def test_prompt_rules_setup_option_1_creates_custom(tmp_path: Path):
    outputs = []
    text, created = prompt_rules_setup(
        project_root=tmp_path,
        input_func=lambda prompt: "1",
        print_func=lambda msg: outputs.append(msg)
    )

    assert created is not None
    assert created.exists()
    assert (tmp_path / "rules" / "security_rules.md").exists()
    assert "Created custom rules template" in "".join(outputs)
    assert "Custom Security & Architecture Guidelines" in text


def test_prompt_rules_setup_option_2_saves_standard(tmp_path: Path):
    outputs = []
    text, created = prompt_rules_setup(
        project_root=tmp_path,
        input_func=lambda prompt: "2",
        print_func=lambda msg: outputs.append(msg)
    )

    assert created is None
    assert not (tmp_path / "rules" / "security_rules.md").exists()
    pref = get_rules_preference(tmp_path)
    assert pref is not None
    assert pref.get("rules") == "standard"
    assert "Using Sentinel's standard security & architecture rules" in "".join(outputs)


def test_resolve_project_rules_first_time_then_remember_standard(tmp_path: Path):
    # First run: user chooses standard (option 2)
    prompt_count = 0

    def mock_input(p):
        nonlocal prompt_count
        prompt_count += 1
        return "2"

    rules1, source1 = resolve_project_rules(
        interactive=True,
        project_root=tmp_path,
        input_func=mock_input,
        print_func=lambda m: None
    )
    assert prompt_count == 1
    assert "standard" in source1.lower()

    # Second run: must NOT prompt again!
    rules2, source2 = resolve_project_rules(
        interactive=True,
        project_root=tmp_path,
        input_func=mock_input,
        print_func=lambda m: None
    )
    assert prompt_count == 1  # Did NOT prompt again!
    assert "standard" in source2.lower()
    assert ".sentinelrc" in source2.lower()


def test_resolve_project_rules_first_time_then_remember_custom(tmp_path: Path):
    # First run: user chooses custom (option 1)
    prompt_count = 0

    def mock_input(p):
        nonlocal prompt_count
        prompt_count += 1
        return "1"

    rules1, source1 = resolve_project_rules(
        interactive=True,
        project_root=tmp_path,
        input_func=mock_input,
        print_func=lambda m: None
    )
    assert prompt_count == 1
    assert (tmp_path / "rules" / "security_rules.md").exists()

    # Second run: custom rules file already exists, must NOT prompt again!
    rules2, source2 = resolve_project_rules(
        interactive=True,
        project_root=tmp_path,
        input_func=mock_input,
        print_func=lambda m: None
    )
    assert prompt_count == 1  # Did NOT prompt again!
    assert "custom rules" in source2.lower()


def test_resolve_project_rules_non_interactive_never_prompts(tmp_path: Path):
    prompt_called = False

    def mock_input(p):
        nonlocal prompt_called
        prompt_called = True
        return "1"

    rules, source = resolve_project_rules(
        interactive=False,
        project_root=tmp_path,
        input_func=mock_input,
        print_func=lambda m: None
    )
    assert not prompt_called
    assert "Standard Sentinel rules" in source


def test_resolve_project_rules_explicit_cli_file(tmp_path: Path):
    custom_file = tmp_path / "my_special_rules.md"
    custom_file.write_text("Rule: Never push on Friday", encoding="utf-8")

    rules, source = resolve_project_rules(
        custom_path=str(custom_file),
        interactive=True,
        project_root=tmp_path
    )
    assert "Never push on Friday" in rules
    assert "Custom file" in source


def test_load_security_rules_backwards_compatible(tmp_path: Path):
    # Default without custom returns standard rules
    res = load_security_rules(project_root=tmp_path)
    assert len(res) > 50

    # With project custom rules
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "security_rules.md").write_text("Specific test rule", encoding="utf-8")

    res_custom = load_security_rules(project_root=tmp_path)
    assert res_custom == "Specific test rule"


def test_cli_init_rules_flag(tmp_path: Path):
    from interfaces.cli import main
    with patch("sys.argv", ["sentinel", "--init-rules"]), \
         patch("interfaces.cli.get_project_root", return_value=tmp_path):
        with pytest.raises(SystemExit) as exc:
            import asyncio
            asyncio.run(main())
        assert exc.value.code == 0
        assert (tmp_path / "rules" / "security_rules.md").exists()

