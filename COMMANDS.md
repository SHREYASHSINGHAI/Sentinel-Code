# Sentinel-Code: Complete Setup & Command Reference

This guide provides the complete, step-by-step command reference for cloning, configuring, and using Sentinel-Code on your local machine across Windows, macOS, and Linux.

---

## 1. Clone & Environment Setup

### Step 1: Clone the Repository
```bash
git clone https://github.com/SHREYASHSINGHAI/Sentinel-Code.git
cd Sentinel-Code
```

---

### Step 2: Create & Activate Virtual Environment

#### On Windows (PowerShell):
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

> **Note (PowerShell Execution Policy):** If script execution is restricted on your system, run:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

#### On Windows (Command Prompt - CMD):
```cmd
python -m venv .venv
.\.venv\Scripts\activate.bat
```

#### On macOS / Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

---

### Step 4: Configure Environment Variables

Create your local `.env` configuration file from the template:

#### On Windows (PowerShell / CMD):
```cmd
copy .env.example .env
```

#### On macOS / Linux:
```bash
cp .env.example .env
```

#### Set your Gemini API Key in `.env`:
Open `.env` in your code editor and enter your Gemini API key ([Get an API Key from Google AI Studio](https://aistudio.google.com/apikey)):

```env
GEMINI_API_KEY=your_actual_gemini_api_key_here
MODEL="gemini-2.5-flash"
```

*(Alternatively, export it directly in your terminal session: `export GEMINI_API_KEY="your_key"` or `$env:GEMINI_API_KEY="your_key"`)*

---

## 2. One-Time Global Setup (Run `sentinel` from ANY Project)

Adding Sentinel's `scripts/` folder to your system `PATH` allows you to run `sentinel` inside any Git repository on your machine without specifying the path.

### On Windows:
1. Open PowerShell and check the absolute path to `scripts`:
   ```powershell
   Resolve-Path .\scripts
   ```
2. Add that path (e.g., `D:\Sentinel-Code\scripts`) to your User `PATH`:
   - Press <kbd>Win</kbd> + <kbd>R</kbd>, type `sysdm.cpl` and press **Enter**.
   - Navigate to **Advanced** > **Environment Variables**.
   - Under **User variables**, select **Path** > **Edit** > **New**.
   - Paste the path to the `scripts` directory and click **OK**.
   - Reopen your terminal.

### On macOS / Linux:
Ensure the launcher is executable and add it to your shell configuration:
```bash
chmod +x scripts/sentinel

# For Zsh (macOS default):
echo 'export PATH="$PATH:'"$(pwd)"'/scripts"' >> ~/.zshrc
source ~/.zshrc

# For Bash (Linux default):
echo 'export PATH="$PATH:'"$(pwd)"'/scripts"' >> ~/.bashrc
source ~/.bashrc
```

---

## 3. First-Time Project Onboarding & Rules Setup

When you navigate to any Git project and run `sentinel` for the very first time without a local rules file, Sentinel interactively assists you:

```text
============================================================
🛡️  Sentinel-Code: Project Rules Setup
============================================================
No custom rules file found for this project (`rules/security_rules.md`).

Would you like to:
  [1] Set up custom rules for this project (generates `rules/security_rules.md`)
  [2] Use Sentinel's standard security & architecture rules
============================================================
Select an option [1/2] (default: 2): 
```

- **Option [1]:** Generates a starter custom rules template at `rules/security_rules.md` tailored for your repository.
- **Option [2]:** Uses Sentinel's global standard rules without generating a file.
- **Persistent Preference:** Your selection is saved to `.sentinelrc`. **Sentinel will never ask you again** on subsequent runs in this project.
- **CI/CD Safe:** In automated or non-interactive environments (CI runners, pre-commit hooks, pipes), Sentinel automatically defaults to standard rules without blocking.

#### Manual Rules Commands
```bash
# Initialize a custom rules/security_rules.md template at any time
sentinel --init-rules

# Audit against a specific custom rules file
sentinel --rules /path/to/my_rules.md
```

---

## 4. Daily Usage Commands (Auditing Git Projects)

Sentinel-Code audits **staged** changes. Navigate to any Git repository on your system:

### Basic Audit
```bash
# 1. Stage changes in your project
git add <file>       # or git add .

# 2. Run Sentinel-Code
sentinel

# (If scripts/ is not in your PATH, run directly from Sentinel directory):
python -m interfaces.cli
```

---

### Output Formats
```bash
# Terminal human-readable report (default)
sentinel

# Machine-readable JSON output (for scripting / pipelines)
sentinel --format json

# Standard OASIS SARIF v2.1.0 (for GitHub Code Scanning Alerts & GitLab SAST)
sentinel --format sarif
```

---

### CI/CD Gatekeeper Policies (`--fail-on`)

Control what finding severity triggers exit code `1` to block commits or CI pipelines:

```bash
# Fail only on HIGH risk issues (default)
sentinel --fail-on high

# Fail on HIGH or MEDIUM risk issues
sentinel --fail-on medium

# Fail on any security finding (HIGH, MEDIUM, or LOW)
sentinel --fail-on low
sentinel --fail-on any

# Non-blocking / report-only mode (always exits with code 0)
sentinel --fail-on none
```

---

### Partial-Audit Budget Protection (`--fail-on-incomplete`)

If an enormous diff exceeds token budgets and files are skipped, Sentinel protects against blind passes:

```bash
# Enforce failure if any part of the diff was skipped (default behavior)
sentinel --fail-on-incomplete

# Allow partial audits to pass the gate
sentinel --no-fail-on-incomplete
```

---

### Switching LLM Models
```bash
# Audit with Gemini 2.5 Flash (default fast model)
sentinel --model gemini-2.5-flash

# Audit with Gemini 2.5 Pro (advanced reasoning model)
sentinel --model gemini-2.5-pro
```

---

## 5. Setting Up as a Git Pre-Commit Hook

Automatically audit code before every `git commit`.

### Method A: Native Git Hook (Zero extra dependencies)
Copy [scripts/pre-commit-hook.sh](scripts/pre-commit-hook.sh) into your target project:

```bash
# macOS / Linux
cp scripts/pre-commit-hook.sh /path/to/your-project/.git/hooks/pre-commit
chmod +x /path/to/your-project/.git/hooks/pre-commit
```

### Method B: Using the `pre-commit` Framework
Add the hook to your project's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: sentinel-code
        name: Sentinel-Code Security Audit
        entry: sentinel --fail-on high
        language: system
        stages: [pre-commit]
        always_run: true
        pass_filenames: false
```

Install and run across files:
```bash
pre-commit install
pre-commit run sentinel-code --all-files
```

---

## 6. Testing, Benchmarking & QA Commands

Run Sentinel's verification and benchmark suites:

```bash
# 1. Run full unit test suite (filter, redaction, chunking, rules, gatekeeper)
pytest

# 2. Run unit tests with verbose test case output
pytest -v

# 3. Test rules loader and onboarding logic specifically
pytest tests/test_rules_loader.py

# 4. Test filter and secret redaction engines specifically
pytest tests/test_filter.py tests/test_redact.py

# 5. Run live end-to-end integration audit on sample diff
python -m tests.test_brain

# 6. Replay historical commits through the pre-filter (0 tokens, free)
python tests/filter_benchmark_test.py --repo . --n 50

# 7. Run Gold-Standard security benchmark in offline pattern mode (0 tokens)
python tests/gold_standard_benchmark.py --offline

# 8. Run Gold-Standard security benchmark with live Gemini LLM evaluation
python tests/gold_standard_benchmark.py --n 10
```

---

## 7. Quick Reference Summary Table

| Workflow Step | Command |
| :--- | :--- |
| **Clone Repository** | `git clone https://github.com/SHREYASHSINGHAI/Sentinel-Code.git && cd Sentinel-Code` |
| **Virtual Env (Windows)** | `python -m venv .venv` & `.\.venv\Scripts\Activate.ps1` |
| **Virtual Env (macOS/Linux)** | `python3 -m venv .venv && source .venv/bin/activate` |
| **Install Dependencies** | `pip install -r requirements.txt` |
| **Configure Environment** | `copy .env.example .env` *(Win)* or `cp .env.example .env` *(Mac/Linux)* |
| **Stage Changes** | `git add <file>` or `git add .` |
| **Audit Staged Code** | `sentinel` or `python -m interfaces.cli` |
| **Initialize Custom Rules** | `sentinel --init-rules` |
| **Audit with Custom Rules File** | `sentinel --rules /path/to/rules.md` |
| **JSON Output** | `sentinel --format json` |
| **SARIF Output** | `sentinel --format sarif` |
| **Strict Gate (High + Medium)** | `sentinel --fail-on medium` |
| **Non-Blocking Audit** | `sentinel --fail-on none` |
| **Allow Incomplete Audits** | `sentinel --no-fail-on-incomplete` |
| **Run Unit Tests** | `pytest` |
| **Offline Security Benchmark** | `python tests/gold_standard_benchmark.py --offline` |
| **Git Filter Latency Benchmark** | `python tests/filter_benchmark_test.py --repo . --n 50` |
