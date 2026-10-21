import sys
from pathlib import Path

# Make the project root importable so `pytest tests/...` works without `python -m`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
