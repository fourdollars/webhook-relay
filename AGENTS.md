<!-- OPENSPEC:START -->
# OpenSpec Instructions

These instructions are for AI assistants working in this project.

Always open `@/openspec/AGENTS.md` when the request:
- Mentions planning or proposals (words like proposal, spec, change, plan)
- Introduces new capabilities, breaking changes, architecture shifts, or big performance/security work
- Sounds ambiguous and you need the authoritative spec before coding

Use `@/openspec/AGENTS.md` to learn:
- How to create and apply change proposals
- Spec format and conventions
- Project structure and guidelines

Keep this managed block so 'openspec update' can refresh the instructions.

<!-- OPENSPEC:END -->

## Python Tooling

This project uses **uv** for Python package management and task execution.

### Why uv?

- **Fast**: 10-100x faster than pip
- **Reliable**: Uses a lockfile for reproducible installs
- **Modern**: Built in Rust with better dependency resolution
- **Simple**: Single tool for virtual environments, package management, and running scripts

### Common Commands

```bash
# Install dependencies
uv pip install -r requirements.txt

# Run tests
uv run pytest tests/

# Run linting tools
uv run flake8 src/ tests/ --max-line-length=100 --ignore=E203,W503
uv run black --check src/ tests/
uv run isort --check-only src/ tests/

# Run with coverage
uv run coverage run -m pytest tests/
uv run coverage report -m
```

### Installing uv

```bash
# Linux/macOS
curl -LsSf https://astral.sh/uv/install.sh | sh

# Or via pip
pip install uv
```

### CI/CD Integration

GitHub Actions workflows use `astral-sh/setup-uv` for consistent uv setup:

```yaml
- name: Set up uv
  uses: astral-sh/setup-uv@v5
  with:
    enable-cache: true

- name: Install dependencies
  run: uv pip install -r requirements.txt

- name: Run tests
  run: uv run pytest tests/
```

### Key Differences from pip

| Task | pip | uv |
|------|-----|-----|
| Install deps | `pip install -r requirements.txt` | `uv pip install -r requirements.txt` |
| Run command | `python -m pytest` | `uv run pytest` |
| Upgrade package | `pip install --upgrade pkg` | `uv pip install --upgrade pkg` |
| Create venv | `python -m venv .venv` | `uv venv` |

**Note**: `uv run` automatically manages the virtual environment, so you don't need to manually activate it.
