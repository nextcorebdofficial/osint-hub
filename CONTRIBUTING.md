# Contributing

Thanks for wanting to help. This project is small on purpose, so it is easy to understand and change.

## Ground rules

- Read [docs/ETHICS_AND_LEGAL.md](docs/ETHICS_AND_LEGAL.md). Contributions that add facial-recognition identification, personal-data scraping, or anything aimed at targeting private individuals will not be accepted.
- Be kind and constructive in issues and pull requests.
- By contributing you agree your work is released under the project's [MIT License](LICENSE).

## Set up

```bash
git clone https://github.com/nextcorebdofficial/osint-hub.git
cd osint-hub
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt pytest
python -m uvicorn main:app --reload
```

## Run the tests

```bash
python -m pytest -q test_app.py
```

Tests are offline: they must not call external services, so they run anywhere and never flake. Test parsing and validation, not live websites.

## Good first contributions

- A new lookup (see "Adding a new lookup" in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md))
- A new encoder, decoder or dork template in `extras.py`
- Translations: the `I18N` object near the top of the script in `templates/index.html`
- Better error messages, accessibility fixes, mobile layout fixes
- Items from the roadmap in the README

## Pull request checklist

- [ ] One focused change per pull request
- [ ] Tests added or updated, and `python -m pytest -q test_app.py` passes
- [ ] No secrets, API keys or personal data in the code, tests or screenshots
- [ ] README or docs updated if behaviour changed
- [ ] New external services named in `NOTICE` and the README credits

## Style

Match the surrounding code: type hints where the file already uses them, short functions, comments only for the non-obvious "why". Keep the UI dependency-free (no front-end build step).

## Reporting bugs

Open an issue with what you did, what you expected, what happened, and your Python version and OS. For security problems, do **not** open a public issue; see [SECURITY.md](SECURITY.md).
