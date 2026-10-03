# wheeltruth

**Your tests passed. Your published wheel is missing files.**

`wheeltruth` checks that your built wheel/sdist actually contains everything the
package needs — before your users find out the hard way.

## The problem

`twine check` verifies your README renders. Nothing in the standard toolchain
verifies that the *files* made it into the artifact. Two real cases from 2026:

- **MLX v0.32.0** (2026-07-25): the macOS ARM64 wheel shipped `py.typed` but
  silently dropped every `.pyi` stub the previous release had. Downstream type
  checking broke, and the test suite never noticed — because tests run against
  the source tree, not the wheel.
- **OpenSpace** (2026-06-14): a tracked `host_skills/` directory vanished from
  the built distribution, breaking integrations for everyone who installed it.

Build backends, MANIFEST.in glitches, and `package-data` misconfigurations drop
files quietly. `wheeltruth` inspects the artifact itself — the thing PyPI
actually serves — not your repo.

## Install

```bash
pip install wheeltruth
```

## Usage

```bash
# Check one or more built artifacts
wheeltruth check dist/*

# Compare a wheel against its sdist (catches files dropped between the two)
wheeltruth check dist/mypkg-1.0-py3-none-any.whl dist/mypkg-1.0.tar.gz

# Also verify expected packages from the project config
wheeltruth check dist/* --project .

# Install into a throwaway venv and import every top-level module
wheeltruth check dist/*.whl --smoke

# Machine-readable report for CI logs / PR comments
wheeltruth check dist/* --report md
```

Exit code is `0` when clean, `1` when issues are found — drop it straight into CI:

```yaml
- name: Build
  run: python -m build
- name: Verify artifacts
  run: |
    pip install wheeltruth
    wheeltruth check dist/*
```

## What it checks

**Wheel only**
- `RECORD` completeness: every file in the zip is listed, every listed file
  exists, and sha256 hashes/sizes match (tampered or hand-edited wheels fail).
- `entry_points.txt`: every `console_scripts`/`gui_scripts` target resolves to
  a module actually inside the wheel (no more `ModuleNotFoundError` on first run).
- Typing stub consistency: if a package ships *some* `.pyi` stubs, every
  module should have one — a half-dropped stub set (the MLX case) is flagged.
- `METADATA` name/version consistency with the wheel filename.

**Wheel vs sdist**
- Files tracked in the sdist's packages that never made it into the wheel
  (the OpenSpace case), and vice versa. Handles `src/` layouts and ignores
  `tests/`, `docs/`, etc.

**With `--project .`**
- Packages declared in `pyproject.toml` / `setup.cfg` / `setup.py` (or
  auto-discovered) actually exist in the wheel.

**With `--smoke`**
- Installs the wheel into a throwaway venv (`--no-deps --no-index`) and
  imports every top-level module.

## Limitations (v0.1)

- v0.1 is **check-only**: it reports problems, it doesn't fix your build config.
- Heuristics, not proof: "expected files" are inferred from the sdist or
  project config. Exotic layouts may produce false positives — file an issue.
- `--smoke` needs a working `venv` + `pip` and takes a few seconds per wheel.
- Stub checks are consistency checks; they can't know what the *previous*
  release shipped.

## License

MIT
