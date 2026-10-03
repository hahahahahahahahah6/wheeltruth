"""Core checks for wheeltruth: does the built artifact contain what it should?"""

from __future__ import annotations

import ast
import base64
import csv
import hashlib
import io
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile

SEVERITIES = ("info", "warning", "error")

# Top-level sdist dirs that are never shipped inside a wheel.
_NON_PACKAGE_TOPS = {
    "tests", "test", "docs", "doc", "examples", "example",
    ".github", ".git", "tools", "scripts",
}


class Finding:
    def __init__(self, severity, code, message, artifact="", detail=""):
        assert severity in SEVERITIES
        self.severity = severity
        self.code = code
        self.message = message
        self.artifact = artifact
        self.detail = detail

    def __repr__(self):  # pragma: no cover - debugging helper
        return f"Finding({self.severity!r}, {self.code!r}, {self.message!r})"


class ArtifactReport:
    def __init__(self, path, kind):
        self.path = path
        self.kind = kind  # "wheel" | "sdist"
        self.findings = []

    def add(self, severity, code, message, detail=""):
        self.findings.append(
            Finding(severity, code, message, artifact=self.path, detail=detail)
        )

    @property
    def has_issues(self):
        return any(f.severity in ("warning", "error") for f in self.findings)

    @property
    def errors(self):
        return [f for f in self.findings if f.severity == "error"]


def _is_dist_info(path):
    return bool(re.match(r"[^/]+\.dist-info/", path))


def _is_signature_record(path):
    return bool(re.match(r"[^/]+\.dist-info/RECORD(\.jws|\.p7s)?$", path))


def parse_wheel_filename(filename):
    """Return (name, version) from a wheel filename, or (None, None)."""
    base = os.path.basename(filename)
    if not base.endswith(".whl"):
        return None, None
    parts = base[:-4].split("-")
    if len(parts) < 5:
        return None, None
    rest = parts[:-3]  # name, version, [build]
    if len(rest) == 3:
        name, version = rest[0], rest[1]
    elif len(rest) == 2:
        name, version = rest
    else:
        return None, None
    return name, version


def parse_sdist_filename(filename):
    base = os.path.basename(filename)
    for suffix in (".tar.gz", ".tgz", ".zip"):
        if base.endswith(suffix):
            stem = base[: -len(suffix)]
            if "-" in stem:
                name, version = stem.rsplit("-", 1)
                return name, version
    return None, None


def _norm_name(name):
    return re.sub(r"[-_.]+", "-", name or "").lower()


def parse_rfc822_headers(text):
    """Minimal RFC822 header parser -> {key: [values]}. Stops at first blank line."""
    headers = {}
    key = None
    for line in text.splitlines():
        if not line.strip():
            break
        if line[0] in " \t" and key:
            headers[key][-1] += "\n" + line.strip()
        elif ":" in line:
            k, v = line.split(":", 1)
            key = k.strip()
            headers.setdefault(key, []).append(v.strip())
        else:
            key = None
    return headers


def parse_entry_points(text):
    """Parse entry_points.txt -> {group: [(name, value), ...]}."""
    groups = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            groups.setdefault(current, [])
        elif current is not None and "=" in line:
            name, value = line.split("=", 1)
            groups[current].append((name.strip(), value.strip()))
    return groups


class WheelData:
    def __init__(self, path):
        self.path = path
        self.files = []
        self.record = {}  # path -> (hash, size)
        self.metadata = {}
        self.entry_points = {}
        self.dist_info = ""
        self.filename_name, self.filename_version = parse_wheel_filename(path)


def read_wheel(path):
    wheel = WheelData(path)
    with zipfile.ZipFile(path) as zf:
        wheel.files = [n for n in zf.namelist() if not n.endswith("/")]
        dist_infos = {n.split("/")[0] for n in wheel.files if _is_dist_info(n)}
        # A wheel may contain vendored distributions, including their dist-info
        # directories.  Select this wheel's metadata directory rather than the
        # first one alphabetically; in particular, never merge vendored RECORDs.
        for dist_info in sorted(dist_infos):
            metadata_path = f"{dist_info}/METADATA"
            if metadata_path not in wheel.files:
                continue
            headers = parse_rfc822_headers(
                zf.read(metadata_path).decode("utf-8", "replace")
            )
            metadata_name, _ = _meta_name_version(headers)
            if _norm_name(metadata_name) == _norm_name(wheel.filename_name):
                wheel.dist_info = dist_info
                break
        # Preserve useful mismatch diagnostics for malformed wheels that have
        # exactly one plausible metadata directory.
        if not wheel.dist_info and len(dist_infos) == 1:
            wheel.dist_info = next(iter(dist_infos))
        for name in wheel.files:
            if name == f"{wheel.dist_info}/METADATA" and wheel.dist_info:
                wheel.metadata = parse_rfc822_headers(
                    zf.read(name).decode("utf-8", "replace")
                )
            elif name == f"{wheel.dist_info}/entry_points.txt" and wheel.dist_info:
                wheel.entry_points = parse_entry_points(
                    zf.read(name).decode("utf-8", "replace")
                )
            elif name == f"{wheel.dist_info}/RECORD" and wheel.dist_info:
                text = zf.read(name).decode("utf-8", "replace")
                for row in csv.reader(io.StringIO(text)):
                    if len(row) >= 1 and row[0]:
                        wheel.record[row[0]] = (
                            row[1] if len(row) > 1 else "",
                            row[2] if len(row) > 2 else "",
                        )
    return wheel


class SdistData:
    def __init__(self, path):
        self.path = path
        self.files = []
        self.pkg_info = {}
        self.filename_name, self.filename_version = parse_sdist_filename(path)


def read_sdist(path):
    sdist = SdistData(path)
    base = os.path.basename(path)
    if base.endswith(".zip"):
        with zipfile.ZipFile(path) as zf:
            sdist.files = [n for n in zf.namelist() if not n.endswith("/")]
            for n in sdist.files:
                if n.count("/") == 1 and n.endswith("PKG-INFO"):
                    sdist.pkg_info = parse_rfc822_headers(
                        zf.read(n).decode("utf-8", "replace")
                    )
    else:
        with tarfile.open(path, "r:*") as tf:
            for member in tf.getmembers():
                if member.isfile():
                    sdist.files.append(member.name)
            for n in sdist.files:
                if n.count("/") == 1 and n.endswith("PKG-INFO"):
                    f = tf.extractfile(n)
                    if f:
                        sdist.pkg_info = parse_rfc822_headers(
                            f.read().decode("utf-8", "replace")
                        )
    return sdist


def _meta_name_version(headers):
    name = (headers.get("Name") or [""])[0]
    version = (headers.get("Version") or [""])[0]
    return name, version


# ---------------------------------------------------------------- checks


def check_metadata_consistency(kind, headers, filename_name, filename_version, rep):
    name, version = _meta_name_version(headers)
    if not name:
        rep.add("error", "metadata-no-name", "METADATA/PKG-INFO has no Name field")
    if not version:
        rep.add("error", "metadata-no-version", "METADATA/PKG-INFO has no Version field")
    if filename_name and name and _norm_name(filename_name) != _norm_name(name):
        rep.add(
            "error",
            "metadata-name-mismatch",
            f"filename implies name {filename_name!r} but metadata says {name!r}",
        )
    if filename_version and version and filename_version != version:
        rep.add(
            "warning",
            "metadata-version-mismatch",
            f"filename implies version {filename_version!r} but metadata says {version!r}",
        )


def _b64_nopad(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def check_record(wheel, rep):
    """Every file in the zip must be listed in RECORD with a valid hash/size."""
    try:
        zf = zipfile.ZipFile(wheel.path)
    except zipfile.BadZipFile:
        rep.add("error", "bad-wheel", f"{wheel.path} is not a valid zip file")
        return
    with zf:
        if not wheel.record:
            rep.add("error", "record-missing", "wheel has no .dist-info/RECORD")
            return
        zfiles = set(wheel.files)
        for f in sorted(zfiles):
            if _is_signature_record(f):
                continue
            if f not in wheel.record:
                rep.add(
                    "error",
                    "record-entry-missing",
                    f"file {f} is in the wheel but not listed in RECORD",
                )
        for f in sorted(wheel.record):
            digest, size = wheel.record[f]
            if f not in zfiles:
                rep.add(
                    "error",
                    "record-dangling",
                    f"RECORD lists {f} but it is missing from the wheel",
                )
                continue
            if digest:
                algo, _, expected = digest.partition("=")
                if algo.lower() == "sha256":
                    try:
                        actual = _b64_nopad(hashlib.sha256(zf.read(f)).digest())
                    except KeyError:
                        continue
                    if actual != expected:
                        rep.add(
                            "error",
                            "record-hash-mismatch",
                            f"RECORD hash mismatch for {f} (file changed after RECORD was written)",
                        )
            if size and size.isdigit():
                try:
                    actual_size = zf.getinfo(f).file_size
                except KeyError:
                    continue
                if int(size) != actual_size:
                    rep.add(
                        "error",
                        "record-size-mismatch",
                        f"RECORD size mismatch for {f}: listed {size}, actual {actual_size}",
                    )


def _module_path(module, files):
    """Return the source path for *module*, if it is present in the wheel."""
    if not module or not re.match(r"^[A-Za-z_][\w.]*$", module):
        return None
    rel = module.replace(".", "/")
    for candidate in (rel + ".py", rel + "/__init__.py"):
        if candidate in files:
            return candidate
    return None


def _init_exports(path, attribute, zf):
    """Check an __init__.py for a locally defined or imported attribute."""
    if not path.endswith("/__init__.py"):
        return False
    try:
        tree = ast.parse(zf.read(path).decode("utf-8", "replace"))
    except (KeyError, SyntaxError, ValueError):
        return False
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == attribute:
                return True
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if (alias.asname or alias.name.rsplit(".", 1)[-1]) == attribute:
                    return True
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == attribute
                   for target in targets):
                return True
    return False


def _entry_point_target_path(value, files, zf):
    """Resolve 'module:attr [extras]' to a path inside the wheel, or None."""
    target = value.split()[0]  # strip "[extra]" markers
    # Custom entry-point groups sometimes identify a shipped data file rather
    # than an importable Python object (NumPy's pkg-config entry is one).
    if target in files:
        return target
    module, separator, attribute = target.partition(":")
    path = _module_path(module.strip(), files)
    if path:
        return path
    # Some consumers use ``package.ExportedName`` rather than a colon.  Accept
    # it only when the package initializer actually exposes that name.
    if not separator and "." in module:
        package, attribute = module.rsplit(".", 1)
        path = _module_path(package, files)
        if path and _init_exports(path, attribute, zf):
            return path
    return None


def check_entry_points(wheel, rep):
    files = set(wheel.files)
    with zipfile.ZipFile(wheel.path) as zf:
        for group in sorted(wheel.entry_points):
            for name, value in wheel.entry_points[group]:
                if _entry_point_target_path(value, files, zf) is None:
                    rep.add(
                        "error",
                        "entry-point-dangling",
                        f"[{group}] {name} = {value}: target not found in wheel",
                    )


def _top_package_dirs(files):
    """Collect Python sources, stubs, and extension modules by package."""
    pkgs = {}
    for f in files:
        if _is_dist_info(f) or "/" not in f:
            continue
        top = f.split("/")[0]
        if top in _NON_PACKAGE_TOPS or top.endswith(".data"):
            continue
        entry = pkgs.setdefault(
            top, {"py": set(), "pyi": set(), "extensions": set(), "py_typed": False}
        )
        base = f.rsplit("/", 1)[-1]
        if f.endswith("/py.typed") or base == "py.typed":
            entry["py_typed"] = True
        elif f.endswith(".py"):
            entry["py"].add(f[: -len(".py")])
        elif f.endswith(".pyi"):
            entry["pyi"].add(f[: -len(".pyi")])
        elif f.endswith((".so", ".pyd", ".dylib")):
            # Strip both the library suffix and an optional ABI/platform tag.
            directory, _, filename = f.rpartition("/")
            module = filename.split(".", 1)[0]
            entry["extensions"].add(f"{directory}/{module}" if directory else module)
    return pkgs


def check_typing(wheel, rep):
    """Warn only when a typed compiled module has neither source nor a stub."""
    pkgs = _top_package_dirs(wheel.files)
    for pkg in sorted(pkgs):
        entry = pkgs[pkg]
        if entry["py_typed"]:
            rep.add(
                "info",
                "typing-py-typed",
                f"package {pkg}/ ships py.typed (typed package marker)",
            )
        if entry["py_typed"] or entry["pyi"]:
            missing = sorted(
                s for s in entry["extensions"]
                if s not in entry["py"] and s not in entry["pyi"]
            )
            for stem in missing:
                rep.add(
                    "warning",
                    "typing-stub-missing",
                    f"compiled extension {stem} has neither inline source nor a .pyi stub "
                    f"(downstream type checkers have no type information)",
                    detail=stem,
                )
            for stem in sorted(entry["pyi"] - entry["py"] - entry["extensions"]):
                # A stub for a C extension (stem.so) or namespace edge is fine;
                # only flag when neither .py nor a sibling module exists.
                rep.add(
                    "info",
                    "typing-stub-orphan",
                    f"{stem}.pyi has no sibling {stem}.py in the wheel",
                    detail=f"{stem}.pyi",
                )


def check_wheel_contents(wheel, rep):
    py_files = [
        f
        for f in wheel.files
        if f.endswith(".py") and not _is_dist_info(f) and "__pycache__" not in f
    ]
    if not py_files:
        rep.add(
            "warning", "wheel-no-python", "wheel contains no .py files at all"
        )
    check_metadata_consistency(
        "wheel", wheel.metadata, wheel.filename_name, wheel.filename_version, rep
    )
    check_record(wheel, rep)
    check_entry_points(wheel, rep)
    check_typing(wheel, rep)


def check_sdist_contents(sdist, rep):
    if not sdist.pkg_info:
        rep.add("error", "sdist-no-pkg-info", "sdist has no PKG-INFO")
    else:
        check_metadata_consistency(
            "sdist",
            sdist.pkg_info,
            sdist.filename_name,
            sdist.filename_version,
            rep,
        )
    py_files = [f for f in sdist.files if f.endswith(".py")]
    if not py_files:
        rep.add("warning", "sdist-no-python", "sdist contains no .py files at all")


def _normalize_sdist_path(path):
    """Strip '<name>-<version>/' and an optional 'src/' prefix."""
    parts = path.split("/")
    if len(parts) < 2:
        return None
    rest = parts[1:]
    if rest and rest[0] == "src":
        rest = rest[1:]
    return "/".join(rest) if rest else None


def check_wheel_vs_sdist(wheel, sdist, rep):
    """Files tracked in the sdist's packages should survive into the wheel."""
    wfiles = {
        f
        for f in wheel.files
        if not _is_dist_info(f)
        and not f.endswith("/")
        and "__pycache__" not in f
    }
    # Group sdist files by top-level entry (after normalization).
    s_groups = {}
    for f in sdist.files:
        n = _normalize_sdist_path(f)
        if not n or n.endswith("/"):
            continue
        top = n.split("/")[0]
        # Only compare things that look like shippable packages/modules.
        s_groups.setdefault(top, []).append(n)

    w_groups = {}
    for f in wfiles:
        top = f.split("/")[0]
        w_groups.setdefault(top, []).append(f)

    for top in sorted(s_groups):
        if top in _NON_PACKAGE_TOPS:
            continue
        s_here = s_groups[top]
        # Skip top-level non-package files (setup.py, README, ...) and dirs
        # with no Python files at all.
        if "/" not in s_here[0] and not s_here[0].endswith(".py"):
            continue
        if not any(p.endswith(".py") for p in s_here):
            continue
        s_rel = {p[len(top) + 1 :] for p in s_here}
        w_rel = {p[len(top) + 1 :] for p in w_groups.get(top, []) if "/" in p}
        # Also cover top-level modules (top.py in wheel vs top/<file> mismatch):
        for missing in sorted(s_rel - w_rel):
            # .pyi presence differences are covered by check_typing; still
            # worth flagging here since sdist->wheel drops are the core story.
            rep.add(
                "warning",
                "sdist-file-missing-in-wheel",
                f"{top}/{missing} is in the sdist but missing from the wheel",
                detail=f"{top}/{missing}",
            )
        for extra in sorted(w_rel - s_rel):
            rep.add(
                "info",
                "wheel-file-not-in-sdist",
                f"{top}/{extra} is in the wheel but not in the sdist",
                detail=f"{top}/{extra}",
            )
    # Top-level modules (foo.py) that exist in sdist but not wheel.
    s_toplevel_py = {
        n for n in (_normalize_sdist_path(f) for f in sdist.files) if n and "/" not in n and n.endswith(".py")
    }
    w_toplevel_py = {f for f in wfiles if "/" not in f and f.endswith(".py")}
    for missing in sorted(s_toplevel_py - w_toplevel_py):
        rep.add(
            "warning",
            "sdist-file-missing-in-wheel",
            f"{missing} is in the sdist but missing from the wheel",
            detail=missing,
        )

# ------------------------------------------------- --project heuristics


def _read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def expected_packages_from_project(projdir):
    """Best-effort (name, [top-level packages]) from project config files.

    Returns (name_or_None, packages_or_None). Parses pyproject.toml,
    setup.cfg and setup.py with small targeted parsers (no external deps).
    """
    name = None
    packages = None

    pyproject = _read_text(os.path.join(projdir, "pyproject.toml"))
    if pyproject:
        # [project] name
        m = re.search(
            r"(?ms)^\[project\].*?^\s*name\s*=\s*[\"']([^\"']+)[\"']", pyproject
        )
        if m:
            name = m.group(1)
        # [tool.setuptools.packages.find] namespaces / include
        m = re.search(
            r"(?ms)^\[tool\.setuptools\.packages\.find\].*?^\s*namespaces\s*=\s*(true|false)",
            pyproject,
        )
        # explicit [tool.setuptools] packages = [...]
        m2 = re.search(
            r"(?ms)^\[tool\.setuptools\].*?^\s*packages\s*=\s*\[([^\]]*)\]",
            pyproject,
        )
        if m2:
            packages = re.findall(r"[\"']([\w.]+)[\"']", m2.group(1))

    setup_cfg = _read_text(os.path.join(projdir, "setup.cfg"))
    if setup_cfg:
        m = re.search(r"(?m)^\[metadata\].*?^name\s*=\s*(.+)$", setup_cfg)
        if m and not name:
            name = m.group(1).strip()
        m = re.search(r"(?m)^\[options\].*?^packages\s*=\s*(.+)$", setup_cfg)
        if m and packages is None:
            first = m.group(1).strip()
            if first == "find:":
                packages = None  # auto-discovery; handled below
            else:
                # multi-line list under [options]
                block = re.search(
                    r"(?m)^\[options\].*?^packages\s*=\s*\n((?:[ \t]+\S.*\n?)+)",
                    setup_cfg,
                )
                if block:
                    packages = [
                        ln.strip()
                        for ln in block.group(1).splitlines()
                        if ln.strip()
                    ]
                else:
                    packages = [p.strip() for p in first.split(",") if p.strip()]

    setup_py = _read_text(os.path.join(projdir, "setup.py"))
    if setup_py:
        if not name:
            m = re.search(r"name\s*=\s*[\"']([^\"']+)[\"']", setup_py)
            if m:
                name = m.group(1)
        if packages is None:
            m = re.search(r"packages\s*=\s*\[([^\]]*)\]", setup_py)
            if m:
                packages = re.findall(r"[\"']([\w.]+)[\"']", m.group(1))

    if packages is None:
        # Auto-discovery fallback: top-level dirs with __init__.py (+ src/ layout).
        found = []
        for base in ("", "src"):
            d = os.path.join(projdir, base) if base else projdir
            try:
                entries = os.listdir(d)
            except OSError:
                continue
            for entry in entries:
                full = os.path.join(d, entry)
                if os.path.isdir(full) and os.path.isfile(
                    os.path.join(full, "__init__.py")
                ):
                    found.append(entry)
        packages = sorted(set(found)) or None

    # Normalize dotted names to top-level dirs.
    if packages:
        tops = sorted({p.split(".")[0] for p in packages})
    else:
        tops = None
    return name, tops


def check_project_against_wheel(wheel, projdir, rep):
    name, tops = expected_packages_from_project(projdir)
    if name and wheel.filename_name and _norm_name(name) != _norm_name(
        wheel.filename_name
    ):
        rep.add(
            "warning",
            "project-name-mismatch",
            f"project config names the distribution {name!r} "
            f"but the wheel file says {wheel.filename_name!r}",
        )
    if not tops:
        rep.add(
            "info",
            "project-no-packages",
            "could not determine expected packages from project config",
        )
        return
    wheel_tops = {f.split("/")[0] for f in wheel.files if "/" in f}
    wheel_toplevel_py = {
        f[:-3] for f in wheel.files if "/" not in f and f.endswith(".py")
    }
    for top in tops:
        if top not in wheel_tops and top not in wheel_toplevel_py:
            rep.add(
                "error",
                "project-package-missing",
                f"package {top!r} is configured in the project but missing from the wheel",
            )


# ------------------------------------------------------------------ smoke


def _top_level_modules(wheel):
    mods = set()
    for f in wheel.files:
        if _is_dist_info(f) or "__pycache__" in f:
            continue
        if "/" not in f and f.endswith(".py"):
            mods.add(f[:-3])
        elif f.endswith("/__init__.py"):
            mods.add(f.split("/")[0])
    return sorted(m for m in mods if m.isidentifier())[:25]


def smoke_test_wheel(wheel, rep, timeout=180):
    """Install the wheel into a throwaway venv and import top-level modules."""
    mods = _top_level_modules(wheel)
    if not mods:
        rep.add("info", "smoke-no-modules", "smoke test skipped: no importable modules found")
        return
    tmp = tempfile.mkdtemp(prefix="wheeltruth-smoke-")
    venv_dir = os.path.join(tmp, "venv")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "venv", venv_dir],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        rep.add("info", "smoke-unavailable", f"smoke test unavailable: {exc}")
        return
    if proc.returncode != 0:
        rep.add("info", "smoke-unavailable", "smoke test unavailable: venv creation failed")
        return
    bindir = os.path.join(venv_dir, "Scripts" if os.name == "nt" else "bin")
    pip = os.path.join(bindir, "pip")
    vpy = os.path.join(bindir, "python")
    try:
        proc = subprocess.run(
            [pip, "install", "--no-deps", "--no-index", "--quiet", wheel.path],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        rep.add("warning", "smoke-install-failed", f"smoke test: pip install failed: {exc}")
        return
    if proc.returncode != 0:
        rep.add(
            "error", "smoke-install-failed",
            "smoke test: pip install of the wheel failed",
            detail=proc.stderr[-2000:],
        )
        return
    failed = []
    for mod in mods:
        try:
            proc = subprocess.run(
                [vpy, "-c", f"import {mod}"],
                capture_output=True, text=True, timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            failed.append((mod, "timeout"))
            continue
        if proc.returncode != 0:
            failed.append((mod, proc.stderr.strip().splitlines()[-1][:200] if proc.stderr.strip() else "import failed"))
    for mod, err in failed:
        rep.add("error", "smoke-import-failed", f"smoke test: import {mod} failed: {err}")
    if not failed:
        rep.add("info", "smoke-ok", f"smoke test: {len(mods)} top-level module(s) imported cleanly")


# ----------------------------------------------------------------- reports


def render_text(reports):
    lines = []
    for rep in reports:
        lines.append(f"== {rep.path} ({rep.kind}) ==")
        if not rep.findings:
            lines.append("  OK: no issues found")
        for f in rep.findings:
            lines.append(f"  [{f.severity.upper():7}] {f.code}: {f.message}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(reports):
    lines = ["# wheeltruth report", ""]
    for rep in reports:
        lines.append(f"## `{os.path.basename(rep.path)}` ({rep.kind})")
        lines.append("")
        if not rep.findings:
            lines.append("OK: no issues found")
        else:
            lines.append("| severity | code | message |")
            lines.append("|---|---|---|")
            for f in rep.findings:
                msg = f.message.replace("|", "\\|")
                lines.append(f"| {f.severity} | `{f.code}` | {msg} |")
        lines.append("")
    return "\n".join(lines)


def check_artifacts(paths, project=None, smoke=False):
    """Run all checks over the given artifact paths. Returns [ArtifactReport]."""
    reports = []
    wheels = []
    sdists = []
    for path in paths:
        base = os.path.basename(path)
        rep = None
        try:
            if base.endswith(".whl"):
                rep = ArtifactReport(path, "wheel")
                wheel = read_wheel(path)
                wheels.append((wheel, rep))
                check_wheel_contents(wheel, rep)
                if project:
                    check_project_against_wheel(wheel, project, rep)
                if smoke:
                    smoke_test_wheel(wheel, rep)
            elif base.endswith((".tar.gz", ".tgz", ".zip")):
                rep = ArtifactReport(path, "sdist")
                sdist = read_sdist(path)
                sdists.append((sdist, rep))
                check_sdist_contents(sdist, rep)
            else:
                rep = ArtifactReport(path, "unknown")
                rep.add("error", "unknown-artifact",
                        f"don't know how to check {base!r}: expected .whl or .tar.gz")
        except (zipfile.BadZipFile, tarfile.TarError, OSError) as exc:
            if rep is None:
                rep = ArtifactReport(path, "unknown")
            rep.add("error", "unreadable-artifact", f"could not read {base}: {exc}")
        reports.append(rep)

    # Cross-artifact comparison when we have both kinds.
    if wheels and sdists:
        # Pair each wheel with the sdist of the same distribution when possible.
        for wheel, wrep in wheels:
            wn = _norm_name(wheel.filename_name or (wheel.metadata.get("Name") or [""])[0])
            partner = None
            for sdist, _srep in sdists:
                sn = _norm_name(sdist.filename_name or (sdist.pkg_info.get("Name") or [""])[0])
                if wn and sn and wn == sn:
                    partner = sdist
                    break
            if partner is None:
                partner = sdists[0][0]
            cross = ArtifactReport(f"{wheel.path} vs {partner.path}", "wheel-vs-sdist")
            check_wheel_vs_sdist(wheel, partner, cross)
            # Merge cross findings into the wheel's report for simpler output.
            wrep.findings.extend(cross.findings)

    return reports
