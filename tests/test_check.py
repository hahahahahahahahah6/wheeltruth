"""Tests for wheeltruth. Fake wheels/sdists are built in-test with zipfile/tarfile."""

import base64
import hashlib
import io
import os
import tarfile
import zipfile

import pytest

from wheeltruth import check as C
from wheeltruth.cli import main as cli_main


# ------------------------------------------------------------ fixtures


def _b64(data):
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def b(s):
    return s.encode("utf-8") if isinstance(s, str) else s


def dist_info_files(name="demo", version="0.1.0", entry_points=None):
    di = f"{name}-{version}.dist-info"
    files = {
        f"{di}/METADATA": b(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"),
        f"{di}/WHEEL": b(
            "Wheel-Version: 1.0\nGenerator: wheeltruth-tests\n"
            "Root-Is-Purelib: true\nTag: py3-none-any\n"
        ),
    }
    if entry_points:
        files[f"{di}/entry_points.txt"] = b(entry_points)
    return files


def record_text(files, dist_info):
    rows = []
    for f in sorted(files):
        data = files[f]
        rows.append(f"{f},sha256={_b64(data)},{len(data)}")
    rows.append(f"{dist_info}/RECORD,,")
    return ("\n".join(rows) + "\n").encode()


def write_wheel(path, files, name="demo", version="0.1.0",
                entry_points=None, include_record=True, record_text_override=None):
    """files: {arcname: bytes} for package content (dist-info added automatically)."""
    di = f"{name}-{version}.dist-info"
    all_files = dict(dist_info_files(name, version, entry_points))
    all_files.update({k: b(v) for k, v in files.items()})
    if include_record:
        all_files[f"{di}/RECORD"] = record_text_override or record_text(all_files, di)
    with zipfile.ZipFile(path, "w") as zf:
        for arc, content in all_files.items():
            zf.writestr(arc, content)
    return str(path)


def write_sdist(path, topdir, files):
    """files: {relpath: bytes} placed under topdir/."""
    with tarfile.open(path, "w:gz") as tf:
        for rel, content in files.items():
            data = b(content)
            ti = tarfile.TarInfo(f"{topdir}/{rel}")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return str(path)


def pkg_info_text(name="demo", version="0.1.0"):
    return b(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n")


def codes(rep):
    return {(f.severity, f.code) for f in rep.findings}


# ------------------------------------------------------------------ wheel


def test_clean_wheel_no_findings(tmp_path):
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl", {
        "demo/__init__.py": b"x = 1\n",
        "demo/mod.py": b"y = 2\n",
    })
    (rep,) = C.check_artifacts([whl])
    assert rep.kind == "wheel"
    assert not rep.has_issues, [f.message for f in rep.findings]


def test_record_hash_mismatch(tmp_path):
    files = {"demo/__init__.py": b"x = 1\n"}
    di = "demo-0.1.0.dist-info"
    di_files = dist_info_files()
    di_files.update({k: b(v) for k, v in files.items()})
    rec = record_text(di_files, di)  # RECORD claims the ORIGINAL content
    tampered = dict(di_files)
    tampered["demo/__init__.py"] = b"TAMPERED\n"
    tampered[f"{di}/RECORD"] = rec
    whl = tmp_path / "demo-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(str(whl), "w") as zf:
        for arc, content in tampered.items():
            zf.writestr(arc, content)
    (rep,) = C.check_artifacts([str(whl)])
    assert ("error", "record-hash-mismatch") in codes(rep)


def test_record_size_mismatch(tmp_path):
    files = {"demo/__init__.py": b"x = 1\n"}  # 6 bytes
    di = "demo-0.1.0.dist-info"
    di_files = dist_info_files()
    di_files.update({k: b(v) for k, v in files.items()})
    lines = []
    for line in record_text(di_files, di).decode().splitlines():
        if line.startswith("demo/__init__.py,"):
            parts = line.split(",")
            parts[2] = "999"  # lie about the size
            line = ",".join(parts)
        lines.append(line)
    rec = ("\n".join(lines) + "\n").encode()
    payload = dict(di_files)
    payload[f"{di}/RECORD"] = rec
    whl = tmp_path / "demo-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(str(whl), "w") as zf:
        for arc, content in payload.items():
            zf.writestr(arc, content)
    (rep,) = C.check_artifacts([str(whl)])
    assert ("error", "record-size-mismatch") in codes(rep)


def test_file_missing_from_record(tmp_path):
    files = {"demo/__init__.py": b"x = 1\n"}
    di_files = dist_info_files()
    rec = record_text(di_files, "demo-0.1.0.dist-info")  # no package files listed
    whl = tmp_path / "demo-0.1.0-py3-none-any.whl"
    payload = dict(di_files)
    payload.update({k: b(v) for k, v in files.items()})
    payload["demo-0.1.0.dist-info/RECORD"] = rec
    with zipfile.ZipFile(str(whl), "w") as zf:
        for arc, content in payload.items():
            zf.writestr(arc, content)
    (rep,) = C.check_artifacts([str(whl)])
    assert ("error", "record-entry-missing") in codes(rep)


def test_record_lists_missing_file(tmp_path):
    files = {"demo/__init__.py": b"x = 1\n"}
    di = "demo-0.1.0.dist-info"
    di_files = dist_info_files()
    di_files.update({k: b(v) for k, v in files.items()})
    rows = [f"demo/ghost.py,sha256={_b64(b'x')},1"]
    for f in sorted(di_files):
        rows.append(f"{f},sha256={_b64(di_files[f])},{len(di_files[f])}")
    rows.append(f"{di}/RECORD,,")
    rec = ("\n".join(rows) + "\n").encode()
    whl = tmp_path / "demo-0.1.0-py3-none-any.whl"
    payload = dict(di_files)
    payload[f"{di}/RECORD"] = rec
    with zipfile.ZipFile(str(whl), "w") as zf:
        for arc, content in payload.items():
            zf.writestr(arc, content)
    (rep,) = C.check_artifacts([str(whl)])
    assert ("error", "record-dangling") in codes(rep)


def test_vendored_dist_info_record_is_not_merged(tmp_path):
    files = dist_info_files()
    files.update({
        "demo/__init__.py": b"",
        "demo/_vendor/dependency-2.0.dist-info/METADATA":
            b"Name: dependency\nVersion: 2.0\n",
        "demo/_vendor/dependency-2.0.dist-info/RECORD":
            b"dependency/__init__.py,,\n",
    })
    files["demo-0.1.0.dist-info/RECORD"] = record_text(
        files, "demo-0.1.0.dist-info"
    )
    whl = tmp_path / "demo-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(whl, "w") as zf:
        for arc, content in files.items():
            zf.writestr(arc, content)

    wheel = C.read_wheel(str(whl))
    (rep,) = C.check_artifacts([str(whl)])
    assert wheel.dist_info == "demo-0.1.0.dist-info"
    assert "dependency/__init__.py" not in wheel.record
    assert not [f for f in rep.findings if f.code == "record-dangling"]


def test_wheel_without_record(tmp_path):
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl",
                      {"demo/__init__.py": b"x=1\n"}, include_record=False)
    (rep,) = C.check_artifacts([whl])
    assert ("error", "record-missing") in codes(rep)


def test_entry_point_ok(tmp_path):
    ep = "[console_scripts]\ndemo-cli = demo.mod:main\n"
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl", {
        "demo/__init__.py": b"",
        "demo/mod.py": b"def main(): pass\n",
    }, entry_points=ep)
    (rep,) = C.check_artifacts([whl])
    assert not rep.has_issues


def test_entry_point_dangling(tmp_path):
    ep = "[console_scripts]\ndemo-cli = demo.missing:main\n[gui_scripts]\ndemo-gui = demo_missing:gone\n"
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl",
                      {"demo/__init__.py": b""}, entry_points=ep)
    (rep,) = C.check_artifacts([whl])
    dangling = [f for f in rep.findings if f.code == "entry-point-dangling"]
    assert len(dangling) == 2
    assert all(f.severity == "error" for f in dangling)


def test_entry_point_with_extras_marker(tmp_path):
    ep = "[console_scripts]\ndemo-cli = demo.mod:main [fancy]\n"
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl", {
        "demo/__init__.py": b"",
        "demo/mod.py": b"def main(): pass\n",
    }, entry_points=ep)
    (rep,) = C.check_artifacts([whl])
    assert not [f for f in rep.findings if f.code == "entry-point-dangling"]


def test_entry_point_can_target_shipped_data_file(tmp_path):
    ep = "[pkg_config]\nnumpy = numpy/_core/lib/pkgconfig/numpy.pc\n"
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl", {
        "numpy/__init__.py": b"",
        "numpy/_core/lib/pkgconfig/numpy.pc": b"Name: NumPy\n",
    }, entry_points=ep)
    (rep,) = C.check_artifacts([whl])
    assert not [f for f in rep.findings if f.code == "entry-point-dangling"]


def test_entry_point_can_target_reexported_package_attribute(tmp_path):
    ep = "[fsspec.specs]\nhf = huggingface_hub.HfFileSystem\n"
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl", {
        "huggingface_hub/__init__.py":
            b"from .hf_file_system import HfFileSystem\n",
        "huggingface_hub/hf_file_system.py": b"class HfFileSystem: pass\n",
    }, entry_points=ep)
    (rep,) = C.check_artifacts([whl])
    assert not [f for f in rep.findings if f.code == "entry-point-dangling"]


def test_inline_typed_python_does_not_require_sibling_stubs(tmp_path):
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl", {
        "demo/__init__.py": b"",
        "demo/py.typed": b"",
        "demo/a.py": b"x: int = 1\n",
        "demo/a.pyi": b"x: int\n",
        "demo/b.py": b"y: int = 2\n",
    })
    (rep,) = C.check_artifacts([whl])
    missing = [f for f in rep.findings if f.code == "typing-stub-missing"]
    assert not missing


def test_compiled_extension_without_source_or_stub_warns(tmp_path):
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl", {
        "demo/__init__.py": b"",
        "demo/py.typed": b"",
        "demo/native.cpython-312-x86_64-linux-gnu.so": b"binary",
    })
    (rep,) = C.check_artifacts([whl])
    missing = [f for f in rep.findings if f.code == "typing-stub-missing"]
    assert len(missing) == 1 and "demo/native" in missing[0].message
    assert missing[0].severity == "warning"


def test_stub_orphan_is_info_only(tmp_path):
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl", {
        "demo/__init__.py": b"",
        "demo/c.pyi": b"x: int\n",
    })
    (rep,) = C.check_artifacts([whl])
    assert ("info", "typing-stub-orphan") in codes(rep)
    assert not rep.has_issues


def test_metadata_name_mismatch(tmp_path):
    di = dist_info_files(name="other", version="0.1.0")
    files = dict(di)
    files.update({"demo/__init__.py": b""})
    files["other-0.1.0.dist-info/RECORD"] = record_text(files, "other-0.1.0.dist-info")
    whl = tmp_path / "demo-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(str(whl), "w") as zf:
        for arc, content in files.items():
            zf.writestr(arc, content)
    (rep,) = C.check_artifacts([str(whl)])
    assert ("error", "metadata-name-mismatch") in codes(rep)


def test_metadata_version_mismatch_warning(tmp_path):
    di = dist_info_files(name="demo", version="0.2.0")
    files = dict(di)
    files.update({"demo/__init__.py": b""})
    files["demo-0.2.0.dist-info/RECORD"] = record_text(files, "demo-0.2.0.dist-info")
    whl = tmp_path / "demo-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(str(whl), "w") as zf:
        for arc, content in files.items():
            zf.writestr(arc, content)
    (rep,) = C.check_artifacts([str(whl)])
    assert ("warning", "metadata-version-mismatch") in codes(rep)


def test_empty_wheel_warns(tmp_path):
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl",
                      {"demo/data.json": b"{}"})
    (rep,) = C.check_artifacts([whl])
    assert ("warning", "wheel-no-python") in codes(rep)


def test_namespace_package_no_crash(tmp_path):
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl", {
        "demo/__init__.py": b"",
        "demo/sub/mod.py": b"z = 3\n",  # no demo/sub/__init__.py: namespace-ish
    })
    (rep,) = C.check_artifacts([whl])
    assert not [f for f in rep.findings if f.severity == "error"]


# ------------------------------------------------------------------ sdist


def test_sdist_clean(tmp_path):
    sdist = write_sdist(tmp_path / "demo-0.1.0.tar.gz", "demo-0.1.0", {
        "PKG-INFO": pkg_info_text(),
        "demo/__init__.py": b"",
        "demo/mod.py": b"",
    })
    (rep,) = C.check_artifacts([sdist])
    assert rep.kind == "sdist"
    assert not rep.has_issues


def test_sdist_no_pkg_info(tmp_path):
    sdist = write_sdist(tmp_path / "demo-0.1.0.tar.gz", "demo-0.1.0", {
        "demo/__init__.py": b"",
    })
    (rep,) = C.check_artifacts([sdist])
    assert ("error", "sdist-no-pkg-info") in codes(rep)


# ------------------------------------------------------- wheel vs sdist


def test_sdist_file_dropped_from_wheel(tmp_path):
    # The OpenSpace story: a tracked directory/file vanishes from the wheel.
    sdist = write_sdist(tmp_path / "demo-0.1.0.tar.gz", "demo-0.1.0", {
        "PKG-INFO": pkg_info_text(),
        "demo/__init__.py": b"",
        "demo/mod.py": b"",
        "demo/skills/helper.py": b"",
    })
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl", {
        "demo/__init__.py": b"",
        "demo/mod.py": b"",
    })
    _w, _s = C.check_artifacts([whl, sdist])
    missing = [f for f in _w.findings if f.code == "sdist-file-missing-in-wheel"]
    assert any("demo/skills/helper.py" in f.message for f in missing)
    assert all(f.severity == "warning" for f in missing)


def test_wheel_extra_file_is_info_only(tmp_path):
    sdist = write_sdist(tmp_path / "demo-0.1.0.tar.gz", "demo-0.1.0", {
        "PKG-INFO": pkg_info_text(),
        "demo/__init__.py": b"",
    })
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl", {
        "demo/__init__.py": b"",
        "demo/_generated.py": b"",
    })
    (wrep, _s) = C.check_artifacts([whl, sdist])
    assert ("info", "wheel-file-not-in-sdist") in codes(wrep)


def test_src_layout_no_false_positives(tmp_path):
    sdist = write_sdist(tmp_path / "demo-0.1.0.tar.gz", "demo-0.1.0", {
        "PKG-INFO": pkg_info_text(),
        "src/demo/__init__.py": b"",
        "src/demo/mod.py": b"",
    })
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl", {
        "demo/__init__.py": b"",
        "demo/mod.py": b"",
    })
    (wrep, _s) = C.check_artifacts([whl, sdist])
    assert not [f for f in wrep.findings if f.code == "sdist-file-missing-in-wheel"]


def test_sdist_tests_dir_ignored(tmp_path):
    sdist = write_sdist(tmp_path / "demo-0.1.0.tar.gz", "demo-0.1.0", {
        "PKG-INFO": pkg_info_text(),
        "demo/__init__.py": b"",
        "tests/test_demo.py": b"def test_x(): pass\n",
    })
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl", {
        "demo/__init__.py": b"",
    })
    (wrep, _s) = C.check_artifacts([whl, sdist])
    assert not [f for f in wrep.findings if f.code == "sdist-file-missing-in-wheel"]


def test_sdist_toplevel_module_dropped(tmp_path):
    sdist = write_sdist(tmp_path / "demo-0.1.0.tar.gz", "demo-0.1.0", {
        "PKG-INFO": pkg_info_text(),
        "demo/__init__.py": b"",
        "solo.py": b"a = 1\n",
    })
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl", {
        "demo/__init__.py": b"",
    })
    (wrep, _s) = C.check_artifacts([whl, sdist])
    assert any(f.code == "sdist-file-missing-in-wheel" and "solo.py" in f.message
               for f in wrep.findings)


# ---------------------------------------------------------------- project


def test_project_package_missing(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "pyproject.toml").write_text(
        '[project]\nname = "demo"\n[tool.setuptools]\npackages = ["demo", "ghost"]\n'
    )
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl",
                      {"demo/__init__.py": b""})
    (rep,) = C.check_artifacts([whl], project=str(proj))
    assert ("error", "project-package-missing") in codes(rep)


def test_project_autodiscovery_ok(tmp_path):
    proj = tmp_path / "proj"
    (proj / "demo").mkdir(parents=True)
    (proj / "demo" / "__init__.py").write_text("")
    (proj / "pyproject.toml").write_text('[project]\nname = "demo"\n')
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl",
                      {"demo/__init__.py": b""})
    (rep,) = C.check_artifacts([whl], project=str(proj))
    assert not [f for f in rep.findings if f.code == "project-package-missing"]


def test_project_setup_cfg_packages(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "setup.cfg").write_text(
        "[metadata]\nname = demo\n[options]\npackages =\n    demo\n"
    )
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl",
                      {"demo/__init__.py": b""})
    (rep,) = C.check_artifacts([whl], project=str(proj))
    assert not [f for f in rep.findings if f.code == "project-package-missing"]


# -------------------------------------------------------------------- CLI


def test_cli_exit_codes(tmp_path, capsys):
    good = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl",
                       {"demo/__init__.py": b""})
    assert cli_main(["check", good]) == 0
    bad = write_wheel(tmp_path / "bad-0.1.0-py3-none-any.whl", {
        "demo/__init__.py": b"",
    }, name="bad", entry_points="[console_scripts]\nx = demo.nope:main\n")
    assert cli_main(["check", bad, "--quiet"]) == 1
    weird = tmp_path / "note.txt"
    weird.write_text("hello")
    assert cli_main(["check", str(weird), "--quiet"]) == 1


def test_cli_markdown_report(tmp_path, capsys):
    bad = write_wheel(tmp_path / "bad-0.1.0-py3-none-any.whl", {
        "demo/__init__.py": b"",
    }, name="bad", entry_points="[console_scripts]\nx = demo.nope:main\n")
    rc = cli_main(["check", bad, "--report", "md"])
    out = capsys.readouterr().out
    assert rc == 1
    assert out.startswith("# wheeltruth report")
    assert "| error | `entry-point-dangling` |" in out


def test_cli_text_report_ok_message(tmp_path, capsys):
    good = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl",
                       {"demo/__init__.py": b""})
    assert cli_main(["check", good]) == 0
    assert "OK: no issues found" in capsys.readouterr().out


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli_main(["--version"])
    assert exc.value.code == 0
    assert "0.1.0" in capsys.readouterr().out


# ------------------------------------------------------------------ smoke


def test_smoke_good_wheel(tmp_path):
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl", {
        "demo/__init__.py": b"VALUE = 42\n",
    })
    (rep,) = C.check_artifacts([whl], smoke=True)
    assert ("info", "smoke-ok") in codes(rep)
    assert not [f for f in rep.findings if f.severity == "error"]


def test_smoke_import_failure(tmp_path):
    whl = write_wheel(tmp_path / "demo-0.1.0-py3-none-any.whl", {
        "demo/__init__.py": b"import definitely_not_a_real_module_xyz\n",
    })
    (rep,) = C.check_artifacts([whl], smoke=True)
    assert ("error", "smoke-import-failed") in codes(rep)


# ------------------------------------------------------------------ misc


def test_parse_wheel_filename():
    assert C.parse_wheel_filename("demo-0.1.0-py3-none-any.whl") == ("demo", "0.1.0")
    assert C.parse_wheel_filename("my_pkg-1.2.3-1-py3-none-any.whl") == ("my_pkg", "1.2.3")
    assert C.parse_wheel_filename("nope.tar.gz") == (None, None)


def test_parse_sdist_filename():
    assert C.parse_sdist_filename("demo-0.1.0.tar.gz") == ("demo", "0.1.0")
    assert C.parse_sdist_filename("demo-0.1.0.tgz") == ("demo", "0.1.0")
    assert C.parse_sdist_filename("demo-0.1.0.zip") == ("demo", "0.1.0")


def test_unreadable_artifact(tmp_path):
    bad = tmp_path / "demo-0.1.0-py3-none-any.whl"
    bad.write_bytes(b"this is not a zip")
    (rep,) = C.check_artifacts([str(bad)])
    assert rep.findings and rep.findings[0].severity == "error"
