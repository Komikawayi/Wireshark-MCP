#!/usr/bin/env python3
"""Validate both skill trees, references and helpers inside a built wheel."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]


def check(wheel: Path) -> int:
    source = ROOT / "skills"
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    expected = {item["name"] for item in manifest["skills"]}
    with ZipFile(wheel) as archive:
        names = set(archive.namelist())
        actual = {
            name.split("/")[2]
            for name in names
            if name.startswith("wireshark_mcp/skills/") and name.endswith("/SKILL.md")
        }
        if actual != expected:
            raise ValueError(f"wheel skills {actual} differ from manifest {expected}")
        for relative in [
            "manifest.json",
            *[
                str(p.relative_to(source))
                for p in source.rglob("*")
                if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"
            ],
        ]:
            name = "wireshark_mcp/skills/" + relative.replace("\\", "/")
            if name not in names or archive.read(name) != (source / relative).read_bytes():
                raise ValueError(f"missing or different wheel skill resource: {relative}")
        if any("/__pycache__/" in name or name.endswith(".pyc") for name in names if "/skills/" in name):
            raise ValueError("wheel contains generated skill bytecode")
    print(f"Verified {len(expected)} packaged skills and every canonical resource: {wheel}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    args = parser.parse_args()
    return check(args.wheel)


if __name__ == "__main__":
    raise SystemExit(main())
