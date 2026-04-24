#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from zipfile import ZipFile, ZipInfo, BadZipFile

SNAPSHOT_NAME_RE = re.compile(r"^(?P<target>.+)-main_(?P<source_commit>[0-9a-f]{40})\.zip$")
SCHEMA_VERSION = 1


class SnapshotError(Exception):
    pass


@dataclass(frozen=True)
class PackedEntry:
    path: str
    record: dict[str, object]
    raw_size: int
    raw_sha256: str


def _json_line(obj: dict[str, object]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_zip_path(name: str) -> str:
    raw = str(name).replace("\\", "/")
    while raw.startswith("./"):
        raw = raw[2:]
    if raw == "" or raw.endswith("/"):
        raise SnapshotError(f"not_a_file_path:{name!r}")
    posix = PurePosixPath(raw)
    if posix.is_absolute():
        raise SnapshotError(f"absolute_path_forbidden:{name!r}")
    if any(part in ("", ".", "..") for part in posix.parts):
        raise SnapshotError(f"unsafe_path_forbidden:{name!r}")
    return posix.as_posix()


def _zip_mode(info: ZipInfo) -> int:
    mode = (info.external_attr >> 16) & 0o177777
    if mode == 0:
        return 0o100644
    if stat.S_ISDIR(mode):
        raise SnapshotError(f"directory_passed_as_file:{info.filename!r}")
    if stat.S_ISLNK(mode):
        return 0o120000
    if stat.S_ISREG(mode):
        return mode
    # ZIP snapshots should not carry device/socket/fifo entries.
    raise SnapshotError(f"unsupported_zip_entry_mode:{info.filename!r}:mode={mode:o}")


def _mode_string(mode: int) -> str:
    if stat.S_ISLNK(mode):
        return "120000"
    if mode & 0o111:
        return "100755"
    return "100644"


def _infer_target_and_commit(input_zip: Path, target: str | None, source_commit: str | None) -> tuple[str, str | None]:
    match = SNAPSHOT_NAME_RE.fullmatch(input_zip.name)
    inferred_target = match.group("target") if match else None
    inferred_commit = match.group("source_commit") if match else None

    final_target = (target or inferred_target or "").strip()
    if not final_target:
        raise SnapshotError("target_missing: pass --target or use <target>-main_<40hex>.zip basename")

    final_commit = (source_commit or inferred_commit or "").strip() or None
    if final_commit is not None and not re.fullmatch(r"[0-9a-f]{40}", final_commit):
        raise SnapshotError(f"source_commit_must_be_40_lower_hex:{final_commit}")
    return final_target, final_commit


def _pack_regular_file(info: ZipInfo, path: str, raw: bytes, mode: int) -> PackedEntry:
    digest = _sha256_bytes(raw)
    record = {
        "type": "file",
        "path": path,
        "mode": _mode_string(mode),
        "size": len(raw),
        "sha256": digest,
        "encoding": "base64",
        "data": base64.b64encode(raw).decode("ascii"),
    }
    return PackedEntry(path=path, record=record, raw_size=len(raw), raw_sha256=digest)


def _pack_symlink(info: ZipInfo, path: str, raw: bytes) -> PackedEntry:
    try:
        target = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SnapshotError(f"symlink_target_not_utf8:{path}") from exc
    if "\x00" in target or target == "":
        raise SnapshotError(f"invalid_symlink_target:{path}")
    digest = _sha256_bytes(raw)
    record = {
        "type": "symlink",
        "path": path,
        "mode": "120000",
        "target": target,
        "size": len(raw),
        "sha256": digest,
    }
    return PackedEntry(path=path, record=record, raw_size=len(raw), raw_sha256=digest)


def pack_zip_to_jsonl(input_zip: Path, output_jsonl: Path, target: str | None, source_commit: str | None) -> None:
    if not input_zip.is_file():
        raise SnapshotError(f"input_zip_not_found:{input_zip}")
    final_target, final_commit = _infer_target_and_commit(input_zip, target, source_commit)

    try:
        with ZipFile(input_zip, "r") as zf:
            infos = [info for info in zf.infolist() if not info.is_dir()]
            if not infos:
                raise SnapshotError("zip_contains_no_files")
            packed: list[PackedEntry] = []
            seen_paths: set[str] = set()
            for info in sorted(infos, key=lambda item: _safe_zip_path(item.filename)):
                path = _safe_zip_path(info.filename)
                if path in seen_paths:
                    raise SnapshotError(f"duplicate_path:{path}")
                seen_paths.add(path)
                mode = _zip_mode(info)
                raw = zf.read(info.filename)
                if stat.S_ISLNK(mode):
                    packed.append(_pack_symlink(info, path, raw))
                else:
                    packed.append(_pack_regular_file(info, path, raw, mode))
    except BadZipFile as exc:
        raise SnapshotError(f"bad_zip:{input_zip}") from exc

    total_size = sum(item.raw_size for item in packed)
    file_manifest = [
        {
            "path": item.path,
            "type": item.record["type"],
            "mode": item.record["mode"],
            "size": item.raw_size,
            "sha256": item.raw_sha256,
        }
        for item in packed
    ]
    files_manifest_sha256 = _sha256_bytes(_json_line({"files": file_manifest}).encode("utf-8"))

    header: dict[str, object] = {
        "type": "header",
        "schema_version": SCHEMA_VERSION,
        "target": final_target,
        "source_commit": final_commit,
        "source_format": "zip",
        "source_basename": input_zip.name,
        "file_count": len(packed),
        "total_size": total_size,
        "files_manifest_sha256": files_manifest_sha256,
    }

    lines = [_json_line(header)]
    lines.extend(_json_line(item.record) for item in packed)
    body_sha256 = _sha256_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    footer: dict[str, object] = {
        "type": "footer",
        "schema_version": SCHEMA_VERSION,
        "target": final_target,
        "file_count": len(packed),
        "total_size": total_size,
        "files_manifest_sha256": files_manifest_sha256,
        "body_sha256": body_sha256,
    }
    lines.append(_json_line(footer))

    output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    tmp = output_jsonl.with_suffix(output_jsonl.suffix + ".part")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    tmp.replace(output_jsonl)

    print("SNAPSHOT_JSONL_OK")
    print(f"target={final_target}")
    print(f"source_commit={final_commit or '-'}")
    print(f"input_zip={input_zip}")
    print(f"output_jsonl={output_jsonl}")
    print(f"file_count={len(packed)}")
    print(f"total_size={total_size}")
    print(f"files_manifest_sha256={files_manifest_sha256}")
    print(f"body_sha256={body_sha256}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Convert one repository ZIP snapshot into one deterministic UTF-8 JSONL snapshot container."
    )
    parser.add_argument("input_zip", help="Input snapshot ZIP, e.g. audiomason2-main_<sha>.zip")
    parser.add_argument("output_jsonl", help="Output .snapshot.jsonl path")
    parser.add_argument("--target", help="Target repo name; inferred from <target>-main_<sha>.zip when omitted")
    parser.add_argument("--source-commit", help="40-hex source commit; inferred from filename when omitted")
    args = parser.parse_args(argv)

    try:
        pack_zip_to_jsonl(
            Path(args.input_zip).resolve(),
            Path(args.output_jsonl).resolve(),
            args.target,
            args.source_commit,
        )
        return 0
    except SnapshotError as exc:
        print(f"SNAPSHOT_JSONL_FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
