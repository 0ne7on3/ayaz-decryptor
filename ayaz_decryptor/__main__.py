import argparse
import hashlib
import io
import json
import sys
from pathlib import Path

from . import __version__
from .core import decode_info, decrypt_file, read_footer, transform_body
from .pairs import analyze_archive, iter_pairs


class DiscardOutput:
    def write(self, data):
        return len(data)


def load_json(path):
    with open(path, "rb") as handle:
        raw = handle.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("JSON exceeds 2 MiB")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("Invalid profile JSON") from error
    if not isinstance(value, dict):
        raise ValueError("Profile must be a JSON object")
    return value


def emit(value, path):
    content = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    if path:
        with open(path, "x", encoding="utf-8") as handle:
            handle.write(content)
    else:
        print(content, end="")


def verify_archive(archive, profile, *, allow_unknown_name=False):
    results = []
    for metadata, encrypted, decrypted in iter_pairs(archive):
        result = {"inode": metadata.get("inode"), "archive_validation": metadata.get("validation")}
        try:
            source = io.BytesIO(encrypted)
            footer = read_footer(source)
            info = decode_info(
                footer, profile, metadata["decrypted"]["original_name"],
                allow_unknown_name=allow_unknown_name,
            )
            digest = transform_body(source, DiscardOutput(), footer.body_size, info)
            match = digest == hashlib.sha256(decrypted).hexdigest()
            validation = "sha256_match" if match else "sha256_mismatch"
            if not info.name_verified:
                validation += "_name_unverified"
            result.update(
                sha256=digest, match=match, validation=validation,
                name_validation="metadata_match" if info.name_verified else "inventory_label_only",
            )
        except (ValueError, KeyError, TypeError) as error:
            result.update(match=False, error=str(error))
        results.append(result)
    return {
        "pair_count": len(results), "matched": sum(item["match"] for item in results),
        "note": "A match against an archive candidate does not by itself confirm that the original is intact",
        "results": results,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Recover LockBit 3 files using a known metadata keystream")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="Validate file pairs and extract confirmed keystream bytes")
    analyze.add_argument("archive", type=Path)
    analyze.add_argument("--report", type=Path)
    decrypt = commands.add_parser("decrypt", help="Decrypt one file with its group's complete keystream")
    decrypt.add_argument("input", type=Path)
    decrypt.add_argument("--profile", type=Path, required=True)
    decrypt.add_argument("--original-name", required=True)
    decrypt.add_argument("--output", type=Path, required=True)
    decrypt.add_argument("--expected-sha256")
    decrypt.add_argument(
        "--allow-unknown-name", action="store_true",
        help="Allow an unknown metadata filename when the content key and encryption layout are fully known",
    )
    verify = commands.add_parser("verify", help="Compare decrypted content with each file pair")
    verify.add_argument("archive", type=Path)
    verify.add_argument("--profile", type=Path, required=True)
    verify.add_argument("--report", type=Path)
    verify.add_argument(
        "--allow-unknown-name", action="store_true",
        help="Verify paired content even when the compressed filename keystream is incomplete",
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "analyze":
            emit(analyze_archive(args.archive), args.report)
            return 0
        profile = load_json(args.profile)
        if args.command == "decrypt":
            emit(decrypt_file(
                args.input, args.output, profile, args.original_name, args.expected_sha256,
                allow_unknown_name=args.allow_unknown_name,
            ), None)
            return 0
        result = verify_archive(args.archive, profile, allow_unknown_name=args.allow_unknown_name)
        emit(result, args.report)
        return 0 if result["matched"] == result["pair_count"] else 2
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
