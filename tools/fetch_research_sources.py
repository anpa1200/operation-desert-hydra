#!/usr/bin/env python3
"""Fetch source-list URLs into separate raw-source folders.

The script is intentionally simple and dependency-light. It uses curl for web
fetching because vendor sites often behave better with curl redirects and a
browser-like user agent than with urllib.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_LIST = ROOT / "docs/source-gathering/relevant-research-list.md"
OUT_DIR = ROOT / "docs/source-gathering/raw-sources"
MANIFEST = OUT_DIR / "manifest.json"

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


def slugify(value: str, max_len: int = 90) -> str:
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = re.sub(r"-+", "-", value).strip("-")
    return value[:max_len].strip("-") or "source"


def parse_sources(text: str) -> list[dict[str, str]]:
    sources: list[dict[str, str]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        match = re.match(r"^(\d+)\.\s+(.+?)\s*$", lines[i])
        if not match:
            i += 1
            continue

        number = int(match.group(1))
        title = match.group(2).strip()
        url = ""
        j = i + 1
        while j < len(lines):
            candidate = lines[j].strip()
            if candidate.startswith("https://"):
                url = candidate
                break
            if re.match(r"^\d+\.\s+", candidate) or candidate.startswith("## "):
                break
            j += 1

        if url:
            sources.append({"number": str(number), "title": title, "url": url})
        i = j + 1
    return sources


def run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def content_kind(path: Path, headers: str, url: str) -> tuple[str, str]:
    header_lc = headers.lower()
    url_lc = url.lower()
    head = path.read_bytes()[:500]
    head_text = head.decode("utf-8", errors="ignore").lower()
    if head.startswith(b"%PDF"):
        return "pdf", "pdf"
    if "text/html" in header_lc or "<html" in head_text or "<!doctype html" in head_text:
        return "html", "html"
    if "application/pdf" in header_lc or url_lc.endswith(".pdf"):
        return "pdf", "pdf"
    if "application/json" in header_lc or url_lc.endswith(".json"):
        return "json", "json"
    if "text/plain" in header_lc or url_lc.endswith(".txt"):
        return "text", "txt"
    return "binary", "bin"


def extract_text(kind: str, raw_path: Path, text_path: Path) -> str:
    if kind == "pdf":
        result = run(["pdftotext", "-layout", str(raw_path), str(text_path)])
        return result.stderr.strip()
    if kind == "html":
        result = run(["html2text", str(raw_path)])
        text_path.write_text(result.stdout, encoding="utf-8", errors="ignore")
        return result.stderr.strip()
    if kind in {"json", "text"}:
        text_path.write_bytes(raw_path.read_bytes())
        return ""
    return "no text extractor for binary content"


def fetch_one(source: dict[str, str]) -> dict[str, object]:
    number = int(source["number"])
    title = source["title"]
    url = source["url"]
    source_dir = OUT_DIR / f"{number:02d}-{slugify(title)}"
    source_dir.mkdir(parents=True, exist_ok=True)

    tmp_body = source_dir / "source.download"
    header_path = source_dir / "headers.txt"

    curl_cmd = [
        "curl",
        "-L",
        "--compressed",
        "--connect-timeout",
        "20",
        "--max-time",
        "90",
        "--retry",
        "2",
        "--retry-delay",
        "2",
        "-A",
        USER_AGENT,
        "-D",
        str(header_path),
        "-o",
        str(tmp_body),
        "-w",
        "%{http_code} %{url_effective}",
        url,
    ]
    result = run(curl_cmd)
    status_line = result.stdout.strip()
    status_code = status_line.split(" ", 1)[0] if status_line else ""
    headers = header_path.read_text(errors="ignore") if header_path.exists() else ""

    metadata: dict[str, object] = {
        "number": number,
        "title": title,
        "url": url,
        "curl_status": status_line,
        "http_status": status_code,
        "stderr": result.stderr.strip(),
        "saved": False,
    }

    if result.returncode != 0 or not tmp_body.exists() or tmp_body.stat().st_size == 0:
        metadata["error"] = "download_failed_or_empty"
        (source_dir / "metadata.json").write_text(
            json.dumps(metadata, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return metadata

    kind, ext = content_kind(tmp_body, headers, url)
    raw_path = source_dir / f"source.{ext}"
    if raw_path.exists():
        raw_path.unlink()
    tmp_body.rename(raw_path)

    text_path = source_dir / "source.txt"
    extract_error = extract_text(kind, raw_path, text_path)

    metadata.update(
        {
            "saved": True,
            "http_ok": status_code.startswith(("2", "3")),
            "kind": kind,
            "raw_file": str(raw_path.relative_to(ROOT)),
            "text_file": str(text_path.relative_to(ROOT)) if text_path.exists() else None,
            "size_bytes": raw_path.stat().st_size,
            "extract_error": extract_error,
        }
    )
    (source_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return metadata


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sources = parse_sources(SOURCE_LIST.read_text(encoding="utf-8"))
    if not sources:
        print("No sources parsed", file=sys.stderr)
        return 1

    manifest = []
    for source in sources:
        print(f"[{source['number']}] {source['title']}", flush=True)
        manifest.append(fetch_one(source))

    MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    ok = sum(1 for item in manifest if item.get("saved"))
    failed = len(manifest) - ok
    print(f"Fetched {ok}/{len(manifest)} sources; failed {failed}")
    return 0 if failed == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
