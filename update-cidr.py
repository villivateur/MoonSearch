#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from email.utils import formatdate, parsedate_to_datetime
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ZONE_PATTERN = re.compile(r'href="([a-z0-9]{2}-aggregated\.zone)"', re.IGNORECASE)


@dataclass(frozen=True)
class Dataset:
	name: str
	index_url: str
	output_dir: Path

	@property
	def manifest_path(self) -> Path:
		return self.output_dir / ".ipdeny-sync.json"


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Update CIDR zone files from ipdeny aggregated datasets."
	)
	parser.add_argument(
		"--family",
		choices=("ipv4", "ipv6", "all"),
		default="all",
		help="Select which address family to update.",
	)
	parser.add_argument(
		"--timeout",
		type=int,
		default=60,
		help="HTTP timeout in seconds.",
	)
	parser.add_argument(
		"--dry-run",
		action="store_true",
		help="Show what would change without writing files.",
	)
	return parser.parse_args()


def fetch_text(url: str, timeout: int) -> str:
	with urlopen(url, timeout=timeout) as response:
		charset = response.headers.get_content_charset() or "utf-8"
		return response.read().decode(charset, errors="replace")


def list_remote_zone_files(index_url: str, timeout: int) -> list[str]:
	html = fetch_text(index_url, timeout)
	filenames = sorted(set(match.lower() for match in ZONE_PATTERN.findall(html)))
	if not filenames:
		raise RuntimeError(f"No zone files found at {index_url}")
	return filenames


def list_local_zone_files(directory: Path) -> set[str]:
	return {path.name.lower() for path in directory.glob("*-aggregated.zone") if path.is_file()}


def write_file_atomic(path: Path, content: bytes) -> None:
	path.parent.mkdir(parents=True, exist_ok=True)
	with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
		handle.write(content)
		temp_path = Path(handle.name)
	temp_path.replace(path)


def load_manifest(path: Path) -> dict[str, str]:
	if not path.exists():
		return {}
	try:
		return json.loads(path.read_text(encoding="utf-8"))
	except (OSError, json.JSONDecodeError):
		return {}


def save_manifest(path: Path, manifest: dict[str, str]) -> None:
	path.parent.mkdir(parents=True, exist_ok=True)
	content = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
	write_file_atomic(path, content.encode("utf-8"))


def format_if_modified_since(filename: str, manifest: dict[str, str]) -> str | None:
	return manifest.get(filename)


def apply_last_modified(path: Path, header_value: str | None) -> None:
	if not header_value:
		return
	modified_at = parsedate_to_datetime(header_value).timestamp()
	os.utime(path, (modified_at, modified_at))


def download_if_changed(
	url: str,
	filename: str,
	timeout: int,
	manifest: dict[str, str],
) -> tuple[bool, bytes | None, str | None]:
	headers = {}
	last_seen = format_if_modified_since(filename, manifest)
	if last_seen:
		headers["If-Modified-Since"] = last_seen

	request = Request(url, headers=headers)
	try:
		with urlopen(request, timeout=timeout) as response:
			last_modified = response.headers.get("Last-Modified")
			return True, response.read(), last_modified
	except HTTPError as exc:
		if exc.code == 304:
			return False, None, None
		raise


def sync_dataset(dataset: Dataset, timeout: int, dry_run: bool) -> tuple[int, int, int]:
	remote_files = list_remote_zone_files(dataset.index_url, timeout)
	local_files = list_local_zone_files(dataset.output_dir)
	remote_set = set(remote_files)
	manifest = load_manifest(dataset.manifest_path)

	removed = 0
	updated = 0

	stale_files = sorted(local_files - remote_set)
	for filename in stale_files:
		target = dataset.output_dir / filename
		if dry_run:
			print(f"[{dataset.name}] remove {target}")
		else:
			target.unlink(missing_ok=True)
			manifest.pop(filename, None)
		removed += 1

	for filename in remote_files:
		target = dataset.output_dir / filename
		url = f"{dataset.index_url}{filename}"
		changed, content, last_modified = download_if_changed(url, filename, timeout, manifest)

		if not changed:
			continue

		if dry_run:
			print(f"[{dataset.name}] update {target}")
		else:
			assert content is not None
			write_file_atomic(target, content)
			apply_last_modified(target, last_modified)
			if last_modified:
				manifest[filename] = last_modified
		updated += 1

	if not dry_run:
		save_manifest(dataset.manifest_path, manifest)

	return len(remote_files), updated, removed


def build_datasets(root: Path) -> dict[str, Dataset]:
	cidr_root = root / "cidr_database"
	return {
		"ipv4": Dataset(
			name="ipv4",
			index_url="https://www.ipdeny.com/ipblocks/data/aggregated/",
			output_dir=cidr_root / "ipv4",
		),
		"ipv6": Dataset(
			name="ipv6",
			index_url="https://www.ipdeny.com/ipv6/ipaddresses/aggregated/",
			output_dir=cidr_root / "ipv6",
		),
	}


def iter_selected_datasets(selection: str, datasets: dict[str, Dataset]) -> Iterable[Dataset]:
	if selection == "all":
		return (datasets["ipv4"], datasets["ipv6"])
	return (datasets[selection],)


def main() -> int:
	args = parse_args()
	root = Path(__file__).resolve().parent
	datasets = build_datasets(root)

	try:
		total_files = 0
		total_updates = 0
		total_removed = 0

		for dataset in iter_selected_datasets(args.family, datasets):
			count, updated, removed = sync_dataset(dataset, args.timeout, args.dry_run)
			total_files += count
			total_updates += updated
			total_removed += removed
			print(
				f"[{dataset.name}] remote={count} updated={updated} removed={removed}"
			)

		action = "would change" if args.dry_run else "changed"
		print(
			f"Done: scanned {total_files} files, {action} {total_updates} files, removed {total_removed} stale files."
		)
		return 0
	except (HTTPError, URLError, RuntimeError, OSError) as exc:
		print(f"Error: {exc}", file=sys.stderr)
		return 1


if __name__ == "__main__":
	raise SystemExit(main())
