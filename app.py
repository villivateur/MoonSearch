from __future__ import annotations

import csv
import ipaddress
from dataclasses import dataclass
from pathlib import Path

from flask import Flask, render_template, request


BASE_DIR = Path(__file__).resolve().parent
CIDR_DATABASE_DIR = BASE_DIR / "cidr_database"


@dataclass(frozen=True)
class CountryInfo:
    code: str
    english_name: str
    chinese_name: str


@dataclass(frozen=True)
class LookupStats:
    ipv4_networks: int
    ipv6_networks: int
    country_count: int


@dataclass(frozen=True)
class SpecialNetwork:
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    label: str


SPECIAL_NETWORKS = (
    SpecialNetwork(ipaddress.ip_network("127.0.0.0/8"), "本地回环"),
    SpecialNetwork(ipaddress.ip_network("::1/128"), "本地回环"),
    SpecialNetwork(ipaddress.ip_network("10.0.0.0/8"), "私有网络"),
    SpecialNetwork(ipaddress.ip_network("172.16.0.0/12"), "私有网络"),
    SpecialNetwork(ipaddress.ip_network("192.168.0.0/16"), "私有网络"),
    SpecialNetwork(ipaddress.ip_network("fc00::/7"), "私有网络"),
    SpecialNetwork(ipaddress.ip_network("169.254.0.0/16"), "本地链路"),
    SpecialNetwork(ipaddress.ip_network("fe80::/10"), "本地链路"),
    SpecialNetwork(ipaddress.ip_network("224.0.0.0/4"), "组播地址"),
    SpecialNetwork(ipaddress.ip_network("ff00::/8"), "组播地址"),
    SpecialNetwork(ipaddress.ip_network("255.255.255.255/32"), "广播地址"),
    SpecialNetwork(ipaddress.ip_network("0.0.0.0/8"), "保留网络"),
    SpecialNetwork(ipaddress.ip_network("100.64.0.0/10"), "保留网络"),
    SpecialNetwork(ipaddress.ip_network("192.0.0.0/24"), "保留网络"),
    SpecialNetwork(ipaddress.ip_network("192.0.2.0/24"), "保留网络"),
    SpecialNetwork(ipaddress.ip_network("198.18.0.0/15"), "保留网络"),
    SpecialNetwork(ipaddress.ip_network("198.51.100.0/24"), "保留网络"),
    SpecialNetwork(ipaddress.ip_network("203.0.113.0/24"), "保留网络"),
    SpecialNetwork(ipaddress.ip_network("240.0.0.0/4"), "保留网络"),
    SpecialNetwork(ipaddress.ip_network("::/128"), "未指定地址"),
    SpecialNetwork(ipaddress.ip_network("2001:2::/48"), "保留网络"),
    SpecialNetwork(ipaddress.ip_network("2001:db8::/32"), "保留网络"),
)


def classify_special_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    for entry in SPECIAL_NETWORKS:
        if ip_obj.version != entry.network.version:
            continue
        if ip_obj in entry.network:
            return entry.label

    if ip_obj.is_reserved:
        return "保留网络"
    return None


class CidrRepository:
    def __init__(self, database_dir: Path) -> None:
        self.database_dir = database_dir
        self.countries = self._load_countries(database_dir / "country_codes.csv")
        self.ipv4_tables, self.ipv4_prefix_lengths, ipv4_count = self._load_network_tables(database_dir / "ipv4")
        self.ipv6_tables, self.ipv6_prefix_lengths, ipv6_count = self._load_network_tables(database_dir / "ipv6")
        self.stats = LookupStats(
            ipv4_networks=ipv4_count,
            ipv6_networks=ipv6_count,
            country_count=len(self.countries),
        )

    def lookup(self, ip_text: str) -> CountryInfo | None:
        ip_obj = ipaddress.ip_address(ip_text)
        if ip_obj.version == 4:
            code = self._lookup_in_tables(ip_obj, self.ipv4_tables, self.ipv4_prefix_lengths, 32)
        else:
            code = self._lookup_in_tables(ip_obj, self.ipv6_tables, self.ipv6_prefix_lengths, 128)
        if code is None:
            return None
        return self.countries.get(code, CountryInfo(code=code, english_name=code, chinese_name=code))

    @staticmethod
    def _load_countries(csv_path: Path) -> dict[str, CountryInfo]:
        countries: dict[str, CountryInfo] = {}
        with csv_path.open("r", encoding="utf-8-sig", newline="") as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                code = (row.get("code") or "").strip().upper()
                if not code:
                    continue
                english_name = (row.get("country_name") or code).strip().title()
                chinese_name = (row.get("country_name_zh") or code).strip()
                countries[code] = CountryInfo(
                    code=code,
                    english_name=english_name,
                    chinese_name=chinese_name,
                )
        return countries

    @staticmethod
    def _load_network_tables(directory: Path) -> tuple[dict[int, dict[int, str]], list[int], int]:
        prefix_tables: dict[int, dict[int, str]] = {}
        network_count = 0

        for zone_file in sorted(directory.glob("*-aggregated.zone")):
            country_code = zone_file.name.split("-", 1)[0].upper()
            with zone_file.open("r", encoding="utf-8") as handle:
                for raw_line in handle:
                    cidr = raw_line.strip()
                    if not cidr:
                        continue
                    network = ipaddress.ip_network(cidr, strict=False)
                    host_bits = network.max_prefixlen - network.prefixlen
                    network_key = int(network.network_address) >> host_bits if host_bits else int(network.network_address)
                    prefix_tables.setdefault(network.prefixlen, {})[network_key] = country_code
                    network_count += 1

        prefix_lengths = sorted(prefix_tables.keys(), reverse=True)
        return prefix_tables, prefix_lengths, network_count

    @staticmethod
    def _lookup_in_tables(
        ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address,
        prefix_tables: dict[int, dict[int, str]],
        prefix_lengths: list[int],
        max_prefixlen: int,
    ) -> str | None:
        ip_value = int(ip_obj)
        for prefixlen in prefix_lengths:
            host_bits = max_prefixlen - prefixlen
            network_key = ip_value >> host_bits if host_bits else ip_value
            country_code = prefix_tables[prefixlen].get(network_key)
            if country_code is not None:
                return country_code
        return None


app = Flask(__name__)
repository = CidrRepository(CIDR_DATABASE_DIR)


@app.route("/", methods=["GET", "POST"])
def index() -> str:
    ip_value = ""
    result = None
    error = None

    if request.method == "POST":
        ip_value = request.form.get("ip", "").strip()
        if not ip_value:
            error = "请输入 IPv4 或 IPv6 地址。"
        else:
            try:
                ip_obj = ipaddress.ip_address(ip_value)
            except ValueError:
                error = "请输入合法的 IPv4 或 IPv6 地址。"
            else:
                special_label = classify_special_ip(ip_obj)
                if special_label is not None:
                    result = special_label
                else:
                    country = repository.lookup(ip_value)
                    if country is None:
                        result = "Unknown | 未知"
                    else:
                        result = f"{country.english_name} | {country.chinese_name}"

    return render_template(
        "index.html",
        ip_value=ip_value,
        result=result,
        error=error,
        stats=repository.stats,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
