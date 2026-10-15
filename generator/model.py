"""Derived network model built from inventory/sites.yaml.

Everything that the generator and the tests need (subnets, tunnels, peers)
is computed here once, so configs and tests can never disagree about the plan.
"""
from __future__ import annotations

import csv
import hashlib
import ipaddress
import itertools
import secrets
import string
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
INV = ROOT / "inventory"


@dataclass
class Vlan:
    id: int
    name: str
    desc: str
    net: ipaddress.IPv4Network
    dhcp: bool
    internet: bool
    cross_site: bool
    type: str = "vlan"          # vlan (on FortiLink) | ssid (tunnel-mode FortiAP SSID)
    ssid: str | None = None

    @property
    def gw(self) -> ipaddress.IPv4Address:
        return self.net.network_address + 1

    def dhcp_range(self) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]:
        # .50 .. last-5 leaves room for statics at the bottom and top
        return self.net.network_address + 50, self.net.broadcast_address - 5


@dataclass
class Site:
    id: int
    code: str
    name: str
    users: int
    model: str
    ha: bool
    supernet: ipaddress.IPv4Network
    loopback: ipaddress.IPv4Address
    fortilink_net: ipaddress.IPv4Network
    vpn_pool: ipaddress.IPv4Network
    dc_ips: list[str]
    wan: dict
    fortilink_ports: list[str]
    switches: list[dict]
    aps: dict
    ha_hbdev: list[str] = field(default_factory=list)
    vlans: list[Vlan] = field(default_factory=list)

    def vlan(self, name: str) -> Vlan:
        return next(v for v in self.vlans if v.name == name)

    def wan_ip(self, w: str) -> str:
        return self.wan[w]["ip"].split("/")[0]


@dataclass
class Tunnel:
    """One IPsec tunnel between two sites over a specific ISP pair."""
    a: Site
    b: Site
    a_wan: str               # wan1 | wan2 on side A
    b_wan: str
    net: ipaddress.IPv4Network   # /30
    psk: str

    @property
    def a_name(self) -> str:   # interface name as seen on site A
        return f"{self.b.code}_{self.a_wan[-1]}{self.b_wan[-1]}"

    @property
    def b_name(self) -> str:
        return f"{self.a.code}_{self.b_wan[-1]}{self.a_wan[-1]}"

    @property
    def a_ip(self):
        return self.net.network_address + 1

    @property
    def b_ip(self):
        return self.net.network_address + 2

    def side(self, site: Site) -> dict:
        """Everything site `site` needs to build its half of this tunnel."""
        if site.code == self.a.code:
            return dict(name=self.a_name, local_wan=self.a_wan, peer=self.b,
                        peer_wan=self.b_wan, ip=self.a_ip, remote_ip=self.b_ip)
        assert site.code == self.b.code
        return dict(name=self.b_name, local_wan=self.b_wan, peer=self.a,
                    peer_wan=self.a_wan, ip=self.b_ip, remote_ip=self.a_ip)


def _rand(n: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits  # no symbols: avoids CLI escaping issues
    return "".join(secrets.choice(alphabet) for _ in range(n))


def demo_mode() -> bool:
    """Public/demo mode: no inventory/secrets.yaml present and --real-secrets not requested.
    Demo secrets are deterministic, clearly labelled and MUST be replaced before deployment."""
    return not (INV / "secrets.yaml").exists()


def load_secrets(keys: list[str], rotate: bool = False, real: bool = False) -> dict:
    """Real secrets live in inventory/secrets.yaml (git-ignored, created with --real-secrets).
    Without that file the generator uses DEMO placeholders so the repo never contains live keys."""
    path = INV / "secrets.yaml"
    if not real and demo_mode():
        return {k: "DEMO" + hashlib.sha256(k.encode()).hexdigest()[:28] for k in keys}
    data = {} if rotate or not path.exists() else (yaml.safe_load(path.read_text()) or {})
    changed = False
    for k in keys:
        if k not in data:
            data[k] = _rand()
            changed = True
    if changed:
        path.write_text("# GENERATED - store in your password vault, never commit.\n"
                        + yaml.safe_dump(data, sort_keys=True))
    return data


@dataclass
class Model:
    g: dict
    sites: list[Site]
    tunnels: list[Tunnel]
    users: list[dict]
    secrets: dict

    def site(self, code: str) -> Site:
        return next(s for s in self.sites if s.code == code)

    def tunnels_of(self, site: Site) -> list[Tunnel]:
        return [t for t in self.tunnels if site.code in (t.a.code, t.b.code)]

    def peers_of(self, site: Site) -> list[Site]:
        return [s for s in self.sites if s.code != site.code]


def build(rotate_secrets: bool = False, real_secrets: bool = False) -> Model:
    raw = yaml.safe_load((INV / "sites.yaml").read_text())
    g = raw["global"]
    sites: list[Site] = []
    for s in sorted(raw["sites"], key=lambda x: x["id"]):
        site = Site(
            id=s["id"], code=s["code"], name=s["name"], users=s["users"],
            model=s["model"], ha=s["ha"],
            supernet=ipaddress.ip_network(s["supernet"]),
            loopback=ipaddress.ip_address(s["loopback"]),
            fortilink_net=ipaddress.ip_network(s["fortilink_net"]),
            vpn_pool=ipaddress.ip_network(s["vpn_pool"]),
            dc_ips=s["dc_ips"], wan=s["wan"],
            fortilink_ports=s["fortilink_ports"], switches=s["switches"],
            aps=s["aps"], ha_hbdev=s.get("ha_hbdev", []),
        )
        second_octet = site.supernet.network_address.packed[1]
        for v in g["vlans"]:
            prefix = v.get("prefix", 24)
            net = ipaddress.ip_network(f"10.{second_octet}.{v['id']}.0/{prefix}")
            site.vlans.append(Vlan(id=v["id"], name=v["name"], desc=v["desc"], net=net,
                                   dhcp=v["dhcp"], internet=v["internet"],
                                   cross_site=v["cross_site"], type=v.get("type", "vlan"),
                                   ssid=v.get("ssid")))
        sites.append(site)

    # Full mesh: every site pair gets 4 tunnels (wan1/wan2 x wan1/wan2) so that
    # ANY single ISP failure at ANY site still leaves 2+ paths between every pair.
    overlay = ipaddress.ip_network(g["overlay_supernet"])
    slots = overlay.subnets(new_prefix=30)
    pending = []
    for a, b in itertools.combinations(sites, 2):
        for aw, bw in itertools.product(("wan1", "wan2"), repeat=2):
            pending.append((a, b, aw, bw, next(slots)))

    secret_keys = [f"psk_{a.code}_{b.code}_{aw}{bw}" for a, b, aw, bw, _ in pending]
    secret_keys += [f"ravpn_psk_{s.code}" for s in sites]
    secret_keys += ["ldap_bind_password", "radius_secret", "fsso_password",
                    "bgp_password", "ha_password", "guest_wifi_psk"]
    sec = load_secrets(secret_keys, rotate=rotate_secrets, real=real_secrets or rotate_secrets)

    tunnels = [Tunnel(a, b, aw, bw, net, sec[f"psk_{a.code}_{b.code}_{aw}{bw}"])
               for a, b, aw, bw, net in pending]

    users = []
    with open(INV / "vpn_users.csv") as fh:
        rows = [ln for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
    for r in csv.DictReader(rows):
        users.append({k: v.strip() for k, v in r.items()})

    return Model(g=g, sites=sites, tunnels=tunnels, users=users, secrets=sec)
