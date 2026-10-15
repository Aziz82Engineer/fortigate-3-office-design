"""Minimal FortiOS CLI parser + policy/routing/SD-WAN simulator used by the tests.

The parser enforces the CLI grammar (config ... end, edit ... next, set/unset)
and merges repeated `config <path>` blocks exactly like FortiOS does when a
script is applied top to bottom.
"""
from __future__ import annotations

import ipaddress
import shlex
from dataclasses import dataclass, field
from pathlib import Path


class ParseError(Exception):
    pass


@dataclass
class Node:
    sets: dict[str, list[str]] = field(default_factory=dict)
    configs: dict[str, "Node"] = field(default_factory=dict)
    edits: dict[str, "Node"] = field(default_factory=dict)   # insertion-ordered

    # convenience -----------------------------------------------------------
    def get(self, key: str, default=None):
        v = self.sets.get(key)
        if v is None:
            return default
        return v[0] if len(v) == 1 else v

    def lst(self, key: str) -> list[str]:
        return list(self.sets.get(key, []))

    def cfg(self, path: str) -> "Node":
        return self.configs.get(path, Node())

    def merge(self, other: "Node"):
        self.sets.update(other.sets)
        for k, v in other.configs.items():
            self.configs.setdefault(k, Node()).merge(v)
        for k, v in other.edits.items():
            self.edits.setdefault(k, Node()).merge(v)


def parse(text: str) -> Node:
    root = Node()
    stack: list[tuple[str, Node]] = [("root", root)]
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tok = shlex.split(line, posix=True)
        except ValueError as e:
            raise ParseError(f"line {lineno}: {e}: {raw!r}")
        kind, cur = stack[-1]
        if tok[0] == "config":
            if len(tok) < 2:
                raise ParseError(f"line {lineno}: config without path")
            node = Node()
            stack.append(("config:" + " ".join(tok[1:]), node))
        elif tok[0] == "edit":
            if not kind.startswith("config"):
                raise ParseError(f"line {lineno}: edit outside config")
            if len(tok) != 2:
                raise ParseError(f"line {lineno}: edit needs exactly one key: {raw!r}")
            node = Node()
            stack.append(("edit:" + tok[1], node))
        elif tok[0] == "next":
            if not kind.startswith("edit"):
                raise ParseError(f"line {lineno}: 'next' without 'edit'")
            _, node = stack.pop()
            parent = stack[-1][1]
            key = kind.split(":", 1)[1]
            parent.edits.setdefault(key, Node()).merge(node)
        elif tok[0] == "end":
            if not kind.startswith("config"):
                raise ParseError(f"line {lineno}: 'end' closes {kind}, not a config")
            _, node = stack.pop()
            parent = stack[-1][1]
            parent.configs.setdefault(kind.split(":", 1)[1], Node()).merge(node)
        elif tok[0] == "set":
            if len(tok) < 3:
                raise ParseError(f"line {lineno}: set without value: {raw!r}")
            if kind == "root":
                raise ParseError(f"line {lineno}: set outside config")
            cur.sets[tok[1]] = tok[2:]
        elif tok[0] == "unset":
            cur.sets.pop(tok[1], None)
        else:
            raise ParseError(f"line {lineno}: unknown statement {tok[0]!r}")
    if len(stack) != 1:
        raise ParseError(f"unterminated block(s): {[k for k, _ in stack[1:]]}")
    return root


def load(path: Path) -> Node:
    return parse(path.read_text())


# --------------------------------------------------------------------------- #
#                     objects predefined in FortiOS 7.6                        #
# --------------------------------------------------------------------------- #
# proto, port ranges   (icmp => None)
PREDEF_SERVICES = {
    "ALL": [("any", 0, 65535)],
    "HTTP": [("tcp", 80, 80)], "HTTPS": [("tcp", 443, 443)],
    "DNS": [("tcp", 53, 53), ("udp", 53, 53)], "NTP": [("udp", 123, 123), ("tcp", 123, 123)],
    "PING": [("icmp", 0, 0)], "SSH": [("tcp", 22, 22)], "SMB": [("tcp", 445, 445)],
    "KERBEROS": [("tcp", 88, 88), ("udp", 88, 88)], "LDAP": [("tcp", 389, 389)],
    "LDAP_UDP": [("udp", 389, 389)], "DCE-RPC": [("tcp", 135, 135), ("udp", 135, 135)],
    "SNMP": [("udp", 161, 162), ("tcp", 161, 162)], "BGP": [("tcp", 179, 179)],
    "RDP": [("tcp", 3389, 3389)],
}
PREDEF_ADDR = {"all": ipaddress.ip_network("0.0.0.0/0")}
PREDEF_PROFILES = {
    "av-profile": {"default"}, "webfilter-profile": {"default"},
    "dnsfilter-profile": {"default"}, "ips-sensor": {"default", "high_security"},
    "application-list": {"default", "block-high-risk"},
    "ssl-ssh-profile": {"certificate-inspection", "deep-inspection"},
}
PREDEF_INTERFACES = {"wan1", "wan2", "fortilink"}


# --------------------------------------------------------------------------- #
#                               simulator                                     #
# --------------------------------------------------------------------------- #
class FortiGate:
    def __init__(self, root: Node):
        self.root = root
        self.intf = root.cfg("system interface").edits
        self.addr = root.cfg("firewall address").edits
        self.addrgrp = root.cfg("firewall addrgrp").edits
        self.svc = root.cfg("firewall service custom").edits
        self.svcgrp = root.cfg("firewall service group").edits
        self.policies = root.cfg("firewall policy").edits
        self.sdwan = root.cfg("system sdwan")
        self.zones = root.cfg("system zone").edits
        self.groups = root.cfg("user group").edits
        self.vaps = root.cfg("wireless-controller vap").edits
        self.p1 = root.cfg("vpn ipsec phase1-interface").edits

    # ---- names --------------------------------------------------------------
    def interfaces(self) -> set[str]:
        return set(self.intf) | set(self.vaps) | set(self.p1) | PREDEF_INTERFACES

    def zone_members(self) -> dict[str, set[str]]:
        z = {name: set(n.lst("interface")) for name, n in self.zones.items()}
        for _, mem in self.sdwan.cfg("members").edits.items():
            z.setdefault(mem.get("zone"), set()).add(mem.get("interface"))
        return z

    def intf_matches(self, listed: list[str], intf: str) -> bool:
        zm = self.zone_members()
        return any(x == intf or intf in zm.get(x, set()) for x in listed)

    # ---- addresses ----------------------------------------------------------
    def resolve_addr(self, name: str, seen=None) -> list:
        seen = seen or set()
        if name in PREDEF_ADDR:
            return [PREDEF_ADDR[name]]
        if name in self.addr:
            ip, m = self.addr[name].lst("subnet")
            return [ipaddress.ip_network(f"{ip}/{m}")]
        if name in self.addrgrp:
            if name in seen:
                raise ValueError(f"address group loop at {name}")
            out = []
            for mbr in self.addrgrp[name].lst("member"):
                out += self.resolve_addr(mbr, seen | {name})
            return out
        raise KeyError(f"unknown address {name}")

    def addr_contains(self, names: list[str], ip) -> bool:
        ip = ipaddress.ip_address(ip)
        return any(ip in n for x in names for n in self.resolve_addr(x))

    # ---- services -----------------------------------------------------------
    def resolve_svc(self, name: str) -> list[tuple[str, int, int]]:
        if name in PREDEF_SERVICES:
            return PREDEF_SERVICES[name]
        if name in self.svc:
            out = []
            for proto in ("tcp", "udp"):
                for rng in self.svc[name].lst(f"{proto}-portrange"):
                    for r in rng.split():
                        lo, _, hi = r.partition("-")
                        out.append((proto, int(lo), int(hi or lo)))
            return out
        if name in self.svcgrp:
            out = []
            for mbr in self.svcgrp[name].lst("member"):
                out += self.resolve_svc(mbr)
            return out
        raise KeyError(f"unknown service {name}")

    def svc_matches(self, names: list[str], proto: str, port: int) -> bool:
        for n in names:
            for p, lo, hi in self.resolve_svc(n):
                if p == "any" or (p == proto and (proto == "icmp" or lo <= port <= hi)):
                    return True
        return False

    # ---- users --------------------------------------------------------------
    def user_groups(self, username: str | None, fsso_groups: set[str] = frozenset()) -> set[str]:
        out: set[str] = set()
        changed = True
        while changed:
            changed = False
            for gname, g in self.groups.items():
                if gname in out:
                    continue
                mem = set(g.lst("member"))
                if (username and username in mem) or (mem & out) or (mem & fsso_groups):
                    out.add(gname)
                    changed = True
        return out

    # ---- routing ------------------------------------------------------------
    def connected(self) -> list[tuple[ipaddress.IPv4Network, str]]:
        out = []
        for name, n in self.intf.items():
            if n.get("type") == "loopback" or not n.lst("ip"):
                continue
            ip, m = n.lst("ip")
            if m == "255.255.255.255":
                rip = n.lst("remote-ip")
                if rip:
                    out.append((ipaddress.ip_network(f"{rip[0]}/{rip[1]}", strict=False), name))
                continue
            out.append((ipaddress.ip_network(f"{ip}/{m}", strict=False), name))
        for name, p in self.p1.items():
            if p.get("type") == "dynamic" and p.get("ipv4-start-ip"):
                lo = ipaddress.ip_address(p.get("ipv4-start-ip"))
                hi = ipaddress.ip_address(p.get("ipv4-end-ip"))
                for net in ipaddress.summarize_address_range(lo, hi):
                    out.append((net, name))
        return out

    def route(self, dst, bgp_routes: dict[str, str], down_tunnels: set[str] = frozenset()):
        """Longest-prefix match. bgp_routes = {prefix: 'OVERLAY'} as learned from peers.
        Returns egress interface/zone name or 'BLACKHOLE'."""
        dst = ipaddress.ip_address(dst)
        cands = []
        for net, name in self.connected():
            if dst in net and name not in down_tunnels:
                cands.append((net.prefixlen, 0, name))
        for pfx, via in bgp_routes.items():
            net = ipaddress.ip_network(pfx)
            if dst in net:
                cands.append((net.prefixlen, 200, via))
        for _, r in self.root.cfg("router static").edits.items():
            if r.get("sdwan-zone"):
                net, dist, via = ipaddress.ip_network("0.0.0.0/0"), int(r.get("distance", 10)), r.get("sdwan-zone")
            else:
                ip, m = r.lst("dst")
                net = ipaddress.ip_network(f"{ip}/{m}")
                dist = int(r.get("distance", 10))
                via = "BLACKHOLE" if r.get("blackhole") == "enable" else r.get("device")
                if via in down_tunnels:
                    continue
            if dst in net:
                cands.append((net.prefixlen, dist, via))
        if not cands:
            return "BLACKHOLE"
        cands.sort(key=lambda c: (-c[0], c[1]))
        return cands[0][2]

    def src_intf(self, src) -> str:
        src = ipaddress.ip_address(src)
        best = None
        for net, name in self.connected():
            if src in net and (best is None or net.prefixlen > best[0].prefixlen):
                best = (net, name)
        return best[1] if best else None

    # ---- policy lookup --------------------------------------------------------
    def lookup(self, srcintf: str, dstintf: str, src, dst, proto: str, port: int,
               user_groups: set[str] = frozenset()):
        for pid, p in self.policies.items():
            if p.get("status") == "disable":
                continue
            if not self.intf_matches(p.lst("srcintf"), srcintf):
                continue
            if not self.intf_matches(p.lst("dstintf"), dstintf):
                continue
            if not self.addr_contains(p.lst("srcaddr"), src):
                continue
            if not self.addr_contains(p.lst("dstaddr"), dst):
                continue
            if not self.svc_matches(p.lst("service"), proto, port):
                continue
            if p.lst("groups") and not (set(p.lst("groups")) & set(user_groups)):
                continue
            return p.get("action"), pid, p.get("name")
        return "deny", "0", "implicit-deny"


def sdwan_pick(fg: FortiGate, rule_name: str, alive: set[int], in_sla: set[int] | None = None):
    """Return the SD-WAN member id a rule would use given alive/in-SLA members."""
    in_sla = alive if in_sla is None else in_sla
    for _, r in fg.sdwan.cfg("service").edits.items():
        if r.get("name") != rule_name:
            continue
        members = [int(x) for x in " ".join(r.lst("priority-members")).split()]
        mode = r.get("mode")
        if mode == "sla":
            for mid in members:
                if mid in alive and mid in in_sla:
                    return mid
            # nothing meets SLA -> FortiOS falls back to first alive member
        for mid in members:
            if mid in alive:
                return mid
        return None
    raise KeyError(rule_name)
