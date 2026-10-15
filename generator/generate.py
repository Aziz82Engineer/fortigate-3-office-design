#!/usr/bin/env python3
"""Generate FortiOS 7.6 CLI scripts for every office from inventory/sites.yaml.

Output (configs/):
  <CODE>-fortigate.conf        full day-0 config script, dependency-ordered
  <CODE>-post-ems.conf         apply after FortiClient EMS tags have synced
  <CODE>-fortiswitch-ports.conf apply after FortiSwitches are authorized
Usage:  python3 generator/generate.py                  # demo secrets (safe to publish)
        python3 generator/generate.py --real-secrets   # create/use inventory/secrets.yaml
        python3 generator/generate.py --rotate-secrets # new real secrets
"""
from __future__ import annotations

import ipaddress
import sys
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from model import ROOT, Model, Site, build, demo_mode  # noqa: E402

OUT = ROOT / "configs"

# Built-in FortiOS objects this design relies on (verified against 7.6 defaults).
UTM_FULL = {
    "av-profile": "default", "webfilter-profile": "default",
    "dnsfilter-profile": "default", "ips-sensor": "default",
    "application-list": "default",
}


def q(*vals) -> str:
    return " ".join(f'"{v}"' for v in vals)


def mask(net) -> str:
    net = ipaddress.ip_network(net)
    return f"{net.network_address} {net.netmask}"


class W:
    """Tiny FortiOS CLI writer with correct config/edit/next/end nesting."""

    def __init__(self):
        self.lines: list[str] = []
        self.depth = 0

    def raw(self, s: str):
        self.lines.append("    " * self.depth + s)

    def comment(self, s: str):
        self.lines.append("")
        self.lines.append(f"# ---- {s} ----")

    # Keys whose values are free strings / object references -> quoted, exactly
    # like a FortiOS config backup. Everything else (enums, numbers, IP+mask,
    # space-separated enum lists) stays bare.
    QUOTED = {
        "hostname", "alias", "vdom", "interface", "name", "ssid", "passphrase", "secret",
        "secondary-secret", "password", "password2", "psksecret", "server", "secondary-server",
        "server2", "cnid", "dn", "username", "ca-cert", "radius-server", "schedule",
        "dnsfilter-profile", "av-profile", "webfilter-profile", "ips-sensor", "application-list",
        "ssl-ssh-profile", "ldap-server", "email-to", "phase1name", "comments", "comment",
        "description", "health-check", "zone", "sdwan-zone", "device",
        "update-source", "group-name", "upstream", "server-hostname", "server-name",
        "authusrgrp", "ipv4-split-include", "domain", "vlan", "remote-gw-ztna-tags",
    }

    def set(self, k: str, v):
        if isinstance(v, (list, tuple)):
            v = q(*v)
        elif isinstance(v, str) and k in self.QUOTED:
            v = f'"{v}"'
        self.raw(f"set {k} {v}")

    @contextmanager
    def config(self, path: str):
        self.raw(f"config {path}")
        self.depth += 1
        yield
        self.depth -= 1
        self.raw("end")

    @contextmanager
    def edit(self, key):
        self.raw(f'edit {key}' if isinstance(key, int) else f'edit "{key}"')
        self.depth += 1
        yield
        self.depth -= 1
        self.raw("next")

    def text(self) -> str:
        return "\n".join(self.lines).lstrip("\n") + "\n"


def addr_name(site_code: str, what: str) -> str:
    return f"{site_code}_{what}"


# --------------------------------------------------------------------------- #
#                               main builder                                  #
# --------------------------------------------------------------------------- #
def build_site(m: Model, s: Site) -> str:
    g, sec = m.g, m.secrets
    w = W()
    peers = m.peers_of(s)
    tunnels = [t.side(s) for t in m.tunnels_of(s)]
    beirut = m.site("BEY")
    ssids = [v for v in s.vlans if v.type == "ssid"]
    wired = [v for v in s.vlans if v.type == "vlan"]
    corp_local = [v for v in s.vlans if v.cross_site]

    w.lines += [
        f"# {g['company']} - {s.name} ({s.code}) FortiGate {s.model}"
        f"{' A-P HA cluster' if s.ha else ''}",
        f"# Target FortiOS {g['fortios_target']} - GENERATED from inventory/sites.yaml, do not hand-edit.",
        "# Prerequisites (see design doc 'Deployment runbook'):",
        "#   1. FortiGate registered in FortiCloud, licensed (UTP), firmware upgraded, factory-reset.",
        "#   2. wan1/wan2 removed from the default SD-WAN zone and from any default policy.",
        "#   3. Corporate root CA imported as 'CORP-ROOT-CA' (System > Certificates) for LDAPS.",
        "#   4. Apply via FortiManager CLI script or System > Settings > Configuration scripts.",
    ]
    if demo_mode():
        w.lines += ["#",
                    "# !!! DEMO SECRETS: every key/password below starts with 'DEMO' and is public.",
                    "# !!! Run 'python3 generator/generate.py --real-secrets' before deploying."]

    # ---------------- system ----------------
    w.comment("System, admin hardening, DNS, NTP")
    with w.config("system global"):
        w.set("hostname", f"FGT-{s.code}-01")
        w.set("admin-sport", 8443)            # frees 443 for IKE-over-TCP
        w.set("admin-ssh-port", 22)
        w.set("admintimeout", 15)
        w.set("admin-lockout-threshold", 3)
        w.set("admin-lockout-duration", 900)
        w.set("strong-crypto", "enable")
        w.set("ssl-min-proto-version", "TLSv1-2")
        w.set("admin-https-redirect", "enable")
        w.set("gui-firmware-upgrade-warning", "enable")
    with w.config("system settings"):
        w.set("ike-tcp-port", g["remote_access"]["ike_tcp_port"])
        w.set("gui-multiple-interface-policy", "enable")
    with w.config("system dns"):
        w.set("primary", g["public_dns"][0])
        w.set("secondary", g["public_dns"][1])
        w.set("protocol", "dot")
        w.set("server-hostname", "globalsdns.fortinet.net")
    with w.config("system password-policy"):
        w.set("status", "enable")
        w.set("minimum-length", 14)
        w.set("min-upper-case-letter", 1)
        w.set("min-lower-case-letter", 1)
        w.set("min-number", 1)
        w.set("min-non-alphanumeric", 1)
        w.set("expire-status", "disable")

    # ---------------- interfaces ----------------
    w.comment("WAN, loopback, FortiLink and VLAN interfaces")
    with w.config("system interface"):
        for wn in ("wan1", "wan2"):
            wd = s.wan[wn]
            with w.edit(wn):
                w.set("mode", "static")
                w.set("ip", f"{s.wan_ip(wn)} {ipaddress.ip_interface(wd['ip']).netmask}")
                w.set("allowaccess", "ping")
                w.set("role", "wan")
                w.set("alias", wd["isp"][:25])
                w.set("estimated-upstream-bandwidth", wd["bw_mbps"] * 1000)
                w.set("estimated-downstream-bandwidth", wd["bw_mbps"] * 1000)
        with w.edit("Lo-BGP"):
            w.set("vdom", "root")
            w.set("type", "loopback")
            w.set("ip", f"{s.loopback} 255.255.255.255")
            w.set("allowaccess", "ping fabric")
            w.set("role", "lan")
        with w.edit("fortilink"):
            w.set("ip", f"{s.fortilink_net.network_address + 1} {s.fortilink_net.netmask}")
            w.set("allowaccess", "ping fabric")
            w.set("fortilink", "enable")
            w.set("member", s.fortilink_ports)
        for v in wired:
            with w.edit(v.name):
                w.set("vdom", "root")
                w.set("interface", "fortilink")
                w.set("vlanid", v.id)
                w.set("ip", f"{v.gw} {v.net.netmask}")
                if v.name == "MGMT":
                    w.set("allowaccess", "ping https ssh snmp capwap fabric")
                else:
                    w.set("allowaccess", "ping")
                w.set("role", "lan")
                w.set("device-identification", "enable")
                w.set("alias", v.desc[:25])

    # ---------------- wireless (tunnel-mode SSIDs) ----------------
    w.comment("Wi-Fi: tunnel-mode SSIDs on FortiAP (corp = WPA3-Enterprise/802.1X via NPS)")
    with w.config("user radius"):
        with w.edit("AD-NPS"):
            w.set("server", s.dc_ips[0])
            w.set("secret", sec["radius_secret"])
            if len(s.dc_ips) > 1:
                w.set("secondary-server", s.dc_ips[1])
                w.set("secondary-secret", sec["radius_secret"])
            else:
                w.set("secondary-server", beirut.dc_ips[0])
                w.set("secondary-secret", sec["radius_secret"])
    with w.config("wireless-controller vap"):
        for v in ssids:
            with w.edit(v.name):
                w.set("ssid", v.ssid)
                if v.name == "GUEST":
                    w.set("security", "wpa2-only-personal")
                    w.set("passphrase", sec["guest_wifi_psk"])
                    w.set("intra-vap-privacy", "enable")
                else:
                    w.set("security", "wpa3-enterprise")
                    w.set("auth", "radius")
                    w.set("radius-server", "AD-NPS")
                w.set("schedule", "always")
    with w.config("system interface"):
        for v in ssids:
            with w.edit(v.name):
                w.set("ip", f"{v.gw} {v.net.netmask}")
                w.set("allowaccess", "ping")
                w.set("role", "lan")
                w.set("device-identification", "enable")

    w.comment("NTP server for internal segments (FortiGuard-synced)")
    with w.config("system ntp"):
        w.set("ntpsync", "enable")
        w.set("type", "fortiguard")
        w.set("server-mode", "enable")
        w.set("interface", [v.name for v in s.vlans if v.name not in ("GUEST",)])

    # ---------------- DNS server for isolated segments ----------------
    w.comment("FortiGate as DNS for isolated segments (with DNS filtering)")
    with w.config("system dns-server"):
        for name in ("GUEST", "DEVICE_LAB", "PRINT_IOT", "CCTV"):
            with w.edit(name):
                w.set("mode", "recursive")
                w.set("dnsfilter-profile", "default")

    # ---------------- DHCP ----------------
    w.comment("DHCP scopes")
    corp_dns = s.dc_ips[:2] + ([beirut.dc_ips[0]] if s.code != "BEY" else [])
    with w.config("system dhcp server"):
        idx = 1
        for v in s.vlans:
            if not v.dhcp:
                continue
            with w.edit(idx):
                w.set("interface", v.name)
                w.set("default-gateway", str(v.gw))
                w.set("netmask", str(v.net.netmask))
                if v.cross_site or v.name == "MGMT":
                    w.set("dns-service", "specify")
                    for n, ip in enumerate(corp_dns[:3], 1):
                        w.set(f"dns-server{n}", ip)
                    w.set("domain", g["domain"])
                else:
                    w.set("dns-service", "local")
                w.set("ntp-service", "local")
                w.set("lease-time", 3600 if v.name == "GUEST" else 28800)
                lo, hi = v.dhcp_range()
                with w.config("ip-range"):
                    with w.edit(1):
                        w.set("start-ip", str(lo))
                        w.set("end-ip", str(hi))
            idx += 1

    # ---------------- HA ----------------
    if s.ha:
        w.comment("HA active-passive (secondary unit: same config, priority 100)")
        with w.config("system ha"):
            w.set("group-id", s.id * 10)
            w.set("group-name", f"{s.code}-HA")
            w.set("mode", "a-p")
            w.set("password", sec["ha_password"])
            w.set("hbdev", f'"{s.ha_hbdev[0]}" 50 "{s.ha_hbdev[1]}" 50')
            w.set("session-pickup", "enable")
            w.set("session-pickup-connectionless", "enable")
            w.set("ha-mgmt-status", "disable")
            w.set("override", "disable")
            w.set("priority", 200)
            w.set("monitor", ["wan1", "wan2"])

    # ---------------- addresses ----------------
    w.comment("Address objects (identical on all sites - FortiManager can make them global)")
    with w.config("firewall address"):
        for site in m.sites:
            for v in site.vlans:
                with w.edit(addr_name(site.code, v.name)):
                    w.set("subnet", mask(v.net))
            with w.edit(addr_name(site.code, "NET")):
                w.set("subnet", mask(site.supernet))
            with w.edit(addr_name(site.code, "LO")):
                w.set("subnet", f"{site.loopback} 255.255.255.255")
            with w.edit(addr_name(site.code, "VPN_POOL")):
                w.set("subnet", mask(site.vpn_pool))
            for n, ip in enumerate(site.dc_ips, 1):
                with w.edit(addr_name(site.code, f"DC{n}")):
                    w.set("subnet", f"{ip} 255.255.255.255")
            with w.edit(addr_name(site.code, "NVR")):
                w.set("subnet", f"{site.vlan('SERVERS').net.network_address + 50} 255.255.255.255")
            with w.edit(addr_name(site.code, "STAGING")):
                w.set("subnet", f"{site.vlan('SERVERS').net.network_address + 128} 255.255.255.192")
        with w.edit("OVERLAY_TUNNELS"):
            w.set("subnet", mask(g["overlay_supernet"]))
        with w.edit("LOOPBACKS"):
            w.set("subnet", mask(g["loopback_supernet"]))
    with w.config("firewall addrgrp"):
        with w.edit("LOCAL_CORP"):
            w.set("member", [addr_name(s.code, v.name) for v in corp_local]
                  + [addr_name(s.code, "VPN_POOL")])
        with w.edit("REMOTE_CORP"):
            w.set("member", [addr_name(p.code, v.name) for p in peers for v in p.vlans if v.cross_site]
                  + [addr_name(p.code, "VPN_POOL") for p in peers])
        with w.edit("REMOTE_NETS"):
            w.set("member", [addr_name(p.code, "NET") for p in peers])
        with w.edit("VPN_SPLIT"):
            w.set("member", [addr_name(x.code, "NET") for x in m.sites])
        with w.edit("ALL_DCS"):
            w.set("member", [addr_name(x.code, f"DC{n}") for x in m.sites
                             for n in range(1, len(x.dc_ips) + 1)])
        with w.edit("USER_SEGMENTS"):
            w.set("member", [addr_name(s.code, n) for n in ("STAFF", "DEV", "CORP_WIFI")])

    # ---------------- services ----------------
    w.comment("Custom services")
    with w.config("firewall service custom"):
        with w.edit("AD-EXTRA"):
            w.set("tcp-portrange", "464 636 3268-3269 49152-65535")
            w.set("udp-portrange", "464")
        with w.edit("PRINTING"):
            w.set("tcp-portrange", "515 631 9100")
        with w.edit("FABRIC-8013"):
            w.set("tcp-portrange", "8013")
    with w.config("firewall service group"):
        with w.edit("SVC-AD"):
            w.set("member", ["DNS", "KERBEROS", "LDAP", "LDAP_UDP", "SMB", "NTP",
                             "DCE-RPC", "AD-EXTRA"])
        with w.edit("SVC-STAFF-SERVERS"):
            w.set("member", ["SVC-AD", "HTTP", "HTTPS", "PING"])
        with w.edit("SVC-MGMT"):
            w.set("member", ["HTTPS", "SSH", "PING", "SNMP"])
        with w.edit("SVC-WEB"):
            w.set("member", ["HTTP", "HTTPS", "DNS", "NTP", "PING"])

    # ---------------- identity ----------------
    w.comment("Identity: AD over LDAPS, FSSO, FortiIdentity Cloud MFA for VPN users")
    local_dc = s.dc_ips[0]
    second_dc = s.dc_ips[1] if len(s.dc_ips) > 1 else beirut.dc_ips[0]
    with w.config("user ldap"):
        with w.edit("AD-LDAP"):
            w.set("server", local_dc)
            w.set("secondary-server", second_dc)
            w.set("cnid", "sAMAccountName")
            w.set("dn", g["ldap_base_dn"])
            w.set("type", "regular")
            w.set("username", g["ldap_bind_dn"])
            w.set("password", sec["ldap_bind_password"])
            w.set("secure", "ldaps")
            w.set("port", 636)
            w.set("ca-cert", "CORP-ROOT-CA")
    with w.config("user fsso"):
        with w.edit("FSSO-CA"):
            w.set("server", beirut.dc_ips[0])
            w.set("password", sec["fsso_password"])
            w.set("server2", beirut.dc_ips[1])
            w.set("password2", sec["fsso_password"])
    it_dn = f"CN=IT-ADMINS,OU=Groups,{g['ldap_base_dn']}".upper()
    with w.config("user adgrp"):
        with w.edit(it_dn):
            w.set("server-name", "FSSO-CA")
    with w.config("user local"):
        for u in m.users:
            with w.edit(u["username"]):
                w.set("type", "ldap")
                w.set("ldap-server", "AD-LDAP")
                w.set("two-factor", "fortitoken-cloud")
                w.set("email-to", u["email"])
                w.set("status", "enable")
    roles = ("Staff", "Developers", "IT")
    with w.config("user group"):
        for r in roles:
            with w.edit(f"VPN-{r}"):
                w.set("member", [u["username"] for u in m.users if u["role"] == r] or ["guest"])
        with w.edit("VPN-ALL"):
            w.set("member", [f"VPN-{r}" for r in roles])
        with w.edit("FSSO-IT-Admins"):
            w.set("group-type", "fsso-service")
            w.set("member", it_dn)

    # ---------------- site-to-site IPsec ----------------
    w.comment("Site-to-site IPsec full mesh: 4 tunnels per peer (every ISP x every ISP)")
    with w.config("vpn ipsec phase1-interface"):
        for t, side in zip(m.tunnels_of(s), tunnels):
            with w.edit(side["name"]):
                w.set("interface", side["local_wan"])
                w.set("ike-version", 2)
                w.set("peertype", "any")
                w.set("net-device", "disable")
                w.set("proposal", "aes256gcm-prfsha384 aes256-sha256")
                w.set("dhgrp", "21 20")
                w.set("remote-gw", side["peer"].wan_ip(side["peer_wan"]))
                w.set("psksecret", t.psk)
                w.set("dpd", "on-idle")
                w.set("dpd-retryinterval", 5)
                w.set("auto-discovery-sender", "disable")
                w.set("keylife", 28800)
                w.set("comments", f"to {side['peer'].name} {side['peer_wan']} via local {side['local_wan']}")
    with w.config("vpn ipsec phase2-interface"):
        for side in tunnels:
            with w.edit(side["name"]):
                w.set("phase1name", side["name"])
                w.set("proposal", "aes256gcm aes256-sha256")
                w.set("dhgrp", "21 20")
                w.set("auto-negotiate", "enable")
                w.set("keylifeseconds", 3600)
    with w.config("system interface"):
        for side in tunnels:
            with w.edit(side["name"]):
                w.set("ip", f"{side['ip']} 255.255.255.255")
                w.set("remote-ip", f"{side['remote_ip']} 255.255.255.252")
                w.set("allowaccess", "ping")

    # ---------------- remote access ----------------
    ra = g["remote_access"]
    pool = list(s.vpn_pool.hosts())
    ra_ranges = {"RA-VPN1": ("wan1", pool[9], pool[127]),    # .10 - .128
                 "RA-VPN2": ("wan2", pool[129], pool[249])}  # .130 - .250
    w.comment("Remote access: FortiClient IKEv2 dial-up, EAP-TTLS to AD + FortiToken (no SSL VPN)")
    with w.config("vpn ipsec phase1-interface"):
        for name, (wan, lo, hi) in ra_ranges.items():
            with w.edit(name):
                w.set("type", "dynamic")
                w.set("interface", wan)
                w.set("ike-version", ra["ike_version"])
                w.set("peertype", "any")
                w.set("net-device", "disable")
                w.set("mode-cfg", "enable")
                w.set("proposal", "aes256gcm-prfsha384 aes256-sha256")
                w.set("dhgrp", "21 20")
                w.set("eap", "enable")
                w.set("eap-identity", "send-request")
                w.set("authusrgrp", "VPN-ALL")
                w.set("transport", ra["transport"])
                w.set("ipv4-start-ip", str(lo))
                w.set("ipv4-end-ip", str(hi))
                w.set("ipv4-netmask", str(s.vpn_pool.netmask))
                w.set("dns-mode", "manual")
                w.set("ipv4-dns-server1", corp_dns[0])
                w.set("ipv4-dns-server2", corp_dns[1])
                w.set("ipv4-split-include", "VPN_SPLIT")
                w.set("client-auto-negotiate", "enable")
                w.set("client-keep-alive", "enable")
                w.set("dpd", "on-idle")
                w.set("dpd-retryinterval", 60)
                w.set("psksecret", sec[f"ravpn_psk_{s.code}"])
                w.set("comments", f"FortiClient remote access via {wan}")
    with w.config("vpn ipsec phase2-interface"):
        for name in ra_ranges:
            with w.edit(name):
                w.set("phase1name", name)
                w.set("proposal", "aes256gcm aes256-sha256")
                w.set("dhgrp", "21 20")
    with w.config("system zone"):
        with w.edit("RA_VPN"):
            w.set("interface", list(ra_ranges))
            w.set("intrazone", "deny")

    # ---------------- SD-WAN ----------------
    w.comment("SD-WAN: UNDERLAY (2 ISPs) + OVERLAY (8 tunnels), SLA-driven steering")
    member_ids: dict[str, int] = {"wan1": 1, "wan2": 2}
    for pi, p in enumerate(peers):
        for side in tunnels:
            if side["peer"].code == p.code:
                combo = side["name"][-2:]
                member_ids[side["name"]] = 100 + pi * 10 + {"11": 1, "22": 2, "12": 3, "21": 4}[combo]
    with w.config("system sdwan"):
        w.set("status", "enable")
        w.set("load-balance-mode", "source-ip-based")
        with w.config("zone"):
            for z in ("UNDERLAY", "OVERLAY"):
                with w.edit(z):
                    pass
        with w.config("members"):
            for wn in ("wan1", "wan2"):
                with w.edit(member_ids[wn]):
                    w.set("interface", wn)
                    w.set("zone", "UNDERLAY")
                    w.set("gateway", s.wan[wn]["gw"])
                    w.set("priority", 1 if wn == "wan1" else 10)
            for side in tunnels:
                with w.edit(member_ids[side["name"]]):
                    w.set("interface", side["name"])
                    w.set("zone", "OVERLAY")
                    w.set("priority", 1)
        with w.config("health-check"):
            with w.edit("INET"):
                w.set("server", g["internet_sla_targets"])
                w.set("protocol", "ping")
                w.set("interval", 1000)
                w.set("failtime", 5)
                w.set("recoverytime", 10)
                w.set("members", "1 2")
                w.set("update-static-route", "enable")
                with w.config("sla"):
                    with w.edit(1):
                        w.set("latency-threshold", 250)
                        w.set("jitter-threshold", 50)
                        w.set("packetloss-threshold", 5)
                    with w.edit(2):
                        w.set("latency-threshold", 150)
                        w.set("jitter-threshold", 30)
                        w.set("packetloss-threshold", 1)
            for p in peers:
                mids = [member_ids[sd["name"]] for sd in tunnels if sd["peer"].code == p.code]
                with w.edit(f"HC_{p.code}"):
                    w.set("server", str(p.loopback))
                    w.set("protocol", "ping")
                    w.set("interval", 1000)
                    w.set("failtime", 5)
                    w.set("recoverytime", 10)
                    w.set("members", " ".join(map(str, sorted(mids))))
                    w.set("update-static-route", "enable")
                    with w.config("sla"):
                        with w.edit(1):
                            w.set("latency-threshold", 200)
                            w.set("jitter-threshold", 50)
                            w.set("packetloss-threshold", 2)
        with w.config("service"):
            sid = 1
            for p in peers:
                mids = {sd["name"][-2:]: member_ids[sd["name"]] for sd in tunnels
                        if sd["peer"].code == p.code}
                order = " ".join(str(mids[c]) for c in ("11", "22", "12", "21"))
                with w.edit(sid):
                    w.set("name", f"VOICE-{p.code}")
                    w.set("mode", "priority")
                    w.set("link-cost-factor", "latency")
                    w.set("src", [addr_name(s.code, "VOICE")])
                    w.set("dst", [addr_name(p.code, "NET")])
                    w.set("health-check", f"HC_{p.code}")
                    w.set("priority-members", order)
                sid += 1
                with w.edit(sid):
                    w.set("name", f"CORP-{p.code}")
                    w.set("mode", "sla")
                    w.set("dst", [addr_name(p.code, "NET")])
                    w.set("src", ["all"])
                    with w.config("sla"):
                        with w.edit(f"HC_{p.code}"):
                            w.set("id", 1)
                    w.set("priority-members", order)
                sid += 1
            with w.edit(sid):
                w.set("name", "VOICE-INET")
                w.set("mode", "priority")
                w.set("link-cost-factor", "latency")
                w.set("src", [addr_name(s.code, "VOICE")])
                w.set("dst", ["all"])
                w.set("health-check", "INET")
                w.set("priority-members", "1 2")
            sid += 1
            with w.edit(sid):
                w.set("name", "GUEST-INET")
                w.set("mode", "manual")
                w.set("src", [addr_name(s.code, "GUEST")])
                w.set("dst", ["all"])
                w.set("priority-members", "2 1")

    # ---------------- routing ----------------
    w.comment("Static routing: default via UNDERLAY, peer loopbacks via tunnels, RFC1918 blackholes")
    with w.config("router static"):
        rid = 1
        with w.edit(rid):
            w.set("sdwan-zone", "UNDERLAY")
            w.set("comment", "default route - SD-WAN underlay")
        for side in tunnels:
            rid += 1
            with w.edit(rid):
                w.set("dst", f"{side['peer'].loopback} 255.255.255.255")
                w.set("device", side["name"])
                w.set("comment", f"{side['peer'].code} loopback")
        for net in (str(s.supernet), "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
            rid += 1
            with w.edit(rid):
                w.set("dst", mask(net))
                w.set("blackhole", "enable")
                w.set("distance", 254)
                w.set("comment", "never leak private ranges to the internet")
    w.comment("iBGP full mesh between loopbacks (AS %s)" % g["bgp_as"])
    with w.config("router bgp"):
        w.set("as", g["bgp_as"])
        w.set("router-id", str(s.loopback))
        w.set("ibgp-multipath", "enable")
        w.set("graceful-restart", "enable")
        with w.config("neighbor"):
            for p in peers:
                with w.edit(str(p.loopback)):
                    w.set("remote-as", g["bgp_as"])
                    w.set("update-source", "Lo-BGP")
                    w.set("soft-reconfiguration", "enable")
                    w.set("advertisement-interval", 1)
                    w.set("connect-timer", 10)
                    w.set("password", sec["bgp_password"])
                    w.set("description", f"{p.name}")
        with w.config("network"):
            with w.edit(1):
                w.set("prefix", mask(s.supernet))

    # ---------------- policies ----------------
    w.comment("Firewall policies (first match wins; implicit deny + log at the end)")
    pols = []

    def pol(name, src, dst, sa, da, svc, nat=False, utm=None, ssl=None, groups=None, action="accept"):
        pols.append(dict(name=name, srcintf=src, dstintf=dst, srcaddr=sa, dstaddr=da,
                         service=svc, nat=nat, utm=utm, ssl=ssl, groups=groups, action=action))

    C = s.code
    # overlay control plane first
    pol("OVERLAY-to-LOOPBACK", ["OVERLAY"], ["Lo-BGP"], ["LOOPBACKS", "OVERLAY_TUNNELS"],
        [addr_name(C, "LO")], ["BGP", "PING", "FABRIC-8013"])
    # internet
    pol("STAFF-to-INTERNET", ["STAFF", "CORP_WIFI"], ["UNDERLAY"],
        [addr_name(C, "STAFF"), addr_name(C, "CORP_WIFI")], ["all"], ["ALL"],
        nat=True, utm=UTM_FULL, ssl="deep-inspection")
    pol("DEV-to-INTERNET", ["DEV"], ["UNDERLAY"], [addr_name(C, "DEV")], ["all"], ["ALL"],
        nat=True, utm=UTM_FULL, ssl="certificate-inspection")
    pol("SERVERS-to-INTERNET", ["SERVERS"], ["UNDERLAY"], [addr_name(C, "SERVERS")], ["all"], ["ALL"],
        nat=True, utm={"av-profile": "default", "ips-sensor": "default",
                       "application-list": "default"}, ssl="certificate-inspection")
    pol("VOICE-to-INTERNET", ["VOICE"], ["UNDERLAY"], [addr_name(C, "VOICE")], ["all"], ["ALL"], nat=True)
    pol("GUEST-to-INTERNET", ["GUEST"], ["UNDERLAY"], [addr_name(C, "GUEST")], ["all"], ["SVC-WEB"],
        nat=True, utm={"webfilter-profile": "default", "dnsfilter-profile": "default",
                       "application-list": "block-high-risk", "av-profile": "default"},
        ssl="certificate-inspection")
    pol("LAB-to-INTERNET", ["DEVICE_LAB"], ["UNDERLAY"], [addr_name(C, "DEVICE_LAB")], ["all"], ["ALL"],
        nat=True, utm=UTM_FULL, ssl="certificate-inspection")
    pol("MGMT-to-INTERNET", ["MGMT"], ["UNDERLAY"], [addr_name(C, "MGMT")], ["all"], ["SVC-WEB"],
        nat=True, utm={"ips-sensor": "default"}, ssl="certificate-inspection")
    pol("IOT-to-NTP", ["PRINT_IOT"], ["UNDERLAY"], [addr_name(C, "PRINT_IOT")], ["all"], ["NTP"], nat=True)
    # intra-site
    ips_only = {"ips-sensor": "default"}
    pol("USERS-to-SERVERS", ["STAFF", "CORP_WIFI"], ["SERVERS"],
        [addr_name(C, "STAFF"), addr_name(C, "CORP_WIFI")], [addr_name(C, "SERVERS")],
        ["SVC-STAFF-SERVERS"], utm=ips_only, ssl="certificate-inspection")
    pol("DEV-to-SERVERS", ["DEV"], ["SERVERS"], [addr_name(C, "DEV")], [addr_name(C, "SERVERS")],
        ["ALL"], utm=ips_only, ssl="certificate-inspection")
    pol("USERS-to-PRINT", ["STAFF", "DEV", "CORP_WIFI"], ["PRINT_IOT"], ["USER_SEGMENTS"],
        [addr_name(C, "PRINT_IOT")], ["PRINTING", "HTTP", "HTTPS", "PING"])
    pol("LAB-to-STAGING", ["DEVICE_LAB"], ["SERVERS"], [addr_name(C, "DEVICE_LAB")],
        [addr_name(C, "STAGING")], ["HTTP", "HTTPS"], utm=ips_only, ssl="certificate-inspection")
    pol("LAB-DNS-NTP-to-DC", ["DEVICE_LAB", "PRINT_IOT", "CCTV", "MGMT"], ["SERVERS"],
        [addr_name(C, n) for n in ("DEVICE_LAB", "PRINT_IOT", "CCTV", "MGMT")], ["ALL_DCS"], ["DNS", "NTP"])
    pol("CCTV-to-NVR", ["CCTV"], ["SERVERS"], [addr_name(C, "CCTV")], [addr_name(C, "NVR")], ["ALL"])
    pol("DEV-to-LAB", ["DEV"], ["DEVICE_LAB"], [addr_name(C, "DEV")], [addr_name(C, "DEVICE_LAB")], ["ALL"])
    pol("SERVERS-to-CLIENTS", ["SERVERS"], ["STAFF", "DEV", "CORP_WIFI", "VOICE"],
        [addr_name(C, "SERVERS")], ["USER_SEGMENTS", addr_name(C, "VOICE")], ["ALL"])
    pol("VOICE-local", ["VOICE"], ["SERVERS"], [addr_name(C, "VOICE")], [addr_name(C, "SERVERS")], ["ALL"])
    pol("IT-to-MGMT", ["STAFF", "DEV", "CORP_WIFI"], ["MGMT"], ["USER_SEGMENTS"], [addr_name(C, "MGMT")],
        ["SVC-MGMT"], groups=["FSSO-IT-Admins"])
    # remote access
    pol("VPN-ALL-to-SERVERS", ["RA_VPN"], ["SERVERS"], [addr_name(C, "VPN_POOL")], [addr_name(C, "SERVERS")],
        ["SVC-STAFF-SERVERS"], utm=ips_only, ssl="certificate-inspection", groups=["VPN-ALL"])
    pol("VPN-DEV-to-DEV-SERVERS", ["RA_VPN"], ["SERVERS", "DEV", "DEVICE_LAB"], [addr_name(C, "VPN_POOL")],
        [addr_name(C, "SERVERS"), addr_name(C, "DEV"), addr_name(C, "DEVICE_LAB")], ["ALL"],
        utm=ips_only, ssl="certificate-inspection", groups=["VPN-Developers", "VPN-IT"])
    pol("VPN-IT-to-MGMT", ["RA_VPN"], ["MGMT"], [addr_name(C, "VPN_POOL")], [addr_name(C, "MGMT")],
        ["SVC-MGMT"], groups=["VPN-IT"])
    pol("VPN-to-REMOTE-SITES", ["RA_VPN"], ["OVERLAY"], [addr_name(C, "VPN_POOL")], ["REMOTE_CORP"],
        ["SVC-STAFF-SERVERS"], utm=ips_only, ssl="certificate-inspection", groups=["VPN-ALL"])
    pol("VPN-DEV-to-REMOTE-SITES", ["RA_VPN"], ["OVERLAY"], [addr_name(C, "VPN_POOL")], ["REMOTE_CORP"],
        ["ALL"], utm=ips_only, ssl="certificate-inspection", groups=["VPN-Developers", "VPN-IT"])
    # inter-site
    corp_ifs = [v.name for v in corp_local]
    pol("SITE-to-SITE-out", corp_ifs, ["OVERLAY"], ["LOCAL_CORP"], ["REMOTE_CORP"], ["ALL"],
        utm=ips_only, ssl="certificate-inspection")
    pol("SITE-to-SITE-in", ["OVERLAY"], corp_ifs + ["RA_VPN"], ["REMOTE_CORP"], ["LOCAL_CORP"], ["ALL"],
        utm=ips_only, ssl="certificate-inspection")

    with w.config("firewall policy"):
        for i, p in enumerate(pols, 1):
            with w.edit(i):
                w.set("name", p["name"])
                w.set("srcintf", p["srcintf"])
                w.set("dstintf", p["dstintf"])
                w.set("action", p["action"])
                w.set("srcaddr", p["srcaddr"])
                w.set("dstaddr", p["dstaddr"])
                w.set("schedule", "always")
                w.set("service", p["service"])
                if p["groups"]:
                    w.set("groups", p["groups"])
                if p["utm"]:
                    w.set("utm-status", "enable")
                    w.set("ssl-ssh-profile", p["ssl"])
                    for k, v in p["utm"].items():
                        w.set(k, v)
                w.set("logtraffic", "all")
                if p["nat"]:
                    w.set("nat", "enable")
    with w.config("log setting"):
        w.set("fwpolicy-implicit-log", "enable")
        w.set("local-in-allow", "disable")
        w.set("local-in-deny-unicast", "enable")

    # ---------------- fabric / management / logging ----------------
    w.comment("Security Fabric (root = Beirut), FortiManager Cloud, FortiAnalyzer Cloud, EMS Cloud")
    with w.config("system csf"):
        w.set("status", "enable")
        w.set("group-name", f"{g['company'].upper().replace(' ', '-')}-FABRIC")
        if s.code != "BEY":
            w.set("upstream", str(beirut.loopback))
    with w.config("system central-management"):
        w.set("type", "fortiguard")
    with w.config("log fortianalyzer-cloud setting"):
        w.set("status", "enable")
    with w.config("endpoint-control fctems"):
        with w.edit(1):
            w.set("status", "enable")
            w.set("name", "EMS-Cloud")
            w.set("fortinetone-cloud-authentication", "enable")
    with w.config("system admin"):
        with w.edit("admin"):
            hosts = [m.site(x.code).vlan("MGMT").net for x in m.sites] + [x.vpn_pool for x in m.sites]
            for n, h in enumerate(hosts, 1):
                w.set(f"trusthost{n}", mask(h))
    return w.text()


def build_post_ems(m: Model, s: Site) -> str:
    w = W()
    w.lines += [f"# {s.code}: apply AFTER FortiClient EMS is connected and ZTNA tags are synced.",
                "# Blocks VPN for any endpoint that is not EMS-registered and compliant."]
    tag = m.g["remote_access"]["posture_tag"]
    with w.config("vpn ipsec phase1-interface"):
        for name in ("RA-VPN1", "RA-VPN2"):
            with w.edit(name):
                w.set("remote-gw-match", "ztna")
                w.set("remote-gw-ztna-tags", tag)
    return w.text()


def build_switchports(m: Model, s: Site) -> str:
    """Port plan for the first 48-port FortiSwitch of each site (template)."""
    w = W()
    w.lines += [f"# {s.code}: apply after the FortiSwitch is authorized on FortiLink.",
                "# Replace the serial; adjust ranges to the real patch-panel plan."]
    plan = ([("STAFF", ["VOICE"])] * 20 + [("DEV", ["VOICE"])] * 16 + [("PRINT_IOT", [])] * 4
            + [("MGMT", [])] * 4 + [("CCTV", [])] * 2 + [("DEVICE_LAB", [])] + [("SERVERS", [])])
    with w.config("switch-controller managed-switch"):
        with w.edit(f"S148F-{s.code}-SERIAL-01"):
            with w.config("ports"):
                for i, (native, allowed) in enumerate(plan, 1):
                    with w.edit(f"port{i}"):
                        w.set("vlan", native)
                        if allowed:
                            w.set("allowed-vlans", allowed)
                        if native in ("STAFF", "DEV"):
                            w.set("stp-bpdu-guard", "enable")
                            w.set("edge-port", "enable")
                        w.set("description", f"{native}")
    return w.text()


def main(argv: list[str]) -> None:
    m = build(rotate_secrets="--rotate-secrets" in argv, real_secrets="--real-secrets" in argv)
    OUT.mkdir(exist_ok=True)
    for s in m.sites:
        (OUT / f"{s.code}-fortigate.conf").write_text(build_site(m, s))
        (OUT / f"{s.code}-post-ems.conf").write_text(build_post_ems(m, s))
        (OUT / f"{s.code}-fortiswitch-ports.conf").write_text(build_switchports(m, s))
    if demo_mode():
        print("NOTE: demo secrets in use - run with --real-secrets before deploying")
    print(f"generated configs for {', '.join(s.code for s in m.sites)} -> {OUT}")


if __name__ == "__main__":
    main(sys.argv[1:])
