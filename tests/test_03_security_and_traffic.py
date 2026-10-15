"""Hardening checks + end-to-end traffic simulation through the real policy tables."""
import ipaddress

import pytest

INTERNET = "93.184.216.34"
IT_FSSO = "CN=IT-ADMINS,OU=GROUPS,DC=CORP,DC=ACMEDIGITAL,DC=LOCAL"


# --------------------------------------------------------------- hardening
def test_no_admin_access_on_wan(fgs):
    for code, fg in fgs.items():
        for w in ("wan1", "wan2"):
            acc = set(fg.intf[w].lst("allowaccess"))
            assert acc <= {"ping"}, f"{code} {w} exposes {acc}"


def test_admin_access_only_on_mgmt_and_trusted_hosts(fgs, model):
    for s in model.sites:
        fg = fgs[s.code]
        for name, n in fg.intf.items():
            acc = set(n.lst("allowaccess"))
            if acc & {"https", "ssh", "http", "telnet"}:
                assert name == "MGMT", f"{s.code}: admin access on {name}"
        adm = fg.root.cfg("system admin").edits["admin"]
        trusted = [ipaddress.ip_network("/".join(adm.lst(f"trusthost{i}")))
                   for i in range(1, 11) if adm.lst(f"trusthost{i}")]
        assert trusted and all(not t.overlaps(ipaddress.ip_network(f"{INTERNET}/32")) for t in trusted)
        assert all(t.prefixlen >= 16 for t in trusted)


def test_global_hardening(fgs):
    for code, fg in fgs.items():
        g = fg.root.cfg("system global")
        assert g.get("strong-crypto") == "enable"
        assert g.get("ssl-min-proto-version") == "TLSv1-2"
        assert int(g.get("admin-lockout-threshold")) <= 3
        assert int(g.get("admintimeout")) <= 15
        assert int(fg.root.cfg("system password-policy").get("minimum-length")) >= 14
        assert fg.root.cfg("log setting").get("fwpolicy-implicit-log") == "enable"


def test_every_policy_logs_and_internet_policies_are_inspected(fgs):
    no_utm_ok = {"VOICE-to-INTERNET", "IOT-to-NTP"}   # latency-sensitive / NTP only
    for code, fg in fgs.items():
        for pid, p in fg.policies.items():
            assert p.get("logtraffic") == "all", f"{code} {pid}"
            if "UNDERLAY" in p.lst("dstintf") and p.get("name") not in no_utm_ok:
                assert p.get("utm-status") == "enable", f"{code} {p.get('name')} uninspected"
                assert p.get("nat") == "enable"


def test_no_any_any_any_rules(fgs):
    for code, fg in fgs.items():
        for pid, p in fg.policies.items():
            wide = p.lst("srcaddr") == ["all"] and p.lst("dstaddr") == ["all"] and p.lst("service") == ["ALL"]
            assert not wide, f"{code} {p.get('name')} is any/any/any"


def test_isolated_segments_never_reach_overlay(fgs):
    for code, fg in fgs.items():
        for p in fg.policies.values():
            if "OVERLAY" in p.lst("dstintf"):
                assert not set(p.lst("srcintf")) & {"GUEST", "DEVICE_LAB", "CCTV", "PRINT_IOT"}
            if set(p.lst("srcintf")) == {"GUEST"}:
                assert p.lst("dstintf") == ["UNDERLAY"]


def test_guest_wifi_isolation(fgs):
    for code, fg in fgs.items():
        assert fg.vaps["GUEST"].get("intra-vap-privacy") == "enable"
        assert fg.vaps["CORP_WIFI"].get("security") == "wpa3-enterprise"


# --------------------------------------------------------------- simulation
def _bgp(model, s):
    return {str(p.supernet): "OVERLAY" for p in model.peers_of(s)}


def flow(model, fgs, src_code, src, dst, proto, port, user=None, fsso=frozenset()):
    """Walk a packet through the source FortiGate and, if it crosses the overlay,
    the destination FortiGate. Returns (verdict, [(site, policy name), ...])."""
    s = model.site(src_code)
    fg = fgs[src_code]
    groups = fg.user_groups(user, set(fsso)) if (user or fsso) else set()
    sin = fg.src_intf(src)
    dout = fg.route(dst, _bgp(model, s))
    if dout == "BLACKHOLE":
        return "drop", [(src_code, "blackhole")]
    v, _, name = fg.lookup(sin, dout, src, dst, proto, port, groups)
    trail = [(src_code, name)]
    if v != "accept" or dout != "OVERLAY":
        return v, trail
    dst_site = next(x for x in model.sites if ipaddress.ip_address(dst) in x.supernet)
    fg2 = fgs[dst_site.code]
    tun = next(t.side(dst_site)["name"] for t in model.tunnels_of(dst_site)
               if t.side(dst_site)["peer"].code == src_code)
    dout2 = fg2.route(dst, _bgp(model, dst_site))
    v2, _, name2 = fg2.lookup(tun, dout2, src, dst, proto, port)
    trail.append((dst_site.code, name2))
    return v2, trail


def ip(model, code, vlan, host):
    return str(model.site(code).vlan(vlan).net.network_address + host)


def pool_ip(model, code, host=20):
    return str(model.site(code).vpn_pool.network_address + host)


SITES = ["LON", "BEY", "DXB"]

# (description, src-vlan|"VPN", src-host, dst-vlan|INTERNET|"PRIVATE", dst-host, proto, port, user, fsso, expect)
LOCAL_CASES = [
    ("staff browses web",               "STAFF", 60, "INTERNET", 0, "tcp", 443, None, False, "accept"),
    ("staff reaches DC file share",     "STAFF", 60, "SERVERS", 10, "tcp", 445, None, False, "accept"),
    ("staff blocked from server SSH",   "STAFF", 60, "SERVERS", 10, "tcp", 22, None, False, "deny"),
    ("staff blocked from server RDP",   "STAFF", 60, "SERVERS", 10, "tcp", 3389, None, False, "deny"),
    ("staff blocked from dev desktops", "STAFF", 60, "DEV", 60, "tcp", 22, None, False, "deny"),
    ("wifi user logs on to AD",         "CORP_WIFI", 60, "SERVERS", 10, "tcp", 88, None, False, "accept"),
    ("dev SSH to build server",         "DEV", 60, "SERVERS", 20, "tcp", 22, None, False, "accept"),
    ("dev pushes to Git over SSH",      "DEV", 60, "INTERNET", 0, "tcp", 22, None, False, "accept"),
    ("dev debugs phone via adb",        "DEV", 60, "DEVICE_LAB", 60, "tcp", 5555, None, False, "accept"),
    ("guest browses web",               "GUEST", 60, "INTERNET", 0, "tcp", 443, None, False, "accept"),
    ("guest DNS",                       "GUEST", 60, "INTERNET", 0, "udp", 53, None, False, "accept"),
    ("guest cannot send SMTP spam",     "GUEST", 60, "INTERNET", 0, "tcp", 25, None, False, "deny"),
    ("guest cannot touch servers",      "GUEST", 60, "SERVERS", 10, "tcp", 445, None, False, "deny"),
    ("guest cannot reach intranet web", "GUEST", 60, "SERVERS", 30, "tcp", 443, None, False, "deny"),
    ("guest cannot touch staff",        "GUEST", 60, "STAFF", 60, "tcp", 445, None, False, "deny"),
    ("guest cannot reach other office", "GUEST", 60, "REMOTE", 10, "tcp", 445, None, False, "deny"),
    ("test phone hits staging API",     "DEVICE_LAB", 60, "SERVERS", 130, "tcp", 443, None, False, "accept"),
    ("test phone cannot reach DC SMB",  "DEVICE_LAB", 60, "SERVERS", 10, "tcp", 445, None, False, "deny"),
    ("test phone cannot reach staff",   "DEVICE_LAB", 60, "STAFF", 60, "tcp", 443, None, False, "deny"),
    ("test phone reaches app stores",   "DEVICE_LAB", 60, "INTERNET", 0, "tcp", 443, None, False, "accept"),
    ("camera streams to NVR",           "CCTV", 60, "SERVERS", 50, "tcp", 554, None, False, "accept"),
    ("camera cannot reach internet",    "CCTV", 60, "INTERNET", 0, "tcp", 443, None, False, "deny"),
    ("camera cannot reach DC SMB",      "CCTV", 60, "SERVERS", 10, "tcp", 445, None, False, "deny"),
    ("printer syncs time",              "PRINT_IOT", 60, "INTERNET", 0, "udp", 123, None, False, "accept"),
    ("printer cannot phone home",       "PRINT_IOT", 60, "INTERNET", 0, "tcp", 443, None, False, "deny"),
    ("staff prints",                    "STAFF", 60, "PRINT_IOT", 60, "tcp", 9100, None, False, "accept"),
    ("non-IT staff blocked from MGMT",  "STAFF", 60, "MGMT", 5, "tcp", 443, None, False, "deny"),
    ("IT admin (FSSO) manages switch",  "STAFF", 60, "MGMT", 5, "tcp", 443, None, True, "accept"),
    ("VPN staff opens file share",      "VPN", 20, "SERVERS", 10, "tcp", 445, "m.khoury", False, "accept"),
    ("VPN staff blocked from SSH",      "VPN", 20, "SERVERS", 10, "tcp", 22, "m.khoury", False, "deny"),
    ("VPN dev SSH to build server",     "VPN", 20, "SERVERS", 20, "tcp", 22, "r.haddad", False, "accept"),
    ("VPN staff blocked from MGMT",     "VPN", 20, "MGMT", 5, "tcp", 443, "m.khoury", False, "deny"),
    ("VPN IT manages switches",         "VPN", 20, "MGMT", 5, "tcp", 443, "n.saad", False, "accept"),
    ("typo'd private IP never leaks",   "STAFF", 60, "PRIVATE", 0, "tcp", 443, None, False, "drop"),
]


@pytest.mark.parametrize("site", SITES)
@pytest.mark.parametrize("case", LOCAL_CASES, ids=[c[0] for c in LOCAL_CASES])
def test_traffic_matrix(model, fgs, site, case):
    desc, sv, sh, dv, dh, proto, port, user, fsso, expect = case
    src = pool_ip(model, site, sh) if sv == "VPN" else ip(model, site, sv, sh)
    if dv == "INTERNET":
        dst = INTERNET
    elif dv == "PRIVATE":
        dst = "10.99.0.1"
    elif dv == "REMOTE":
        other = next(c for c in SITES if c != site)
        dst = ip(model, other, "SERVERS", dh)
    else:
        dst = ip(model, site, dv, dh)
    verdict, trail = flow(model, fgs, site, src, dst, proto, port, user,
                          {IT_FSSO} if fsso else frozenset())
    assert verdict == expect, f"{site}: {desc}: got {verdict} via {trail}"


CROSS_CASES = [
    ("staff -> remote file share", "STAFF", 60, "SERVERS", 10, "tcp", 445, None, "accept"),
    ("dev -> remote dev box",      "DEV", 60, "DEV", 61, "tcp", 22, None, "accept"),
    ("voice -> remote phone",      "VOICE", 60, "VOICE", 61, "udp", 5060, None, "accept"),
    ("wifi -> remote intranet",    "CORP_WIFI", 60, "SERVERS", 30, "tcp", 443, None, "accept"),
    ("lab -> remote staging",      "DEVICE_LAB", 60, "SERVERS", 130, "tcp", 443, None, "deny"),
    ("cctv -> remote NVR",         "CCTV", 60, "SERVERS", 50, "tcp", 554, None, "deny"),
    ("iot -> remote",              "PRINT_IOT", 60, "SERVERS", 10, "udp", 53, None, "deny"),
    ("anyone -> remote MGMT",      "STAFF", 60, "MGMT", 5, "tcp", 443, None, "deny"),
    ("VPN staff -> remote share",  "VPN", 20, "SERVERS", 10, "tcp", 445, "m.khoury", "accept"),
    ("VPN staff -> remote SSH",    "VPN", 20, "SERVERS", 10, "tcp", 22, "m.khoury", "deny"),
    ("VPN dev -> remote SSH",      "VPN", 20, "SERVERS", 20, "tcp", 22, "r.haddad", "accept"),
]


@pytest.mark.parametrize("pair", [(a, b) for a in SITES for b in SITES if a != b],
                         ids=lambda p: f"{p[0]}->{p[1]}")
@pytest.mark.parametrize("case", CROSS_CASES, ids=[c[0] for c in CROSS_CASES])
def test_inter_office_matrix(model, fgs, pair, case):
    a, b = pair
    desc, sv, sh, dv, dh, proto, port, user, expect = case
    src = pool_ip(model, a, sh) if sv == "VPN" else ip(model, a, sv, sh)
    dst = ip(model, b, dv, dh)
    verdict, trail = flow(model, fgs, a, src, dst, proto, port, user)
    assert verdict == expect, f"{a}->{b}: {desc}: got {verdict} via {trail}"
    if expect == "accept":
        assert len(trail) == 2, "must be permitted by BOTH firewalls"
