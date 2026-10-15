"""IP plan, site-to-site IPsec symmetry, BGP, remote access."""
import ipaddress
import itertools


def _all_networks(model):
    nets = []
    for s in model.sites:
        nets += [(f"{s.code}/{v.name}", v.net) for v in s.vlans]
        nets += [(f"{s.code}/VPN_POOL", s.vpn_pool), (f"{s.code}/FORTILINK", s.fortilink_net),
                 (f"{s.code}/LO", ipaddress.ip_network(f"{s.loopback}/32"))]
        for wn in ("wan1", "wan2"):
            nets.append((f"{s.code}/{wn}", ipaddress.ip_interface(s.wan[wn]["ip"]).network))
    nets += [(f"tunnel {t.a_name}<->{t.b_name}", t.net) for t in model.tunnels]
    return nets


def test_no_overlapping_subnets_anywhere(model):
    nets = _all_networks(model)
    for (n1, a), (n2, b) in itertools.combinations(nets, 2):
        assert not a.overlaps(b), f"{n1} {a} overlaps {n2} {b}"


def test_site_subnets_sit_inside_their_summary(model):
    for s in model.sites:
        for v in s.vlans:
            assert v.net.subnet_of(s.supernet), (s.code, v.name)
        assert s.vpn_pool.subnet_of(s.supernet)
        assert s.fortilink_net.subnet_of(s.supernet)
    sup = [s.supernet for s in model.sites]
    assert not any(a.overlaps(b) for a, b in itertools.combinations(sup, 2))


def test_vpn_pools_avoid_common_home_ranges(model):
    home = [ipaddress.ip_network(n) for n in ("192.168.0.0/16", "10.0.0.0/16", "10.1.0.0/16",
                                              "172.16.0.0/16")]
    for s in model.sites:
        assert not s.supernet.overlaps(home[0])
        for h in home:
            assert not s.vpn_pool.overlaps(h), f"{s.code} pool collides with typical home LAN {h}"


def test_wan_gateways_are_in_wan_subnet(model):
    for s in model.sites:
        for wn in ("wan1", "wan2"):
            iface = ipaddress.ip_interface(s.wan[wn]["ip"])
            assert ipaddress.ip_address(s.wan[wn]["gw"]) in iface.network


def test_full_mesh_has_4_tunnels_per_pair(model):
    for a, b in itertools.combinations(model.sites, 2):
        pair = [t for t in model.tunnels if {t.a.code, t.b.code} == {a.code, b.code}]
        assert sorted((t.a_wan, t.b_wan) for t in pair) == [
            ("wan1", "wan1"), ("wan1", "wan2"), ("wan2", "wan1"), ("wan2", "wan2")]


def test_ipsec_tunnels_are_mirror_images(model, fgs):
    for t in model.tunnels:
        A, B = fgs[t.a.code], fgs[t.b.code]
        pa, pb = A.p1[t.a_name], B.p1[t.b_name]
        assert pa.get("remote-gw") == t.b.wan_ip(t.b_wan), t.a_name
        assert pb.get("remote-gw") == t.a.wan_ip(t.a_wan), t.b_name
        assert pa.get("interface") == t.a_wan and pb.get("interface") == t.b_wan
        assert pa.get("psksecret") == pb.get("psksecret") and len(pa.get("psksecret")) >= 32
        for k in ("ike-version", "proposal", "dhgrp"):
            assert pa.lst(k) == pb.lst(k), (t.a_name, k)
        assert pa.get("ike-version") == "2"
        p2a = A.root.cfg("vpn ipsec phase2-interface").edits[t.a_name]
        p2b = B.root.cfg("vpn ipsec phase2-interface").edits[t.b_name]
        assert p2a.get("phase1name") == t.a_name and p2b.get("phase1name") == t.b_name
        assert p2a.lst("proposal") == p2b.lst("proposal") and p2a.lst("dhgrp") == p2b.lst("dhgrp")
        ia, ib = A.intf[t.a_name], B.intf[t.b_name]
        assert ia.lst("ip")[0] == ib.lst("remote-ip")[0] == str(t.a_ip)
        assert ib.lst("ip")[0] == ia.lst("remote-ip")[0] == str(t.b_ip)


def test_unique_psk_per_tunnel(model):
    psks = [t.psk for t in model.tunnels]
    assert len(set(psks)) == len(psks)


def test_bgp_full_mesh(model, fgs):
    for s in model.sites:
        bgp = fgs[s.code].root.cfg("router bgp")
        assert bgp.get("as") == str(model.g["bgp_as"])
        assert bgp.get("router-id") == str(s.loopback)
        nbrs = bgp.cfg("neighbor").edits
        assert set(nbrs) == {str(p.loopback) for p in model.peers_of(s)}
        for n in nbrs.values():
            assert n.get("remote-as") == bgp.get("as") and n.get("update-source") == "Lo-BGP"
            assert n.get("password")
        prefixes = [n.lst("prefix") for n in bgp.cfg("network").edits.values()]
        assert prefixes == [[str(s.supernet.network_address), str(s.supernet.netmask)]]


def test_bgp_network_has_matching_rib_route(model, fgs):
    """network-import-check: the advertised /16 must exist in the RIB (blackhole summary)."""
    for s in model.sites:
        statics = fgs[s.code].root.cfg("router static").edits.values()
        assert any(r.lst("dst") == [str(s.supernet.network_address), str(s.supernet.netmask)]
                   and r.get("blackhole") == "enable" for r in statics)


def test_loopback_reachability_over_every_tunnel(model, fgs):
    for s in model.sites:
        fg = fgs[s.code]
        for p in model.peers_of(s):
            devs = {r.get("device") for r in fg.root.cfg("router static").edits.values()
                    if r.lst("dst") == [str(p.loopback), "255.255.255.255"]}
            expect = {t.side(s)["name"] for t in model.tunnels_of(s) if t.side(s)["peer"].code == p.code}
            assert devs == expect and len(devs) == 4


def test_peers_accept_bgp_and_probes_on_loopback(model, fgs):
    for s in model.sites:
        fg = fgs[s.code]
        for t in model.tunnels_of(s):
            side = t.side(s)
            verdict = fg.lookup(side["name"], "Lo-BGP", side["remote_ip"], s.loopback, "tcp", 179)
            assert verdict[0] == "accept", (s.code, side["name"])
            verdict = fg.lookup(side["name"], "Lo-BGP", side["peer"].loopback, s.loopback, "icmp", 0)
            assert verdict[0] == "accept"


# ---------------------------------------------------------------- remote access
def test_remote_access_gateways(model, fgs):
    for s in model.sites:
        fg = fgs[s.code]
        ranges = []
        for name, wan in (("RA-VPN1", "wan1"), ("RA-VPN2", "wan2")):
            p = fg.p1[name]
            assert p.get("type") == "dynamic" and p.get("interface") == wan
            assert p.get("ike-version") == "2" and p.get("eap") == "enable"
            assert p.get("transport") == "auto" and p.get("mode-cfg") == "enable"
            assert p.get("authusrgrp") == "VPN-ALL"
            lo, hi = (ipaddress.ip_address(p.get(k)) for k in ("ipv4-start-ip", "ipv4-end-ip"))
            assert lo in s.vpn_pool and hi in s.vpn_pool
            ranges.append((lo, hi))
            split = {str(n) for n in fg.resolve_addr(p.get("ipv4-split-include"))}
            assert split == {str(x.supernet) for x in model.sites}, "split tunnel must cover every office"
            assert p.get("ipv4-dns-server1") in s.dc_ips
        (a1, a2), (b1, b2) = ranges
        assert a2 < b1, f"{s.code}: RA pools overlap"
        zone = fg.zones["RA_VPN"].lst("interface")
        assert zone == ["RA-VPN1", "RA-VPN2"]
        assert fg.root.cfg("system settings").get("ike-tcp-port") == "443"
        assert fg.root.cfg("system global").get("admin-sport") != "443"


def test_vpn_users_have_mfa_and_correct_role(model, fgs):
    for s in model.sites:
        fg = fgs[s.code]
        locals_ = fg.root.cfg("user local").edits
        for u in model.users:
            n = locals_[u["username"]]
            assert n.get("type") == "ldap" and n.get("ldap-server") == "AD-LDAP"
            assert n.get("two-factor") == "fortitoken-cloud", f"{u['username']} without MFA"
            groups = fg.user_groups(u["username"])
            assert f"VPN-{u['role']}" in groups and "VPN-ALL" in groups
            others = {f"VPN-{r}" for r in ("Staff", "Developers", "IT")} - {f"VPN-{u['role']}"}
            assert not (groups & others), f"{u['username']} leaks into {groups & others}"


def test_ldap_uses_ldaps(fgs):
    for code, fg in fgs.items():
        l = fg.root.cfg("user ldap").edits["AD-LDAP"]
        assert l.get("secure") == "ldaps" and l.get("port") == "636" and l.get("ca-cert")
