"""Failure simulations (ISP outages, tunnel loss) and hardware sizing checks."""
import itertools

import pytest

from fortios import sdwan_pick

WANS = ("wan1", "wan2")


def _member_map(fg):
    return {mm.get("interface"): int(mid) for mid, mm in fg.sdwan.cfg("members").edits.items()}


def _alive_tunnels(model, failed: set[tuple[str, str]]):
    """A tunnel is up only if the ISP at BOTH ends is up."""
    return [t for t in model.tunnels
            if (t.a.code, t.a_wan) not in failed and (t.b.code, t.b_wan) not in failed]


def _failure_scenarios(model):
    """Every combination where each office loses at most ONE of its two ISPs
    (3^3 = 27 scenarios, including the healthy one and triple simultaneous loss)."""
    per_site = [[None] + [(s.code, w) for w in WANS] for s in model.sites]
    for combo in itertools.product(*per_site):
        yield {c for c in combo if c}


def test_every_office_pair_survives_any_single_isp_loss_per_site(model):
    n = 0
    for failed in _failure_scenarios(model):
        alive = _alive_tunnels(model, failed)
        for a, b in itertools.combinations(model.sites, 2):
            assert any({t.a.code, t.b.code} == {a.code, b.code} for t in alive), \
                f"{a.code}<->{b.code} isolated when {sorted(failed)} fail"
        n += 1
    assert n == 27


@pytest.mark.parametrize("scenario", ["healthy", "single", "cross"])
def test_sdwan_rules_steer_to_a_live_tunnel(model, fgs, scenario):
    failures = {"healthy": set(),
                "single": {("BEY", "wan1")},
                # the case only a 2x2 mesh survives: LON loses ISP1, BEY loses ISP2
                "cross": {("LON", "wan1"), ("BEY", "wan2")}}[scenario]
    alive = _alive_tunnels(model, failures)
    for s in model.sites:
        fg = fgs[s.code]
        mm = _member_map(fg)
        alive_ids = {mm[t.side(s)["name"]] for t in alive if s.code in (t.a.code, t.b.code)}
        alive_ids |= {mm[w] for w in WANS if (s.code, w) not in failures}
        for p in model.peers_of(s):
            pick = sdwan_pick(fg, f"CORP-{p.code}", alive_ids)
            assert pick in alive_ids, f"{s.code}->{p.code} picked dead/none member {pick} ({scenario})"
            name = next(k for k, v in mm.items() if v == pick)
            if scenario == "healthy":
                assert name == f"{p.code}_11", "healthy state should use primary ISPs end to end"


def test_sla_degradation_moves_traffic_before_failure(model, fgs):
    fg, s = fgs["LON"], model.site("LON")
    mm = _member_map(fg)
    alive = set(mm.values())
    primary = mm["BEY_11"]
    pick = sdwan_pick(fg, "CORP-BEY", alive, in_sla=alive - {primary})
    assert pick == mm["BEY_22"], "out-of-SLA primary must hand over to the ISP2-ISP2 tunnel"


def test_guest_and_voice_internet_steering(fgs):
    for code, fg in fgs.items():
        assert sdwan_pick(fg, "GUEST-INET", {1, 2}) == 2, "guests ride the secondary ISP"
        assert sdwan_pick(fg, "GUEST-INET", {1}) == 1, "...and fail over to ISP1"
        assert sdwan_pick(fg, "VOICE-INET", {2}) == 2


def test_health_checks_cover_exactly_their_tunnels(model, fgs):
    for s in model.sites:
        fg = fgs[s.code]
        mm = _member_map(fg)
        hcs = fg.sdwan.cfg("health-check").edits
        assert hcs["INET"].get("update-static-route") == "enable"
        assert set(" ".join(hcs["INET"].lst("members")).split()) == {"1", "2"}
        for p in model.peers_of(s):
            hc = hcs[f"HC_{p.code}"]
            assert hc.get("server") == str(p.loopback)
            assert hc.get("update-static-route") == "enable"
            ids = {int(x) for x in " ".join(hc.lst("members")).split()}
            expect = {mm[t.side(s)["name"]] for t in model.tunnels_of(s)
                      if t.side(s)["peer"].code == p.code}
            assert ids == expect


def test_overlay_outage_fails_closed_not_to_internet(model, fgs):
    """If every tunnel to a peer dies, BGP withdraws its /16. Traffic must then
    hit the RFC1918 blackhole - it must NEVER fall through the default route
    and leave unencrypted over the internet."""
    for s in model.sites:
        fg = fgs[s.code]
        for p in model.peers_of(s):
            dst = str(p.vlan("SERVERS").gw + 9)
            bgp_up = {str(x.supernet): "OVERLAY" for x in model.peers_of(s)}
            assert fg.route(dst, bgp_up) == "OVERLAY"
            bgp_down = {k: v for k, v in bgp_up.items() if k != str(p.supernet)}
            down = {t.side(s)["name"] for t in model.tunnels_of(s) if t.side(s)["peer"].code == p.code}
            assert fg.route(dst, bgp_down, down) == "BLACKHOLE", f"{s.code}->{p.code} leaks"
            assert fg.route(str(p.loopback), bgp_down, down) == "BLACKHOLE"
        assert fg.route("93.184.216.34", {}) == "UNDERLAY"


def test_ha_only_where_designed(model, fgs):
    for s in model.sites:
        ha = fgs[s.code].root.configs.get("system ha")
        if s.ha:
            assert ha.get("mode") == "a-p" and ha.get("session-pickup") == "enable"
            assert set(ha.lst("monitor")) == {"wan1", "wan2"} and ha.get("password")
        else:
            assert ha is None


def test_fabric_topology(model, fgs):
    root = model.site("BEY")
    for s in model.sites:
        csf = fgs[s.code].root.cfg("system csf")
        assert csf.get("status") == "enable"
        if s.code == root.code:
            assert csf.get("upstream") is None
        else:
            assert csf.get("upstream") == str(root.loopback)


# ------------------------------------------------------------------ sizing
# Vendor datasheet figures (Fortinet FortiGate 70G / 90G datasheets).
DATASHEET = {
    "FG-70G": {"threat_mbps": 1300, "ngfw_mbps": 1500, "ssl_insp_mbps": 1400, "c2g_tunnels": 500},
    "FG-90G": {"threat_mbps": 2200, "ngfw_mbps": 2500, "ssl_insp_mbps": 2600, "c2g_tunnels": 2500},
}


def test_firewall_sizing(model):
    for s in model.sites:
        d = DATASHEET[s.model]
        # every user may work remotely on the same day -> 3x headroom on tunnels
        assert d["c2g_tunnels"] >= 3 * s.users
        # full-UTM throughput must cover the primary ISP at line rate
        assert d["threat_mbps"] >= s.wan["wan1"]["bw_mbps"], s.code
        assert d["ssl_insp_mbps"] >= s.wan["wan1"]["bw_mbps"], s.code


def test_switch_port_capacity(model):
    ports = {"FS-148F-FPOE": 48, "FS-124F-POE": 24, "FS-124F-FPOE": 24}
    for s in model.sites:
        total = sum(ports[x["model"]] * x["qty"] for x in s.switches)
        # 1 desk port + 1 phone daisy-chained, plus APs, printers, cameras, lab, uplinks
        need = s.users + s.aps["qty"] + 10
        assert total >= need, f"{s.code}: {total} ports < {need}"
