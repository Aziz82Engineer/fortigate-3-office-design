"""Grammar, referential integrity and object hygiene of every generated script."""
from pathlib import Path

import pytest

from fortios import (PREDEF_ADDR, PREDEF_PROFILES, PREDEF_SERVICES, ParseError, load, parse)

CONFIGS = sorted((Path(__file__).resolve().parent.parent / "configs").glob("*.conf"))


@pytest.mark.parametrize("path", CONFIGS, ids=lambda p: p.name)
def test_cli_grammar_is_balanced(model, path):
    load(path)          # raises ParseError on any config/edit/next/end imbalance


def test_parser_rejects_broken_cli():
    for bad in ("config system global\n set hostname x\n",          # missing end
                "config firewall policy\n edit 1\n end\n",          # end before next
                "set hostname x\n",                                   # set outside config
                "config a\n edit 1\n next\nnext\nend\n"):             # stray next
        with pytest.raises(ParseError):
            parse(bad)


def test_no_ssl_vpn_anywhere(fgs):
    """SSL-VPN tunnel mode is removed in FortiOS 7.6.3+; design must not depend on it."""
    for code, fg in fgs.items():
        assert not any(k.startswith("vpn ssl") for k in fg.root.configs), code


def test_policy_names_unique_and_ids_sequential(fgs):
    for code, fg in fgs.items():
        names = [p.get("name") for p in fg.policies.values()]
        assert len(names) == len(set(names)), code
        assert list(fg.policies) == [str(i) for i in range(1, len(names) + 1)], code


def _all_interface_refs(fg):
    zm = fg.zone_members()
    return fg.interfaces() | set(zm) | {"Lo-BGP"}


def test_policy_references_resolve(fgs):
    for code, fg in fgs.items():
        known_if = _all_interface_refs(fg)
        for pid, p in fg.policies.items():
            for i in p.lst("srcintf") + p.lst("dstintf"):
                assert i in known_if, f"{code} policy {pid}: unknown interface {i}"
            for a in p.lst("srcaddr") + p.lst("dstaddr"):
                fg.resolve_addr(a)                      # KeyError if missing
            for s in p.lst("service"):
                fg.resolve_svc(s)
            for g in p.lst("groups"):
                assert g in fg.groups, f"{code} policy {pid}: unknown group {g}"
            for prof, allowed in PREDEF_PROFILES.items():
                if p.get(prof):
                    assert p.get(prof) in allowed, f"{code} {pid}: {prof}={p.get(prof)}"
            if any(p.get(k) for k in PREDEF_PROFILES if k != "ssl-ssh-profile"):
                assert p.get("utm-status") == "enable" and p.get("ssl-ssh-profile"), \
                    f"{code} {pid}: profiles set but UTM/SSL profile missing"


def test_address_groups_resolve_and_have_no_loops(fgs):
    for code, fg in fgs.items():
        for name in fg.addrgrp:
            assert fg.resolve_addr(name), f"{code}: empty group {name}"


def test_service_groups_resolve(fgs):
    for code, fg in fgs.items():
        for name in fg.svcgrp:
            assert fg.resolve_svc(name), f"{code}: empty service group {name}"


def test_sdwan_references_resolve(fgs):
    for code, fg in fgs.items():
        sd = fg.sdwan
        zones = set(sd.cfg("zone").edits)
        members = sd.cfg("members").edits
        assert zones == {"UNDERLAY", "OVERLAY"}
        for mid, mm in members.items():
            assert mm.get("zone") in zones
            assert mm.get("interface") in fg.interfaces(), f"{code}: member {mid}"
        hcs = sd.cfg("health-check").edits
        for name, hc in hcs.items():
            for mid in " ".join(hc.lst("members")).split():
                assert mid in members, f"{code}: health-check {name} -> member {mid}"
        for rid, r in sd.cfg("service").edits.items():
            for mid in " ".join(r.lst("priority-members")).split():
                assert mid in members, f"{code}: rule {rid} -> member {mid}"
            for a in r.lst("src") + r.lst("dst"):
                fg.resolve_addr(a)
            if r.get("health-check"):
                assert r.get("health-check") in hcs
            for h in r.cfg("sla").edits:
                assert h in hcs


def test_dhcp_scopes_are_consistent(fgs, model):
    for s in model.sites:
        fg = fgs[s.code]
        scoped = set()
        for _, d in fg.root.cfg("system dhcp server").edits.items():
            v = s.vlan(d.get("interface"))
            scoped.add(v.name)
            assert d.get("default-gateway") == str(v.gw)
            assert d.get("netmask") == str(v.net.netmask)
            for _, r in d.cfg("ip-range").edits.items():
                import ipaddress
                lo, hi = (ipaddress.ip_address(r.get(k)) for k in ("start-ip", "end-ip"))
                assert lo in v.net and hi in v.net and lo < hi and lo != v.gw
            if v.cross_site:
                assert d.get("dns-server1") in s.dc_ips, f"{s.code}/{v.name} must use local DC DNS"
        assert "SERVERS" not in scoped, "servers are statically addressed"
        assert scoped == {v.name for v in s.vlans if v.dhcp}


def test_every_lan_interface_exists_with_right_gateway(fgs, model):
    for s in model.sites:
        fg = fgs[s.code]
        for v in s.vlans:
            n = fg.intf[v.name]
            assert n.lst("ip") == [str(v.gw), str(v.net.netmask)]
            if v.type == "vlan":
                assert n.get("interface") == "fortilink" and n.get("vlanid") == str(v.id)
            else:
                assert v.name in fg.vaps


def test_predefined_assumptions_are_documented():
    # Guard: if the design starts using another built-in object, add it here
    # and verify it exists on FortiOS 7.6 before deployment.
    assert {"ALL", "HTTPS", "BGP", "LDAP_UDP", "DCE-RPC"} <= set(PREDEF_SERVICES)
    assert set(PREDEF_ADDR) == {"all"}
