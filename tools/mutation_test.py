#!/usr/bin/env python3
"""Mutation test: inject realistic mistakes into the generated configs and prove
the test suite catches every one of them. Prints a table; exits 1 if any survive."""
import os, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CFG = ROOT / "configs"

MUTATIONS = [
    ("PSK typo on one tunnel end", "DXB-fortigate.conf",
     lambda t: re.sub(r'(edit "LON_11"\n(?:.*\n)*?\s+set psksecret ")(\w)', r'\1X', t, count=1)),
    ("Wrong remote-gw on a tunnel", "LON-fortigate.conf",
     lambda t: t.replace("set remote-gw 203.0.113.20", "set remote-gw 203.0.113.21", 1)),
    ("Guest policy widened to the server VLAN", "BEY-fortigate.conf",
     lambda t: t.replace('set srcintf "GUEST"\n        set dstintf "UNDERLAY"',
                         'set srcintf "GUEST"\n        set dstintf "UNDERLAY" "SERVERS"', 1)),
    ("HTTPS admin opened on WAN", "DXB-fortigate.conf",
     lambda t: t.replace("set allowaccess ping\n        set role wan", "set allowaccess ping https\n        set role wan", 1)),
    ("RFC1918 blackhole removed", "LON-fortigate.conf",
     lambda t: re.sub(r'set dst 10\.0\.0\.0 255\.0\.0\.0\n\s+set blackhole enable', 'set dst 10.0.0.0 255.0.0.0\n            set blackhole disable', t)),
    ("MFA dropped for one VPN user", "BEY-fortigate.conf",
     lambda t: t.replace("set two-factor fortitoken-cloud", "set two-factor disable", 1)),
    ("Overlapping VLAN subnet", "DXB-fortigate.conf",
     lambda t: t.replace("set ip 10.30.80.1 255.255.255.0", "set ip 10.30.70.1 255.255.255.0", 1)),
    ("UTM removed from staff internet policy", "LON-fortigate.conf",
     lambda t: re.sub(r'(set name "STAFF-to-INTERNET"(?:.*\n)*?)\s+set utm-status enable\n', r'\1\n', t, count=1)),
    ("Missing 'end' (broken script)", "BEY-fortigate.conf",
     lambda t: t.replace("end\nconfig system settings", "config system settings", 1)),
    ("BGP neighbor removed", "DXB-fortigate.conf",
     lambda t: re.sub(r'edit "10\.255\.255\.1"\n(?:.*\n)*?\s+next\n', '', t, count=1)),
    ("Policy references undefined address", "LON-fortigate.conf",
     lambda t: t.replace('set dstaddr "LON_NVR"', 'set dstaddr "LON_NVR2"', 1)),
    ("Camera given internet", "BEY-fortigate.conf",
     lambda t: t.replace('set srcintf "PRINT_IOT"\n        set dstintf "UNDERLAY"', 'set srcintf "PRINT_IOT" "CCTV"\n        set dstintf "UNDERLAY"', 1)
              .replace('set srcaddr "BEY_PRINT_IOT"\n        set dstaddr "all"\n        set schedule "always"\n        set service "NTP"',
                       'set srcaddr "BEY_PRINT_IOT" "BEY_CCTV"\n        set dstaddr "all"\n        set schedule "always"\n        set service "ALL"', 1)),
]

def run_tests():
    env = dict(os.environ, SKIP_GENERATE="1")
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", str(ROOT / "tests")],
                       cwd=ROOT, env=env, capture_output=True, text=True)
    return r.returncode, r.stdout

subprocess.run([sys.executable, str(ROOT / "generator/generate.py")], check=True, capture_output=True)
assert run_tests()[0] == 0, "baseline must pass"
survivors = 0
print(f"{'mutation':45} result")
for name, fname, fn in MUTATIONS:
    path = CFG / fname
    orig = path.read_text()
    mutated = fn(orig)
    if mutated == orig:
        print(f"{name:45} NOT APPLIED (pattern missed)"); survivors += 1; continue
    path.write_text(mutated)
    code, out = run_tests()
    path.write_text(orig)
    caught = code != 0
    failed = re.search(r"FAILED (\S+)", out)
    print(f"{name:45} {'CAUGHT by ' + failed.group(1).split('::')[-1][:45] if caught and failed else ('CAUGHT' if caught else 'SURVIVED')}")
    survivors += not caught
subprocess.run([sys.executable, str(ROOT / "generator/generate.py")], check=True, capture_output=True)
print(f"\n{len(MUTATIONS) - survivors}/{len(MUTATIONS)} injected faults detected")
sys.exit(1 if survivors else 0)
