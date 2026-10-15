# Fortinet Security Fabric Design – London, Beirut, Dubai

Design document for a web and mobile development company with 140 people across three offices plus home workers.
The FortiOS configurations in [`configs/`](configs/) are generated from [`inventory/sites.yaml`](inventory/sites.yaml) and validated by the test suite in [`tests/`](tests/).

## Executive summary

The three offices become one Fortinet Security Fabric: a FortiGate per office (Beirut as an HA pair), managed FortiSwitches and Wi-Fi 7 FortiAPs, and cloud-hosted management, logging and endpoint control. The configs for all three FortiGates are generated from one inventory file and pass 220 automated tests.

Key decisions:

- **Full-mesh SD-WAN over two ISPs per office.** Every office pair has 4 IPsec tunnels (ISP1/ISP2 at each end). Any office can lose either ISP, even at the same time as the others, and every office still reaches every other.
- **Remote access is IKEv2 IPsec with FortiClient, not SSL VPN.** FortiOS 7.6.3 removed SSL VPN tunnel mode, so this design starts on IPsec. Users sign in with their AD account (EAP-TTLS over LDAPS) plus FortiToken MFA. Only EMS-compliant laptops can connect.
- **10 segments per office.** Staff, developers, servers, voice, corporate Wi-Fi, guest Wi-Fi, mobile test devices, printers/IoT, cameras and management are separated. Each office uses the same VLAN numbers with its own /16 (London 10.10, Beirut 10.20, Dubai 10.30).
- **Target firmware FortiOS 7.6.7.** It is the mature branch, supported until January 2030. FortiOS 8.0 is newer but less proven.
- **Cloud management.** FortiManager Cloud, FortiAnalyzer Cloud, FortiClient EMS Cloud and FortiIdentity Cloud remove the need to run management servers in any office.

Testing: 220 tests check grammar, references, IP plan, VPN symmetry, routing, failover, 34 traffic flows per office and 66 office-to-office flows. A mutation run injected 12 realistic mistakes and the suite caught all 12. The tests also caught one real design gap (Dubai needed a second switch), now fixed. These are offline tests of the generated configs; a lab and on-site acceptance plan is in [Testing and validation](#testing-and-validation).

## Architecture and topology

![Network diagram: three offices joined by a full mesh of IPsec tunnels, cloud management, home workers](docs/network-diagram.svg)

Each pair of offices is joined by 4 tunnels, one per ISP combination, so traffic between two offices never transits the third. Beirut is the Fabric root; all three FortiGates reach the Fortinet cloud services outbound, and home workers land on their own office's FortiGate first.

## Bill of materials and licensing

Beirut gets an HA pair because it is the largest office and the Fabric root, and it faces the least stable power and ISP conditions. London and Dubai run one FortiGate each, with two ISPs for redundancy.

| Office | People | FortiGate | FortiSwitch | FortiAP (Wi-Fi 7) | Primary / backup ISP |
| --- | --- | --- | --- | --- | --- |
| Beirut | 70 | 2 × FG-90G, active-passive HA | 2 × FS-148F-FPOE + 1 × FS-124F-POE | 6 × FAP-231K | 500 / 200 Mbps |
| Dubai | 40 | 1 × FG-90G | 1 × FS-148F-FPOE + 1 × FS-124F-POE | 4 × FAP-231K | 1000 / 500 Mbps |
| London | 30 | 1 × FG-70G | 1 × FS-148F-FPOE | 3 × FAP-231K | 1000 / 300 Mbps |

ISP speeds are planning assumptions; replace them with the real contracts. AP counts assume one AP per 12–15 people on open-plan floors and must be confirmed by a site survey.

Why these models ([70G](https://www.shidirect.com/product/49371495/Fortinet-FortiGate-70G), [90G](https://www.publicsector.shidirect.com/product/46531574/Fortinet-FortiGate-90G) datasheet figures):

| Model | Threat protection | SSL inspection | IPsec (512 B) | Client VPN tunnels | Fits |
| --- | --- | --- | --- | --- | --- |
| FG-70G | 1.3 Gbps | 1.4 Gbps | 7.1 Gbps | 500 | London: 1 Gbps primary ISP at full inspection, 16× VPN headroom |
| FG-90G | 2.2 Gbps | 2.6 Gbps | 25 Gbps | 2,500 | Beirut and Dubai, with room to grow |

If London's primary line goes above 1 Gbps, move London to an FG-90G; the 70G is at its limit for full inspection at that speed.

Subscriptions (quote through a Fortinet partner; prices change often):

- **FortiGuard UTP bundle** on every FortiGate, including the HA secondary: IPS, antivirus, web/DNS filtering, application control.
- **FortiCare Premium** on every FortiSwitch and FortiAP.
- **FortiManager Cloud** and **FortiAnalyzer Cloud**, licensed per FortiGate (4 units).
- **FortiClient EMS Cloud** with VPN/ZTNA endpoint licences for about 150 endpoints (140 people plus spares).
- **FortiIdentity Cloud** (FortiToken Mobile) for about 150 users. Cloud tokens work on all three FortiGates, which local FortiTokens cannot do.

Also order: a UPS per comms rack (the Beirut one sized for long outages), SFP+ DAC cables for FortiLink, and HA heartbeat cables for Beirut.

## IP addressing and VLAN plan

Every office uses the same VLAN IDs; the second octet identifies the office, so 10.20.30.0/24 is always "Beirut developers". Each office advertises one /16 summary over BGP.

| VLAN | Segment | London | Beirut | Dubai | Internet | Other offices |
| --- | --- | --- | --- | --- | --- | --- |
| 10 | MGMT – switches, APs, UPS | 10.10.10.0/24 | 10.20.10.0/24 | 10.30.10.0/24 | Updates only | No |
| 20 | STAFF – wired PM, design, sales, finance | 10.10.20.0/24 | 10.20.20.0/24 | 10.30.20.0/24 | Yes, deep inspection | Yes |
| 30 | DEV – web and mobile engineers | 10.10.30.0/24 | 10.20.30.0/24 | 10.30.30.0/24 | Yes, certificate inspection | Yes |
| 40 | SERVERS – DCs, files, CI, staging | 10.10.40.0/24 | 10.20.40.0/24 | 10.30.40.0/24 | Yes | Yes |
| 50 | VOICE – IP phones, video | 10.10.50.0/24 | 10.20.50.0/24 | 10.30.50.0/24 | Yes | Yes |
| 60 | PRINT_IOT – printers, displays | 10.10.60.0/24 | 10.20.60.0/24 | 10.30.60.0/24 | NTP only | No |
| 70 | GUEST – guest Wi-Fi SSID | 10.10.70.0/24 | 10.20.70.0/24 | 10.30.70.0/24 | Web only | No |
| 80 | DEVICE_LAB – test phones/tablets | 10.10.80.0/24 | 10.20.80.0/24 | 10.30.80.0/24 | Yes | No |
| 90 | CCTV – cameras, door access | 10.10.90.0/24 | 10.20.90.0/24 | 10.30.90.0/24 | No | No |
| 100 | CORP_WIFI – 802.1X SSID | 10.10.100.0/23 | 10.20.100.0/23 | 10.30.100.0/23 | Yes, deep inspection | Yes |
| – | VPN pool (home workers) | 10.10.200.0/24 | 10.20.200.0/24 | 10.30.200.0/24 | Split tunnel | Yes |
| – | FortiLink | 10.10.1.0/24 | 10.20.1.0/24 | 10.30.1.0/24 | – | – |
| – | BGP loopback | 10.255.255.1 | 10.255.255.2 | 10.255.255.3 | – | – |

The gateway is always .1. DHCP hands out .50 to .250; .2 to .49 are for static devices. Servers are static: the first DC is .40.10, the NVR .40.50, staging .40.128/26. Site-to-site tunnels use /30s from 10.255.0.0/24. VPN pools avoid 192.168.x and 10.0/10.1, which home routers commonly use.

## WAN, SD-WAN and site-to-site VPN

Each office builds 8 tunnels, 4 to each other office, one per ISP combination: 12 tunnels in total. iBGP between loopbacks carries the office routes, and SD-WAN chooses the best healthy tunnel per application. With three offices a full mesh is simpler and more resilient than hub-and-spoke, because no office depends on another to reach the third.

**Tunnels.** IKEv2, AES-256-GCM with PRF-SHA384 (AES-256/SHA-256 fallback), DH groups 21 and 20, a unique 32-character pre-shared key per tunnel, and dead-peer detection. Names show the path: on Beirut, `LON_12` means local ISP1 to London ISP2.

**Routing.** Each office has loopback 10.255.255.x and a static /32 route to each peer loopback over all four tunnels to that peer. iBGP (AS 65000, MD5 authentication) runs loopback to loopback, and each office advertises only its /16. If every tunnel to a peer dies, the static routes and BGP routes are withdrawn. Traffic then hits a blackhole route for 10/8, 172.16/12 and 192.168/16, so internal traffic can never escape unencrypted over the internet default route.

**Health checks.** Each office pings 1.1.1.1 and 8.8.8.8 over both ISPs, and each peer loopback over each tunnel, every second. Five lost probes mark a path down; ten good ones bring it back.

| SD-WAN rule | Matches | Strategy | Path order |
| --- | --- | --- | --- |
| VOICE-&lt;office&gt; | Voice VLAN to another office | Lowest latency | Best tunnel at that moment |
| CORP-&lt;office&gt; | Anything to another office | Lowest cost within SLA (200 ms, 50 ms jitter, 2% loss) | ISP1↔ISP1, ISP2↔ISP2, ISP1↔ISP2, ISP2↔ISP1 |
| VOICE-INET | Voice VLAN to the internet | Lowest latency | Either ISP |
| GUEST-INET | Guest Wi-Fi | Manual | ISP2 first, ISP1 if ISP2 fails |
| Implicit | All other internet traffic | Source-IP load balancing | Both ISPs |

Guests are pushed onto the backup ISP so they never compete with staff for the primary line. Corporate traffic moves off a tunnel as soon as it breaks SLA, before it fails outright.

## Remote access for home workers

Home workers connect with EMS-managed FortiClient over IKEv2 IPsec, sign in with their AD account and approve a FortiToken push. Only endpoints that EMS marks compliant can bring the tunnel up. SSL VPN tunnel mode is not used: [FortiOS 7.6.3 removed it](https://dev.to/madhushan/fortios-763-update-ssl-vpn-tunnel-mode-no-longer-supported-27hg) and does not migrate old SSL VPN settings.

1. FortiClient tries the home office's ISP1 gateway, then its ISP2 gateway, then another office as backup. Each office has two dial-up gateways (`RA-VPN1` on wan1, `RA-VPN2` on wan2), each with its own half of the office VPN pool.
2. IKE starts over UDP. If a hotel or café network blocks UDP, it [falls back to TCP 443](https://docs.fortinet.com/document/fortigate/7.6.7/administration-guide/442351). Admin HTTPS moves to 8443 to free port 443.
3. The user authenticates with EAP-TTLS, which is required for LDAP with IKEv2. The FortiGate checks the password against AD over LDAPS (636) with a read-only service account.
4. [FortiIdentity Cloud](https://community.fortinet.com/fortigate-3/technical-tip-dial-up-ipsec-ikev2-with-ldap-authentication-and-2fa-with-fortitoken-fortitoken-cloud-220763) sends the FortiToken Mobile push. Each VPN user is a remote-LDAP user on every FortiGate, generated from `inventory/vpn_users.csv`.
5. After EMS connects, the [posture-tag check](https://docs.fortinet.com/document/fortigate/7.6.7/administration-guide/109455/enforcing-security-posture-tag-match-before-dial-up-ipsec-vpn-connection) (`*-post-ems.conf`) rejects any endpoint without the compliance tag before the tunnel forms.
6. Split tunnel: only the three office /16s go through the tunnel, and DNS points at the office domain controllers. Internet traffic goes direct from home, filtered by FortiClient's web filter.

Access by AD role, enforced on the gateway the user connects to:

| VPN group | Servers | Developer VLAN and test devices | Management VLAN | Other offices |
| --- | --- | --- | --- | --- |
| VPN-Staff | AD logon, file shares, intranet web | No | No | Same as servers |
| VPN-Developers | All ports | All ports | No | All ports |
| VPN-IT | All ports | All ports | HTTPS, SSH, SNMP, ping | All ports |

Minimum versions: FortiOS 7.6.1+, FortiClient 7.4.4+ and EMS 7.4.3+ are needed for EAP-TTLS with token prompts ([Fortinet tip](https://community.fortinet.com/fortigate-3/technical-tip-multi-factor-authentication-support-for-windows-forticlient-with-ldap-eap-ttls-212498)). FortiClient on iOS does not support FortiToken on dial-up IPsec, so phones and tablets get mail and apps through cloud services, not the VPN.

Split tunnel is a trade-off. Full tunnel sends all home traffic through the office FortiGate for inspection, but costs office bandwidth and adds latency. Switching later is one setting per gateway.

## Security policy and segmentation

Each FortiGate has the same 26 policies; anything not listed is denied and logged. Guests, test devices, printers and cameras can never reach another office or a staff segment.

| From ↓ / To → | Internet | Servers | Staff / Wi-Fi | Developers | Test devices | Printers | Management | Other offices |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Staff, corporate Wi-Fi | All, deep inspection | AD, files, web | – | No | No | Print | IT group only | All, IPS |
| Developers | All, certificate inspection | All ports | No | – | All (adb, debug) | Print | IT group only | All, IPS |
| Servers | All, AV + IPS | – | All (GPO, agents) | All | No | No | No | All, IPS |
| Voice | All, no inspection | All | No | No | No | No | No | All, IPS |
| Guest Wi-Fi | Web, DNS, NTP only | No | No | No | No | No | No | No |
| Test devices | All, full UTM | Staging web only + DNS | No | No | – | No | No | No |
| Printers / IoT | NTP only | DNS, NTP | No | No | No | – | No | No |
| Cameras | No | NVR + DNS, NTP | No | No | No | No | No | No |
| Management | Updates (web) | DNS, NTP | No | No | No | No | – | No |
| VPN users | Direct (split tunnel) | By AD role | No | Developers, IT | Developers, IT | No | VPN-IT | By AD role |

Inspection profiles:

- **Staff and corporate Wi-Fi** get full deep SSL inspection, so the corporate root CA must be on every laptop (push it by GPO). Banking and health categories should be exempted.
- **Developers, servers and test devices** get certificate inspection. Deep inspection breaks Git, package registries, Xcode and Android tooling that pin certificates. IPS, antivirus, application control and DNS filtering still apply.
- **Voice** is not inspected, to avoid jitter.
- **Guest Wi-Fi** is limited to web, DNS and NTP. That blocks SMTP spam and torrents, and guests are isolated from each other on the SSID.

The configs use the FortiOS built-in `default` profiles for antivirus, web, DNS, IPS and application control. Tune them in FortiManager after two weeks of logs, for example by blocking high-risk application categories for staff.

Hardening applied on every unit: no admin access on WAN ports (ping only); admin GUI on 8443 only from the MGMT VLANs and VPN pools (trusted hosts); strong crypto with TLS 1.2 minimum; 3 failed logins lock out for 15 minutes; 15-minute idle timeout; 14-character passwords; every policy logged.

## Identity, Wi-Fi and switching

Active Directory stays the single source of identity. FortiGates read it over LDAPS, learn who is logged on where through FSSO, and use NPS (RADIUS) for Wi-Fi 802.1X.

**Active Directory.** Run at least one domain controller per office on the SERVERS VLAN (Beirut has two), as one AD site per office. Every office's DHCP gives its local DC as first DNS server and a Beirut DC as backup, so logons keep working if an office loses its tunnels. Create these AD groups: `VPN-Staff`, `VPN-Developers`, `VPN-IT` and `IT-Admins`, plus a read-only `svc-fortigate` service account.

**FSSO.** Install the FSSO Collector Agent on both Beirut DCs and a DC Agent on every DC. All three FortiGates poll the Beirut collectors, so on-site IT staff in the `IT-Admins` group can reach the management VLAN from any desk without a separate login.

**Wi-Fi.** FortiAPs are managed by the local FortiGate in tunnel mode, so each SSID terminates on the FortiGate as its own interface:

| SSID | Security | Segment | Notes |
| --- | --- | --- | --- |
| Acme-Corp | WPA3-Enterprise, 802.1X via NPS | CORP_WIFI (/23) | AD credentials or machine certificates |
| Acme-Guest | WPA2-Personal, rotated passphrase | GUEST | Client isolation, web only, rides ISP2 |

APs get their address on the MGMT VLAN, which allows CAPWAP. Assign both SSIDs to the FAP-231K profile in FortiManager's AP template. Add a captive portal or daily guest passphrase later if reception needs it.

**Switching.** FortiSwitches are managed by FortiLink over two aggregated ports (10G SFP+ on the 90G, 1G on the 70G). `*-fortiswitch-ports.conf` sets the starting port plan for each office's 48-port switch:

| Ports | Native VLAN | Also carries | Protection |
| --- | --- | --- | --- |
| 1–20 | STAFF | VOICE (phone daisy-chained) | BPDU guard, edge port |
| 21–36 | DEV | VOICE | BPDU guard, edge port |
| 37–40 | PRINT_IOT | – | – |
| 41–44 | MGMT (APs) | – | – |
| 45–46 | CCTV | – | – |
| 47 | DEVICE_LAB (lab switch/charging cart) | – | – |
| 48 | SERVERS | – | – |

The second phase replaces fixed port VLANs with 802.1X on wired ports: NPS returns the VLAN from the user's AD group, so any desk works for anyone.

## Management, logging and monitoring

Nothing has to be hosted in the offices to run the network: management, logs, endpoint control and MFA are Fortinet cloud services, reached outbound from each FortiGate.

| Service | Role | Configured by |
| --- | --- | --- |
| FortiManager Cloud | Policy packages, global address objects, firmware, AP/switch templates, config revisions | `system central-management` type fortiguard |
| FortiAnalyzer Cloud | All traffic, UTM and VPN logs; SOC reports; IOC alerts | `log fortianalyzer-cloud setting` |
| FortiClient EMS Cloud | FortiClient rollout, VPN profile, compliance tags, endpoint web filter | `endpoint-control fctems` |
| FortiIdentity Cloud | FortiToken Mobile push for VPN users | `two-factor fortitoken-cloud` on each VPN user |
| Security Fabric | One topology view; Beirut is root, London and Dubai join over the overlay | `system csf`, upstream 10.255.255.2 |

Operating rhythm:

- **Daily:** review the FortiAnalyzer threat summary and VPN login failures.
- **Weekly:** check the SD-WAN SLA dashboard per office; an ISP that keeps leaving SLA is a contract conversation.
- **Monthly:** apply FortiOS patches on the 7.6 branch through FortiManager, Beirut secondary first, then the others; review the Fabric security rating.
- **Quarterly:** rotate tunnel PSKs and the guest passphrase (`generate.py --rotate-secrets`), recertify VPN group membership in AD, restore a config backup in the lab.

Add automation stitches in a second phase: alert IT by email or Teams when an ISP goes down, a tunnel leaves SLA, or a VPN user fails MFA five times.

## Testing and validation

All 220 automated tests pass against the generated configs, and a mutation run proved the suite catches 12 of 12 injected mistakes. These tests parse and simulate the configs offline; they do not replace a lab and on-site acceptance run on real FortiGates (below).

| Test group | Tests | What it proves |
| --- | --- | --- |
| CLI grammar and references | 19 | Every script parses (config/edit/next/end balanced); every interface, address, service, group, profile and SD-WAN member referenced exists; DHCP scopes match their gateways; no SSL VPN config |
| Addressing, VPN, routing | 14 | No overlapping subnets across all offices; 4 tunnels per office pair with mirrored gateways, keys, proposals and tunnel IPs; unique key per tunnel; BGP full mesh; peers accept BGP and probes on loopbacks; VPN gateways, pools, split tunnel, LDAPS and MFA on every user |
| Security and traffic simulation | 175 | Hardening (no WAN admin, trusted hosts, crypto, logging); 34 flows per office and 11 flows for each of the 6 office pairs, walked through the real policy tables of both firewalls |
| Resilience and sizing | 12 | All 27 ISP-failure combinations keep every office pair connected; SD-WAN rules pick a live tunnel; SLA breach moves traffic; tunnel loss fails closed to a blackhole, never to the internet; HA and Fabric topology; datasheet and switch-port sizing |

The tests found one real gap: Dubai's single 48-port switch could not serve 40 people plus APs, printers and cameras. A 24-port FS-124F-POE was added.

Mutation test (`tools/mutation_test.py`): each fault is injected into a generated config, the suite must fail, then the config is restored.

| Injected fault | Caught by |
| --- | --- |
| PSK typo on one tunnel end | Tunnel mirror check |
| Wrong remote gateway IP | Tunnel mirror check |
| Guest policy widened to the server VLAN | Isolated-segment check |
| HTTPS admin opened on a WAN port | WAN admin check |
| RFC1918 blackhole removed | Traffic matrix (private IP leaked) |
| MFA dropped for one VPN user | MFA and role check |
| Overlapping VLAN subnet | Interface/gateway check |
| UTM removed from the staff internet policy | Profile reference check |
| Missing `end` in the script | Grammar check |
| BGP neighbor removed | BGP full-mesh check |
| Policy references an undefined address | Reference check |
| Cameras given internet access | Traffic matrix (camera flow) |

Lab and on-site acceptance (run before go-live, in this order):

- [ ] Load each script on a FortiGate VM running FortiOS 7.6.7 (30-day trial) and confirm it applies with no command errors; fix any CLI keyword the target build rejects.
- [ ] Tunnels: `diagnose vpn tunnel list` shows all 8 tunnels up per office; `get router info bgp summary` shows 2 established neighbors.
- [ ] SD-WAN: `diagnose sys sdwan health-check` shows every member alive; unplug wan1 at each office in turn and confirm calls and file copies to other offices continue.
- [ ] Pull the BGP routes for one office and confirm `diagnose debug flow` shows its traffic dropped by the blackhole, not sent to the internet.
- [ ] Beirut HA: `get system ha status` shows the pair in sync; power off the primary during a VPN session and a Teams call, and confirm both survive.
- [ ] VPN: an EMS-compliant laptop connects with AD password plus FortiToken push from home, over UDP and from a UDP-blocking network (TCP 443 fallback); a non-compliant laptop is refused.
- [ ] Roles: a VPN-Staff user can open file shares but not SSH; a VPN-Developers user can SSH to build servers; only VPN-IT reaches the management VLAN.
- [ ] Segments: from a guest, test-device, printer and camera port, repeat the deny cases of the traffic matrix with real traffic.
- [ ] Wi-Fi: 802.1X logon on Acme-Corp with an AD account; guest isolation between two phones on Acme-Guest.
- [ ] Logging: a test EICAR download is blocked and appears in FortiAnalyzer Cloud within 5 minutes.

## Deployment runbook

Roll out Beirut first, because it is the Fabric root and hosts the FSSO collectors, then Dubai, then London. Each office cutover fits one evening; keep the old firewall cabled but powered off for one week as rollback.

1. **Prepare (week 1)**
   1. Order hardware and licences; register every serial in one FortiCloud account.
   2. Edit `inventory/sites.yaml`: company name, AD domain, real WAN IPs and gateways, ISP speeds, port names. Add VPN users to `inventory/vpn_users.csv` from AD.
   3. Run `python3 generator/generate.py --real-secrets`, then `python3 -m pytest` and `python3 tools/mutation_test.py`. Proceed only on all green.
   4. Store `inventory/secrets.yaml` in the password vault; never commit it (it is in `.gitignore`).
2. **AD and cloud services (week 1)**
   1. Create the AD groups, the `svc-fortigate` account and an NPS policy for Acme-Corp 802.1X.
   2. Install the FSSO Collector on both Beirut DCs and DC Agents on all DCs.
   3. Activate FortiManager Cloud, FortiAnalyzer Cloud, EMS Cloud and FortiIdentity Cloud.
3. **Lab (week 2):** run the lab checklist in [Testing and validation](#testing-and-validation) on a FortiGate VM.
4. **Each office (weeks 3–5)**
   1. Upgrade the FortiGate to 7.6.7, factory-reset, and remove wan1/wan2 from the default SD-WAN zone and policy.
   2. Import the corporate root CA as `CORP-ROOT-CA`.
   3. Apply `<CODE>-fortigate.conf` (FortiManager CLI script, or System > Configuration scripts). For Beirut, apply to the primary, then join the secondary with the same HA settings and priority 100.
   4. Connect FortiSwitches on FortiLink, authorize them, put the real serial into `<CODE>-fortiswitch-ports.conf` and apply it.
   5. Authorize FortiAPs and assign the SSIDs to the FAP-231K profile.
   6. Cut over ISP cables, then run the on-site acceptance checks for that office.
5. **Remote access (week 5)**
   1. In EMS, publish a FortiClient profile: IKEv2, EAP-TTLS, transport auto, PSK from the vault, gateways home ISP1, home ISP2, backup office.
   2. Pilot with 5 users per office, then roll out to everyone.
   3. When EMS tags sync, apply `<CODE>-post-ems.conf` to enforce compliance before connection.
6. **Handover (week 6):** import all three FortiGates into FortiManager Cloud; from now on, change policy there or in the inventory, not on the boxes.

## Placeholders and open questions

The configs are complete but carry example values marked `# CHANGE` in `inventory/sites.yaml`; replace them, regenerate and retest.

| Placeholder | Example value used | Replace with |
| --- | --- | --- |
| Company, AD domain, LDAP base DN | Acme Digital, corp.acmedigital.local | Your names |
| WAN IPs and gateways | 203.0.113.x, 198.51.100.x (documentation ranges) | Static IPs from each ISP |
| ISP speeds | 1000/300, 500/200, 1000/500 Mbps | Contracted speeds |
| FortiLink and HA port names | internal1/2, x1/x2, internal7/8 | Ports on the delivered units |
| Switch serials | S148F-&lt;CODE&gt;-SERIAL-01 | Real serials |
| VPN users | 7 sample users | Export of the AD VPN groups |
| Secrets | Public `DEMO…` values in this repo | Real random keys from `generate.py --real-secrets` |

Open questions:

- Does each ISP provide static public IPs? The tunnel mesh assumes it. If an office only gets dynamic IPs, its tunnels change to dial-up with DDNS.
- Which hosting do the web and mobile apps use (AWS, Azure, on-prem staging)? A cloud VPC can join the mesh as a fourth BGP peer.
- Is the Beirut UPS sized for long power cuts? HA protects against a failed firewall, not a dark rack.
- Are any FortiGate CLI keywords different on the delivered build? The lab load in week 2 is where that shows up.

## Sources

- [FortiOS 7.6.7 – LDAP authentication with IKEv2 over UDP or TCP](https://docs.fortinet.com/document/fortigate/7.6.7/administration-guide/442351)
- [FortiOS 7.6.7 – Enforcing posture tags before dial-up IPsec](https://docs.fortinet.com/document/fortigate/7.6.7/administration-guide/109455/enforcing-security-posture-tag-match-before-dial-up-ipsec-vpn-connection)
- [Fortinet tip – IKEv2 dial-up with LDAP and FortiToken Cloud](https://community.fortinet.com/fortigate-3/technical-tip-dial-up-ipsec-ikev2-with-ldap-authentication-and-2fa-with-fortitoken-fortitoken-cloud-220763)
- [Fortinet tip – MFA with Windows FortiClient, LDAP and EAP-TTLS](https://community.fortinet.com/fortigate-3/technical-tip-multi-factor-authentication-support-for-windows-forticlient-with-ldap-eap-ttls-212498)
- [Fortinet tip – FortiOS 7.4/7.6 end-of-support dates](https://community.fortinet.com/fortigate-3/technical-tip-fortios-end-of-support-change-for-fortios-v7-4-and-v7-6-224876)
- [SSL VPN tunnel mode removed in FortiOS 7.6.3](https://dev.to/madhushan/fortios-763-update-ssl-vpn-tunnel-mode-no-longer-supported-27hg)
- [FortiOS 7.6.5 – Dynamic BGP on loopback, dual hub](https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/825080)
- [FortiGate 70G specifications (SHI)](https://www.shidirect.com/product/49371495/Fortinet-FortiGate-70G)
- [FortiGate 90G specifications (SHI)](https://www.publicsector.shidirect.com/product/46531574/Fortinet-FortiGate-90G)
- [FortiAP 231K Wi-Fi 7 specifications (SHI)](https://www.publicsector.shidirect.com/product/49880549/Fortinet-FortiAP-231K)
