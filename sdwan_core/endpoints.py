"""Phase-1 endpoint catalogue: (key, category, GET path under /dataservice).

Grows in Phase 2/4 from the official 26.2 OpenAPI specs in
../API Structure/sdwan-api/. Keys are stable names used by checks.
"""

ENDPOINTS: list[tuple[str, str, str]] = [
    # 1 Inventory & baseline
    ("about", "inventory", "/dataservice/client/about"),
    ("server_info", "inventory", "/dataservice/client/server"),
    ("tenancy_mode", "inventory", "/dataservice/clusterManagement/tenancy/mode"),
    ("devices", "inventory", "/dataservice/device"),
    ("controllers", "inventory", "/dataservice/system/device/controllers"),
    ("vedges", "inventory", "/dataservice/system/device/vedges"),
    ("device_monitor", "inventory", "/dataservice/device/monitor"),
    # 2/3 Design & policy
    ("device_templates", "design", "/dataservice/template/device"),
    ("feature_templates", "design", "/dataservice/template/feature"),
    ("config_groups", "design", "/dataservice/v1/config-group"),
    ("policy_vsmart", "policy", "/dataservice/template/policy/vsmart"),
    ("policy_vedge", "policy", "/dataservice/template/policy/vedge"),
    ("policy_security", "policy", "/dataservice/template/policy/security"),
    ("policy_definitions_approute", "policy", "/dataservice/template/policy/definition/approute"),
    ("policy_definitions_data", "policy", "/dataservice/template/policy/definition/data"),
    ("policy_definitions_control", "policy", "/dataservice/template/policy/definition/control"),
    ("sla_classes", "policy", "/dataservice/template/policy/list/sla"),
    ("site_lists", "policy", "/dataservice/template/policy/list/site"),
    ("vpn_lists", "policy", "/dataservice/template/policy/list/vpn"),
    # 5 Security
    ("users", "security", "/dataservice/admin/user"),
    ("user_groups", "security", "/dataservice/admin/usergroup"),
    ("cert_summary", "security", "/dataservice/certificate/stats/summary"),
    ("cert_vedge_list", "security", "/dataservice/certificate/vedge/list"),
    ("cert_controllers", "security", "/dataservice/certificate/vsmart/list"),
    # 6 Health
    ("control_status", "health", "/dataservice/device/control/count"),
    ("bfd_summary", "health", "/dataservice/device/bfd/sites/summary"),
    ("alarms_count", "health", "/dataservice/alarms/count"),
    ("device_health", "health", "/dataservice/device/hardwarehealth/summary"),
    ("reboot_count", "health", "/dataservice/network/issues/rebootcount"),
    ("connections_summary", "health", "/dataservice/network/connectionssummary"),
    # 9 Lifecycle
    ("software_images", "lifecycle", "/dataservice/device/action/software"),
    # 10 Operability
    ("settings_org", "operability", "/dataservice/settings/configuration/organization"),
    ("cluster_health", "operability", "/dataservice/clusterManagement/health/status"),
    ("dr_status", "operability", "/dataservice/disasterrecovery/details"),
    ("sync_status", "operability", "/dataservice/template/device/syncstatus"),
]

ENDPOINTS += [
    # UX 2.0 (configuration groups / policy groups / feature profiles)
    ("policy_groups", "policy", "/dataservice/v1/policy-group"),
    ("topology_groups", "policy", "/dataservice/v1/topology-group"),
    ("fp_system", "design", "/dataservice/v1/feature-profile/sdwan/system"),
    ("fp_transport", "design", "/dataservice/v1/feature-profile/sdwan/transport"),
    ("fp_service", "design", "/dataservice/v1/feature-profile/sdwan/service"),
    ("fp_app_priority", "policy", "/dataservice/v1/feature-profile/sdwan/application-priority"),
    ("fp_topology", "policy", "/dataservice/v1/feature-profile/sdwan/topology"),
    # More UX 1.0 policy objects
    ("policy_definitions_qosmap", "policy", "/dataservice/template/policy/definition/qosmap"),
    ("policy_definitions_zbfw", "policy", "/dataservice/template/policy/definition/zonebasedfw"),
    ("policy_definitions_ips", "policy", "/dataservice/template/policy/definition/intrusionprevention"),
    ("policy_definitions_url", "policy", "/dataservice/template/policy/definition/urlfiltering"),
    ("policy_definitions_dns", "policy", "/dataservice/template/policy/definition/dnssecurity"),
    ("policy_definitions_hubspoke", "policy", "/dataservice/template/policy/definition/hubandspoke"),
    ("policy_definitions_mesh", "policy", "/dataservice/template/policy/definition/mesh"),
    ("policy_definitions_cflowd", "policy", "/dataservice/template/policy/definition/cflowd"),
    ("class_maps", "policy", "/dataservice/template/policy/list/class"),
    ("region_lists", "design", "/dataservice/template/policy/list/region"),
    # Fabric-wide state
    ("device_counters", "health", "/dataservice/device/counters"),
    ("device_status", "health", "/dataservice/device/status"),
    ("alarms", "health", "/dataservice/alarms"),
    ("unreachable", "health", "/dataservice/device/unreachable"),
    ("reboot_history", "health", "/dataservice/device/reboothistory/details"),
    ("cluster_list", "resilience", "/dataservice/clusterManagement/list"),
    ("aaa_manager", "security", "/dataservice/admin/aaa"),
    ("maintenance_window", "operability", "/dataservice/settings/configuration/maintenanceWindow"),
]

# Per-device calls. {sip} = system-ip, {uuid} = device uuid.
# scope: "controllers" (vsmart+vbond+vmanage), "edges", "all".
PER_DEVICE: list[tuple[str, str, str, str]] = [
    ("running_config", "security", "/dataservice/template/config/running/{uuid}"
     "|/dataservice/device/config?deviceId={sip}|/dataservice/device/config/html?deviceId={sip}", "all"),
    ("control_connections", "health", "/dataservice/device/control/connections?deviceId={sip}", "all"),
    ("system_status", "health", "/dataservice/device/system/status?deviceId={sip}", "all"),
    ("omp_summary", "health", "/dataservice/device/omp/summary?deviceId={sip}", "all"),
    ("omp_peers", "health", "/dataservice/device/omp/peers?deviceId={sip}", "edges"),
    ("bfd_sessions", "health", "/dataservice/device/bfd/sessions?deviceId={sip}", "edges"),
    ("wan_interfaces", "design", "/dataservice/device/control/waninterface?deviceId={sip}", "edges"),
    ("interfaces", "design", "/dataservice/device/interface?deviceId={sip}", "edges"),
    ("ntp_assoc", "operability", "/dataservice/device/ntp/associations?deviceId={sip}", "all"),
    ("crashlog", "health", "/dataservice/device/crashlog?deviceId={sip}", "all"),
    ("software", "lifecycle", "/dataservice/device/software?deviceId={sip}", "edges"),
]

import json as _json
import re
from urllib.parse import quote as _q


def _agg(hours: int, fields: list[str], metrics: list[str]) -> str:
    return _q(_json.dumps({
        "query": {"condition": "AND", "rules": [
            {"value": [str(hours)], "field": "entry_time", "type": "date", "operator": "last_n_hours"}]},
        "aggregation": {"field": [{"property": f, "sequence": i + 1} for i, f in enumerate(fields)],
                        "metrics": [{"property": m, "type": "avg"} for m in metrics]}}))


ENDPOINTS += [
    # 7 Performance (24 h tunnel quality, aggregated on the Manager – one call for the whole fabric)
    ("approute_24h", "performance", "/dataservice/statistics/approute/aggregation?query="
     + _agg(24, ["name", "local_color", "remote_color"], ["loss_percentage", "latency", "jitter"])),
    ("approute_color_24h", "performance", "/dataservice/statistics/approute/aggregation?query="
     + _agg(24, ["local_color"], ["loss_percentage", "latency", "jitter"])),
    ("tloc_util", "performance", "/dataservice/device/tlocutil"),
]
PER_DEVICE += [
    ("tunnel_stats", "performance", "/dataservice/device/tunnel/statistics?deviceId={sip}", "edges"),
]


# Bulk state API per key: (state types, fields the checks need).
# Tried first; if bulk fails or a required field is missing (bulk schemas differ by
# release and are a cached subset), the key falls back to its PER_DEVICE path.
# SystemStatus/Interface are NOT bulk: their bulk rows lack CPU/memory and bandwidth fields.
BULK: dict[str, tuple[list[str], list[str]]] = {
    "control_connections": (["ControlConnection"], ["state", "peer-type"]),
    "bfd_sessions": (["BFDSessions"], ["state", "transitions", "tx-interval", "detect-multiplier", "local-color", "color"]),
    "omp_peers": (["OMPPeer"], ["peer", "state"]),
    "software": (["Software"], ["version", "active"]),
}

ENDPOINTS += [
    # Lifecycle stage (Use / Optimize) inputs
    ("tags", "operability", "/dataservice/v1/tags"),
    ("cloudservices", "adoption", "/dataservice/settings/configuration/cloudservices"),
]

# ---- Extended checks (gap closure vs old projects) ----
ENDPOINTS += [
    ("licensing", "lifecycle", "/dataservice/msla/monitoring/licensedDeviceCount"),
    ("smart_licensing", "lifecycle", "/dataservice/smartLicensing/getUserSettings"),
    ("license_devices", "lifecycle", "/dataservice/msla/devices"),
    ("license_pools", "lifecycle", "/dataservice/msla/licenses"),
    ("license_distribution", "lifecycle", "/dataservice/msla/monitoring/licensedDistributionDetails"),
    ("auditlog", "security", "/dataservice/auditlog?query=" + _q(_json.dumps({"query": {"condition": "AND", "rules": [
        {"value": ["7"], "field": "entry_time", "type": "date", "operator": "last_n_days"}]}, "size": 5000}))),
    ("sig_tunnels", "security", "/dataservice/device/sig/getSigTunnelList"),
    ("if_24h", "performance", "/dataservice/statistics/interface/aggregation?query="
     + _agg(24, ["vdevice_name", "interface"], ["rx_kbps", "tx_kbps"]).replace("%22type%22%3A%20%22avg%22", "%22type%22%3A%20%22max%22")),
]
PER_DEVICE += [
    ("bgp_neighbors", "health", "/dataservice/device/bgp/neighbors?deviceId={sip}", "edges"),
    ("ospf_neighbors", "health", "/dataservice/device/ospf/neighbor?deviceId={sip}", "edges"),
    ("control_history", "health", "/dataservice/device/control/connectionshistory?deviceId={sip}", "edges"),
    ("ipsec_outbound", "security", "/dataservice/device/ipsec/outbound?deviceId={sip}", "edges"),
    ("attached_config", "operability", "/dataservice/template/config/attached/{uuid}?type=CFS", "edges"),
]
BULK.update({
    "bgp_neighbors": (["BGPNeighbor"], ["peer-addr"]),
    "ospf_neighbors": (["OSPFNeighbor"], ["neighbor-id"]),
})

# Per device template detail (feature templates it is built from, policy, CLI text) – needed for
# the device template view (router/block diagrams, duplicates). All device templates are read.
PER_TEMPLATE: list[tuple[str, str]] = [
    ("device_template_objects", "/dataservice/template/device/object/{id}"),
]

# Per configuration group: attached devices; per unique feature profile: its features (parcels) with settings.
# The shared policy-object profile is skipped (thousands of objects; listed with its count only).
CG_SKIP_PROFILE_TYPES = {"policy-object"}
_TYPE_OK = re.compile(r"[a-z][a-z-]{0,40}")
_ID_OK = re.compile(r"[A-Za-z0-9_.:-]{1,80}")


def config_group_jobs(results) -> list[tuple[str, dict[str, str]]]:
    """[(key, {id: GET path})] for config-group devices and feature-profile details, from 'config_groups'."""
    r = next((r for r in results if r.key == "config_groups" and r.ok), None)
    rows = ((r.data.get("data") if isinstance(r.data, dict) else r.data) or []) if r else []
    groups = [g for g in rows if isinstance(g, dict) and _ID_OK.fullmatch(str(g.get("id") or "")) and ".." not in str(g["id"])]
    devs = {g["id"]: f"/dataservice/v1/config-group/{g['id']}/device/associate" for g in groups}
    profs = {}
    for g in groups:
        for p in g.get("profiles") or []:
            t, sol = str(p.get("type") or ""), str(p.get("solution") or g.get("solution") or "sdwan")
            if _ID_OK.fullmatch(str(p.get("id") or "")) and ".." not in str(p["id"]) and _TYPE_OK.fullmatch(t) and _TYPE_OK.fullmatch(sol) and t not in CG_SKIP_PROFILE_TYPES:
                profs[p["id"]] = f"/dataservice/v1/feature-profile/{sol}/{t}/{p['id']}?details=true"
    return [("config_group_devices", devs), ("feature_profiles", profs)]


# Keys collected per id outside ENDPOINTS (config groups); counted by collection_count().
PER_ID_KEYS = ["config_group_devices", "feature_profiles", "feature_parcels", "dr_info"]

# Manager disaster recovery detail: small GETs stored together as one data set ("dr_info", per_id by name).
# On Managers without DR some of them answer with an error; the data set counts as read when any succeeds.
DR_PATHS: dict[str, str] = {
    "status": "/dataservice/disasterrecovery/status",            # drStatus: drenabled, pauseDR, pauseReplication
    "datacenters": "/dataservice/disasterrecovery/drstatus",     # [{dcPersonality, mgmtIPAddress}]
    "schedule": "/dataservice/disasterrecovery/schedule",        # schedule: interval, startTime, delayThreshold
    "last_switch": "/dataservice/disasterrecovery/localLatestHistory",  # lastSwitch, reasonForSwitch, updatedPrimary
    "remote_dc": "/dataservice/disasterrecovery/remotedc",       # [{name, ip, state, ...}]
    "history": "/dataservice/disasterrecovery/history",
}


def collection_count() -> int:
    """Number of distinct data sets the collector reads; a change means a new collector version (see live_ui.CHANGELOG)."""
    return len(ENDPOINTS) + len(PER_DEVICE) + len(PER_TEMPLATE) + len(PER_ID_KEYS)


_PARCEL_OK = re.compile(r"[a-z0-9][a-z0-9/-]{0,60}")


def parcel_jobs(results) -> dict[str, str]:
    """{parcel id: GET path} for features whose settings were not included in the profile details."""
    r = next((r for r in results if r.key == "feature_profiles" and r.ok), None)
    out = {}
    for pid, body in ((r.data or {}).get("per_id") or {}).items() if r else []:
        if not isinstance(body, dict):
            continue
        sol, typ = str(body.get("solution") or "sdwan"), str(body.get("profileType") or "")
        for x in body.get("associatedProfileParcels") or []:
            pt, xid = str(x.get("parcelType") or ""), x.get("parcelId")
            if xid and _ID_OK.fullmatch(str(xid)) and ".." not in str(xid) and _ID_OK.fullmatch(str(pid)) and not (x.get("payload") or {}).get("data") and _TYPE_OK.fullmatch(sol) and _TYPE_OK.fullmatch(typ) \
                    and _PARCEL_OK.fullmatch(pt) and ".." not in pt:
                if sol == "sd-routing":  # SD-Routing features are typed "ntp-sd-routing" but addressed as ".../ntp/{id}"
                    pt = pt.removesuffix("-sd-routing")
                out[xid] = f"/dataservice/v1/feature-profile/{sol}/{typ}/{pid}/{pt}/{xid}"
    return out


def template_ids(results) -> list[str]:
    """Ids of all device templates, from the collected 'device_templates' result."""
    r = next((r for r in results if r.key == "device_templates" and r.ok), None)
    rows = ((r.data.get("data") if isinstance(r.data, dict) else r.data) or []) if r else []
    return [t["templateId"] for t in rows if isinstance(t, dict) and t.get("templateId")]


# ---- Traffic & utilisation (1.7.0): top applications, top talkers, WAN circuit utilisation – 7 days ----
# All aggregated on the Manager (one call each for the whole fabric). App data comes from app recognition
# (SAIE/DPI); routers without it simply contribute nothing.
TRAFFIC_HOURS = 168
TRAFFIC_ROUTERS_MAX = 500


def _last(hours: int = TRAFFIC_HOURS) -> dict:
    return {"condition": "AND", "rules": [{"value": [str(hours)], "field": "entry_time", "type": "date", "operator": "last_n_hours"}]}


def _top(field: str, metric: str, size: int, hours: int = TRAFFIC_HOURS) -> str:
    """Biggest `size` values of `field` by summed `metric` (sorted on the Manager)."""
    return _q(_json.dumps({"query": _last(hours), "aggregation": {
        "field": [{"property": field, "sequence": 1, "size": size}],
        "metrics": [{"property": metric, "type": "sum", "order": "desc"}]}}))


def _ifagg(metrics: list[tuple[str, str]], hours: int = TRAFFIC_HOURS) -> str:
    return _q(_json.dumps({"query": _last(hours), "aggregation": {
        "field": [{"property": "vdevice_name", "sequence": 1}, {"property": "interface", "sequence": 2}],
        "metrics": [{"property": m, "type": t} for m, t in metrics]}}))


ENDPOINTS += [
    ("traffic_apps", "performance", "/dataservice/statistics/dpi/applications/summary?limit=20&query=" + _q(_json.dumps({"query": _last()}))),
    # same from the raw app records – fallback for Managers without the summary call
    ("traffic_app_agg", "performance", "/dataservice/statistics/dpi/aggregation?query=" + _top("application", "octets", 20)),
    ("traffic_families", "performance", "/dataservice/statistics/dpi/aggregation?query=" + _top("family", "octets", 15)),
    ("traffic_src", "performance", "/dataservice/statistics/dpi/aggregation?query=" + _top("source_ip", "octets", 50)),
    ("traffic_dst", "performance", "/dataservice/statistics/dpi/aggregation?query=" + _top("dest_ip", "octets", 50)),
    ("traffic_routers", "performance", "/dataservice/statistics/dpi/aggregation?query=" + _top("host_name", "octets", TRAFFIC_ROUTERS_MAX)),
    ("if_7d_avg", "performance", "/dataservice/statistics/interface/aggregation?query="
     + _ifagg([("rx_kbps", "avg"), ("tx_kbps", "avg"), ("bw_down", "max"), ("bw_up", "max")])),
    ("if_7d_peak", "performance", "/dataservice/statistics/interface/aggregation?query=" + _ifagg([("rx_kbps", "max"), ("tx_kbps", "max")])),
]
ENDPOINTS += [
    # overlay: 7-day volume per tunnel end-point pair (tx = sent by local, rx = received by local)
    ("tunnel_pairs", "performance", "/dataservice/statistics/approute/aggregation?query=" + _q(_json.dumps({"query": _last(), "aggregation": {
        "field": [{"property": "local_system_ip", "sequence": 1}, {"property": "remote_system_ip", "sequence": 2}],
        "metrics": [{"property": "tx_octets", "type": "sum"}, {"property": "rx_octets", "type": "sum"}]}}))),
]


def _top_by_router(field: str, size: int = 20) -> str:
    """Top `size` values of `field` per router (host_name), by bytes – one call for the whole network."""
    return _q(_json.dumps({"query": _last(), "aggregation": {
        "field": [{"property": "host_name", "sequence": 1, "size": TRAFFIC_ROUTERS_MAX}, {"property": field, "sequence": 2, "size": size}],
        "metrics": [{"property": "octets", "type": "sum", "order": "desc"}]}}))


ENDPOINTS += [
    # top talkers per router (→ per site): who sends / receives most behind each router
    ("traffic_src_by_router", "performance", "/dataservice/statistics/dpi/aggregation?query=" + _top_by_router("source_ip")),
    ("traffic_dst_by_router", "performance", "/dataservice/statistics/dpi/aggregation?query=" + _top_by_router("dest_ip")),
]

# ---- Hourly time series (second round, after the per-device data is in; bounded) ----
SERIES_KEYS = ["circuit_series", "tunnel_series", "site_pair_series", "app_series", "app_flows"]
FLOW_IPS = 100  # per router: top destination / source IPs, each with its top applications (keeps each read light)
PER_ID_KEYS += SERIES_KEYS
SITE_PAIRS_MAX = 200
APPS_PER_BUCKET = 15
_HOURLY = {"property": "entry_time", "type": "hour", "interval": 1, "order": "asc"}
# tunnel volume plus quality (hourly averages of what the routers measure with BFD) – same query, no extra call
_TUN_METRICS = [("tx_octets", "sum"), ("rx_octets", "sum"), ("loss_percentage", "avg"), ("latency", "avg"), ("jitter", "avg")]


def _in(field: str, values) -> dict:
    return {"value": [str(v) for v in values], "field": field, "type": "string", "operator": "in"}


def _series(stat: str, rules: list[dict], metrics: list[tuple[str, str]], field: str | list[str] | None = None, size: int | None = None) -> str:
    agg = {"metrics": [{"property": m, "type": t} for m, t in metrics], "histogram": _HOURLY}
    if field:
        fields = [field] if isinstance(field, str) else field
        agg["field"] = [{"property": f, "sequence": i + 1, **({"size": size} if size else {})} for i, f in enumerate(fields)]
    q = _last()
    q["rules"] = q["rules"] + rules
    return f"/dataservice/statistics/{stat}/aggregation?query=" + _q(_json.dumps({"query": q, "aggregation": agg}))


def _rows(results, key) -> list:
    r = next((r for r in results if r.key == key and r.ok), None)
    d = (r.data.get("data", r.data) if isinstance(r.data, dict) else r.data) if r else None
    return d if isinstance(d, list) else []


def _per_device(results, key) -> dict:
    r = next((r for r in results if r.key == key and r.ok), None)
    return ((r.data or {}).get("per_device") or {}) if r else {}


_IP_OK = re.compile(r"[0-9A-Fa-f.:]{3,45}")
_SAFE_IF = re.compile(r"[A-Za-z0-9/._:-]{1,80}")
_SITE_OK = re.compile(r"[0-9]{1,10}")
_SAFE_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,80}")


def site_pair_key(a: str, b: str) -> tuple[str, str]:
    """Order of a site pair (shorter id first, then text) – the same everywhere so pair ids always match."""
    return tuple(sorted((a, b), key=lambda s: (len(s), s)))


def series_jobs(results) -> list[tuple[str, dict[str, str]]]:
    """[(key, {id: GET path})] for the hourly 7-day series: WAN circuits and tunnels per router (routers already
    sampled for per-device data), the busiest SITE_PAIRS_MAX site pairs, and applications (fabric + per router with
    app recognition). Only names/IPs that look safe are put into a query."""
    devs = [d for d in _rows(results, "devices") if isinstance(d, dict)]
    by_host = {d.get("host-name"): d for d in devs}
    site_of = {d.get("system-ip"): str(d.get("site-id") or "") for d in devs if d.get("personality") == "vedge"}
    circ, tun = {}, {}
    for host, body in _per_device(results, "wan_interfaces").items():
        sip = (by_host.get(host) or {}).get("system-ip")
        rows = body.get("data", body) if isinstance(body, dict) else body
        ifs = sorted({str(w.get("interface")) for w in rows or [] if isinstance(w, dict) and w.get("interface")})
        ifs = [i for i in ifs if _SAFE_IF.fullmatch(i)]
        if not sip or not _IP_OK.fullmatch(str(sip)):
            continue
        if ifs:
            circ[sip] = _series("interface", [_in("vdevice_name", [sip]), _in("interface", ifs)],
                                [("rx_kbps", "avg"), ("tx_kbps", "avg")], "interface")
        tun[sip] = _series("approute", [_in("local_system_ip", [sip])], _TUN_METRICS, "local_color")
    vol: dict[tuple[str, str], float] = {}
    for r in _rows(results, "tunnel_pairs"):
        a, b = site_of.get(r.get("local_system_ip")), site_of.get(r.get("remote_system_ip"))
        if a and b and a != b:
            k = site_pair_key(a, b)
            vol[k] = vol.get(k, 0) + float(r.get("tx_octets") or 0) + float(r.get("rx_octets") or 0)
    ips = {}
    for sip, s in site_of.items():
        if _IP_OK.fullmatch(str(sip)):
            ips.setdefault(s, []).append(sip)
    pairs = {}
    for (a, b), _v in sorted(vol.items(), key=lambda kv: -kv[1])[:SITE_PAIRS_MAX]:
        if a in ips and b in ips and _SITE_OK.fullmatch(a) and _SITE_OK.fullmatch(b):
            pairs[f"{a}_{b}"] = _series("approute", [_in("local_system_ip", ips[a]), _in("remote_system_ip", ips[b])],
                                        _TUN_METRICS, ["local_system_ip", "remote_system_ip", "local_color", "remote_color"])  # per tunnel
    apps, flows = {}, {}
    top = [a for a in (str(r["application"]) for r in _rows(results, "traffic_app_agg") if r.get("application"))
           if _SAFE_IF.fullmatch(a)][:APPS_PER_BUCKET]  # filter unsafe names first, then keep the top N
    if top:
        apps["fabric"] = _series("dpi", [_in("application", top)], [("octets", "sum")], "application")
    sampled = set(_per_device(results, "wan_interfaces"))  # the routers already sampled for per-device data (max_edges)
    for r in _rows(results, "traffic_routers"):
        h = str(r.get("host_name") or "")
        if h in by_host and h in sampled and _SAFE_NAME.fullmatch(h):  # same router limit as the other per-router data
            apps[h] = _series("dpi", [_in("host_name", [h])], [("octets", "sum")], "application", APPS_PER_BUCKET)
            # 7-day totals for the router: applications per destination / source IP (→ per remote site via its LAN subnets)
            # and per tunnel encapsulation (through a tunnel vs direct Internet breakout)
            for kind, fields in (("dst", [("dest_ip", FLOW_IPS), ("application", 10)]), ("src", [("source_ip", FLOW_IPS), ("application", 10)]),
                                 ("encap", [("tunnel_encap", 5), ("application", 20)])):
                flows[f"{h}:{kind}"] = "/dataservice/statistics/dpi/aggregation?query=" + _q(_json.dumps({
                    "query": {**_last(), "rules": _last()["rules"] + [_in("host_name", [h])]},
                    "aggregation": {"field": [{"property": f, "sequence": i + 1, "size": sz} for i, (f, sz) in enumerate(fields)],
                                    "metrics": [{"property": "octets", "type": "sum", "order": "desc"}]}}))
    return [("circuit_series", circ), ("tunnel_series", tun), ("site_pair_series", pairs), ("app_series", apps), ("app_flows", flows)]

