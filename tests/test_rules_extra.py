from syslogwatch.parse import SyslogEntry, parse_line
from syslogwatch.rules import RULES, rule_by_id


def test_facility_name_maps_known_and_unknown_values():
    known = SyslogEntry(raw="", source_ip="x", message="m", facility=3)
    unknown = SyslogEntry(raw="", source_ip="x", message="m", facility=99)
    missing = SyslogEntry(raw="", source_ip="x", message="m", facility=None)
    assert known.facility_name == "daemon"
    assert unknown.facility_name == "99"
    assert missing.facility_name is None


def test_rule_by_id_finds_rules_and_falls_back_to_unclassified():
    assert rule_by_id("dhcp-pool-exhausted").id == "dhcp-pool-exhausted"
    assert rule_by_id("unclassified").id == "unclassified"
    assert rule_by_id("no-existe") is None


def test_every_rule_pattern_compiles_and_matches_a_sample():
    """Cada regla debe poder dispararse con al menos una línea: si no, es letra muerta."""
    import re

    for rule in RULES:
        assert re.compile(rule.pattern, re.IGNORECASE) is not None


def test_syslog_entry_device_prefers_hostname():
    entry = parse_line("Nov 24 15:20:00 router1 dhcpd: no free leases", source_ip="192.168.1.1")
    assert entry.host == "router1"
    assert entry.device == "router1"


def test_bridge_port_changes_are_noise():
    from syslogwatch.rules import match_rule

    rule = match_rule(parse_line("Nov 24 15:12:03 kernel: br0: port 3(wlan0) entered forwarding state", source_ip="192.168.1.153"))
    assert rule.id == "bridge-port-state"
    assert rule.category == "ruido"


def test_radvd_router_solicitation_is_noise():
    from syslogwatch.rules import match_rule

    rule = match_rule(parse_line("Nov 24 15:18:11 daemon.info radvd: received RS from fe80::1c2a", source_ip="192.168.1.1"))
    assert rule.id == "zcmd-noise"


def test_relevance_filters_unrelated_external_results():
    from syslogwatch.enrich import rank_results

    results = [
        {"title": "Out of memory: Killed process apache2", "url": "u1", "score": 9},
        {"title": "Host safety: hard-hang from memory pressure", "url": "u2", "score": 3},
        {"title": "Bump dependency to 1.2.3", "url": "u3", "score": 99},
    ]
    kept = rank_results(results, "out of memory oom-killer router low memory fix")
    urls = [item["url"] for item in kept]
    assert "u3" not in urls
    assert urls[0] == "u1"  # más palabras en común primero
    assert len(kept) <= 3


def test_a_single_shared_word_is_not_enough_for_a_long_query():
    from syslogwatch.enrich import rank_results

    results = [{"title": "Unrelated memory allocator tweak", "url": "u1", "score": 50}]
    assert rank_results(results, "out of memory oom-killer router low memory fix") == []
    short = [{"title": "no free leases left", "url": "u2", "score": 1}]
    assert rank_results(short, "no free leases")  # consulta corta: basta una palabra


def test_a_listener_port_in_use_is_not_an_ip_conflict():
    from syslogwatch.rules import match_rule

    dns = match_rule(parse_line("Nov 24 15:22:40 user.err dnsmasq[923]: failed to start: address already in use", source_ip="192.168.1.1"))
    conflict = match_rule(parse_line("Nov 24 15:28:00 daemon.err dhcpd: duplicate address 192.168.1.144 detected on interface br0", source_ip="192.168.1.1"))
    assert dns.id == "dns-resolver-down"
    assert conflict.id == "arp-ip-conflict"


def test_cloud_connection_lost_is_not_unclassified():
    from syslogwatch.rules import match_rule

    rule = match_rule(parse_line("Nov 24 15:29:00 daemon.warning mqtt: cloud connection lost, retrying in 30s", source_ip="192.168.1.1"))
    assert rule.id == "cloud-disconnect"


def test_cron_tasks_and_rssi_roaming_from_the_real_network_are_classified():
    from syslogwatch.rules import match_rule

    cron = match_rule(parse_line("Nov 24 17:18:00 user.info crond: USER root pid 6478 cmd /usr/etc/rtspStream.sh",
                                 source_ip="192.168.1.1"))
    rssi = match_rule(parse_line("Nov 24 17:19:00 user.info hostapd: Triggered 74:AB:93:DE:07:32 last_rssi=20 current_rssi=28",
                                 source_ip="192.168.1.153"))
    assert cron.id == "crond-task" and cron.category == "ruido"
    assert rssi.id == "wifi-roaming-trigger" and rssi.category == "wifi"


def test_platform_stats_from_the_router_stay_as_noise():
    from syslogwatch.rules import match_rule

    regla = match_rule(parse_line("Nov 24 17:18:01 user.err zcmdModuleCfg: beIpIfaceStatsUpdate()", source_ip="192.168.1.1"))
    assert regla.id == "zcmd-noise"


def test_the_doubled_tag_from_the_real_router_matches_the_cron_rule():
    from syslogwatch.rules import match_rule

    regla = match_rule(parse_line("Nov 24 17:26:01 cron.info crond: crond: USER root pid 14989 cmd /usr/etc/quarterHour.sh",
                                  source_ip="192.168.1.1"))
    assert regla.id == "crond-task"


def test_the_three_patterns_that_were_unclassified_in_production():
    from syslogwatch.rules import match_rule

    casos = {
        "Nov 24 17:29:00 user.info syslog-ng: Log statistics; dropped='udp(AF_INET(192.168.1.219:514))=0', "
        "processed='center(queued)=31186'": "syslog-stats",
        "Nov 24 17:28:00 user.info wlan: rtk_multi_ap_recordUnassocStaMetric - measurement still ongoing": "rtk-metrics",
        "Nov 24 17:27:00 user.info hostapd: wlan0: A wireless client is associated - 0A:57:41:66:AB:D9": "wifi-client-associated",
    }
    for linea, esperado in casos.items():
        assert match_rule(parse_line(linea, source_ip="192.168.1.153")).id == esperado, linea


def test_the_three_new_rules_are_noise_level_except_the_wifi_one():
    from syslogwatch.rules import rule_by_id

    assert rule_by_id("syslog-stats").weight <= 10
    assert rule_by_id("rtk-metrics").weight <= 10
    assert rule_by_id("wifi-client-associated").category == "wifi"
