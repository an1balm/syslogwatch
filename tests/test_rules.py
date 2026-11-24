from syslogwatch.parse import parse_line
from syslogwatch.rules import RULES, match_rule


def _entry(text, ip="192.168.1.1"):
    return parse_line(text, source_ip=ip)


def test_every_rule_has_a_complete_and_unique_definition():
    ids = [rule.id for rule in RULES]
    assert len(ids) == len(set(ids)), "ids duplicados"
    for rule in RULES:
        assert rule.title and rule.category and rule.cause and rule.fix, rule.id
        assert 0 <= rule.weight <= 100, rule.id
        assert rule.query, rule.id


def test_dhcp_pool_exhaustion_is_recognised_as_critical():
    rule = match_rule(_entry("Nov 24 15:20:00 daemon.err dhcpd: DHCPDISCOVER from 00:11:22:33:44:55: no free leases"))
    assert rule.id == "dhcp-pool-exhausted"
    assert rule.weight >= 80


def test_wifi_handshake_failure_is_recognised():
    rule = match_rule(_entry("Nov 24 15:21:00 daemon.warning hostapd: wlan0: STA aa:bb:cc:dd:ee:ff WPA: 4-Way Handshake failed - pre-shared key may be incorrect"))
    assert rule.id == "wifi-handshake-failed"
    assert rule.category == "wifi"


def test_kernel_hardware_fault_outranks_a_config_save():
    kernel = match_rule(_entry("Nov 24 15:22:00 kern.crit kernel: hardware error: PCIe bus error severity=corrected"))
    saved = match_rule(_entry("Nov 24 15:23:00 user.info zcmdModuleCfg: CONFIG: Saving config - OK"))
    assert kernel.id == "kernel-hardware-error"
    assert saved.id == "config-save-ok"
    assert kernel.weight > saved.weight


def test_zcmd_noise_from_the_digi_router_is_classified_as_noise():
    rule = match_rule(_entry("Nov 24 15:16:47 user.info zcmdModuleCfg: zcmdTr181MtParmAttrQry: no request to retrieve mapping parameter"))
    assert rule.category == "ruido"
    assert rule.weight <= 15


def test_unknown_message_falls_back_to_the_unclassified_rule():
    rule = match_rule(_entry("Nov 24 15:24:00 user.info somethingelse: purple monkey dishwasher"))
    assert rule.id == "unclassified"
    assert rule.category == "desconocido"


def test_matching_ignores_case_and_looks_at_app_plus_message():
    rule = match_rule(_entry("Nov 24 15:25:00 daemon.err DNSMASQ: FAILED to start up"))
    assert rule.id == "dns-resolver-down"
