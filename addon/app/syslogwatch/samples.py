"""Corpus de demostración: mensajes reales de esta red y de los fallos típicos.

Sirve para ver el informe funcionando sin esperar a que algo se rompa. Están
marcados con el prefijo «DEMO» en el fichero de origen para no confundirlos con
tráfico recolectado de verdad.
"""

from __future__ import annotations

from typing import List

DEMO_CORPUS: List[str] = [
    # Router Digi (Zyxel EX3301-T0) — trazas internas reales observadas
    "Nov 24 15:16:47 user.info zcmdModuleCfg: zcmdTr181MtParmAttrQry: no request to retrieve mapping parameter",
    "Nov 24 15:16:48 user.info zcmdModuleCfg: beRaInfoIntfSetStatsUpdate()",
    "Nov 24 15:17:02 user.info zcmdModuleCfg: CONFIG: Saving config - OK",
    "Nov 24 15:18:11 daemon.info radvd: received RS from fe80::1c2a:8bff:fe44:2a10",
    "Nov 24 15:19:40 daemon.err dhcpd: DHCPDISCOVER from 3c:22:fb:11:22:33: no free leases",
    "Nov 24 15:19:41 daemon.err dhcpd: DHCPDISCOVER from 3c:22:fb:11:22:34: no free leases",
    "Nov 24 15:19:42 daemon.err dhcpd: DHCPDISCOVER from 3c:22:fb:11:22:35: no free leases",
    "Nov 24 15:19:55 daemon.err dhcpd: no address available for 3c:22:fb:11:22:36",
    "Nov 24 15:21:03 kern.err kernel: nf_conntrack: table full, dropping packet",
    "Nov 24 15:21:04 kern.err kernel: nf_conntrack: table full, dropping packet",
    "Nov 24 15:21:05 kern.err kernel: nf_conntrack: table full, dropping packet",
    "Nov 24 15:21:06 kern.err kernel: nf_conntrack: table full, dropping packet",
    "Nov 24 15:22:10 kern.crit kernel: Out of memory: Killed process 1188 (hostapd)",
    "Nov 24 15:22:11 kern.err kernel: hardware error: PCIe bus error severity=corrected",
    "Nov 24 15:22:40 user.err dnsmasq[923]: failed to start: address already in use",
    "Nov 24 15:23:00 user.warning ntp: no server suitable for synchronization found",
    "Nov 24 15:24:12 daemon.warning hostapd: wlan0: STA aa:bb:cc:dd:ee:ff WPA: 4-Way Handshake failed - pre-shared key may be incorrect",
    "Nov 24 15:24:13 daemon.warning hostapd: wlan0: STA aa:bb:cc:dd:ee:ff authentication failed",
    "Nov 24 15:25:00 daemon.info hostapd: wlan0: STA 72:8f:c1:2c:2c:5f deauthenticated (reason=3)",
    "Nov 24 15:25:41 daemon.notice hostapd: wlan1: radar detected on channel 120, switching to 44",
    "Nov 24 15:26:30 auth.warning httpd: login failed for user admin from 45.148.10.22",
    "Nov 24 15:26:31 auth.warning httpd: login failed for user admin from 45.148.10.22",
    "Nov 24 15:26:32 auth.warning httpd: too many failed attempts from 45.148.10.22",
    "Nov 24 15:27:00 kern.err kernel: EXT4-fs error (device mmcblk0p2): unable to read inode block",
    "Nov 24 15:27:20 kern.warning kernel: eth0: link is down",
    "Nov 24 15:27:23 kern.info kernel: eth0: link is up, 1000 Mbps full duplex",
    "Nov 24 15:28:00 daemon.err dhcpd: duplicate address 192.168.1.144 detected on interface br0",
    "Nov 24 15:29:00 daemon.warning mqtt: cloud connection lost, retrying in 30s",
    "Nov 24 15:30:00 user.info zcmdModuleCfg: CONFIG: Saving config - OK",
    # COVR-1100 (AP)
    "Nov 24 15:10:49 kernel: [expireEntryBlockList 208]BLOCK LIST STA EXPIRES (0) :[72][8f][c1][2c][2c][5f]",
    "Nov 24 15:10:49 kernel: [expireEntryBlockList 208]BLOCK LIST STA EXPIRES (0) :[72][8f][c1][2c][2c][5f]",
    "Nov 24 15:12:03 kernel: br0: port 3(wlan0) entered forwarding state",
    "Nov 24 15:12:44 daemon.warning hostapd: wlan1: STA 42:5c:f0:17:7a:48 deauthenticated (reason=4)",
]
