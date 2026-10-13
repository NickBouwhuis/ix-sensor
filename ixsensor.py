#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Nick Bouwhuis
"""ix-sensor: spot traffic that doesn't belong on an IXP peering LAN and ship it to
ix.watch (https://ix.watch) over MQTT.

It only detects and reports. Per source (MAC on an IX) it publishes counts, first/last
seen, the MAC's IP if the local neighbour table knows it, and the last few frames (the
decoded headers, plus the raw frame for ix.watch's pcap download). These are frames the
source broadcast to the whole peering LAN. ix.watch resolves who owns the MAC.

    apt install python3-paho-mqtt          # or: pip install paho-mqtt
    ixsensor.py --config /etc/ix-sensor.json

Config (mode 0600, it holds the MQTT password):
    {
      "name": "as64500",                                # your MQTT username
      "interfaces": { "eth1.100": "NL-IX" },           # peering LAN interface -> IX name
      "prefixes": { "NL-IX": ["193.239.116.0/22", "2001:7f8:13::/64"] },  # optional, see peering_lan()
      "mqtt": { "url": "wss://mqtt.ix.watch/", "username": "as64500", "password": "..." },
      "state_file": "/var/lib/ix-sensor/state.json",   # optional
      "site": "ams"                                    # optional: one per host sharing the name
    }

Needs root (raw sockets, promiscuous mode). Standard library + paho-mqtt only.

ix-watcher (bgp.rodeo's own watcher) imports the detection code from this file, so
every IX is judged by the same rules. Keep this file importable without paho.
"""

import ctypes
import fcntl
import base64
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import defaultdict, deque

log = logging.getLogger("ix-sensor")

# ======================================================================
# Detection (shared with ix-watcher)
# ======================================================================

ETH_P_ALL = 0x0003
IFF_PROMISC = 0x100
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
SO_ATTACH_FILTER = 26

# Kernel-side pre-filter for the capture socket (classic BPF, `tcpdump -dd` on an Ethernet link):
#   ether multicast or not (ip or ip6) or (ip and udp and (port 67 or port 68))
#   or (ip6 and (ip6 proto 58 or (udp and (port 546 or port 547))))
# A superset of everything classify() can flag; it only drops ordinary unicast IPv4/IPv6
# traffic, which classify() always returns None for. Without it the kernel copied every
# frame on the interface into Python: a full core on a router with six IX VLANs (2026-10-05).
CAPTURE_BPF = [
    (0x30, 0, 0, 0x00000000), (0x45, 27, 0, 0x00000001), (0x28, 0, 0, 0x0000000c), (0x15, 0, 11, 0x00000800),
    (0x30, 0, 0, 0x00000017), (0x15, 0, 22, 0x00000011), (0x28, 0, 0, 0x00000014), (0x45, 20, 0, 0x00001fff),
    (0xb1, 0, 0, 0x0000000e), (0x48, 0, 0, 0x0000000e), (0x15, 18, 0, 0x00000043), (0x15, 17, 0, 0x00000044),
    (0x48, 0, 0, 0x00000010), (0x15, 15, 0, 0x00000043), (0x15, 14, 13, 0x00000044), (0x15, 0, 13, 0x000086dd),
    (0x30, 0, 0, 0x00000014), (0x15, 11, 0, 0x0000003a), (0x15, 0, 2, 0x0000002c), (0x30, 0, 0, 0x00000036),
    (0x15, 8, 7, 0x0000003a), (0x15, 0, 6, 0x00000011), (0x28, 0, 0, 0x00000036), (0x15, 5, 0, 0x00000222),
    (0x15, 4, 0, 0x00000223), (0x28, 0, 0, 0x00000038), (0x15, 2, 0, 0x00000222), (0x15, 1, 0, 0x00000223),
    (0x6, 0, 0, 0x00000000), (0x6, 0, 0, 0x00040000),
]


def attach_prefilter(sock):
    """Attach CAPTURE_BPF to a raw socket (the kernel copies the program, buf can go away)."""
    prog = b"".join(struct.pack("HBBI", *ins) for ins in CAPTURE_BPF)
    buf = ctypes.create_string_buffer(prog, len(prog))
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER,
                    struct.pack("HL", len(CAPTURE_BPF), ctypes.addressof(buf)))


def mac_str(b):
    return ":".join(f"{x:02x}" for x in b)


def parse_frame(data):
    """Parse Ethernet frame -> (dst, src, ethertype, payload) or None."""
    if len(data) < 14:
        return None
    dst = mac_str(data[0:6])
    src = mac_str(data[6:12])
    etype = struct.unpack("!H", data[12:14])[0]
    payload = data[14:]
    if etype == 0x8100 and len(data) >= 18:  # 802.1Q
        etype = struct.unpack("!H", data[16:18])[0]
        payload = data[18:]
    return dst, src, etype, payload


def peering_lan(iface, configured=None):
    """The peering LAN's prefixes as [(version, network, netmask)] ints, for classify().

    The configured prefixes when given, else the interface's own global addresses. Host
    routes are left out of the latter: they'd make every other member look off-LAN.
    Empty means unknown, and classify() then skips the ARP/ND address checks."""
    cidrs = list(configured or [])
    if not cidrs:
        try:
            out = subprocess.run(["ip", "-j", "addr", "show", "dev", iface], capture_output=True, text=True, timeout=5).stdout
            for link in json.loads(out or "[]"):
                for a in link.get("addr_info", []):
                    if a.get("scope") == "global" and a["prefixlen"] < (31 if a["family"] == "inet" else 127):
                        cidrs.append(f"{a['local']}/{a['prefixlen']}")
        except Exception as e:
            log.warning(f"Reading the addresses of {iface} failed: {e}")
    nets = []
    for c in cidrs:
        n = ipaddress.ip_network(c, strict=False)
        nets.append((n.version, int(n.network_address), int(n.netmask)))
    return nets


def describe_lan(lan):
    if not lan:
        return "peering LAN unknown, ARP/ND address checks off"
    net_cls = {4: ipaddress.IPv4Network, 6: ipaddress.IPv6Network}
    return "peering LAN " + ", ".join(str(net_cls[v]((net, bin(mask).count("1")))) for v, net, mask in lan)


def _in_lan(lan, version, addr):
    a = int.from_bytes(addr, "big")
    return any(v == version and a & mask == net for v, net, mask in lan)


_LINK_LOCAL6 = (0xFE80 << 112, 0xFFC0 << 112)


def _lan_ok6(lan, addr):
    """An IPv6 address that may appear in ND on the LAN: unspecified, link-local or in the LAN."""
    a = int.from_bytes(addr, "big")
    return a == 0 or a & _LINK_LOCAL6[1] == _LINK_LOCAL6[0] or _in_lan(lan, 6, addr)


def _netmask_broadcast(lan, addr):
    """An IPv4 broadcast to an address inside the LAN that is the broadcast address of a
    smaller subnet (185.1.184.255 in a /23): the sender has a longer prefix than the IX's,
    so traffic for peers in the rest of the LAN goes out as broadcast."""
    a = int.from_bytes(addr, "big")
    for v, net, mask in lan:
        if v != 4 or a & mask != net:
            continue
        host_bits = 32 - bin(mask).count("1")
        ones = 0
        while ones < 32 and (a >> ones) & 1:
            ones += 1
        # Not the LAN's own broadcast (all host bits set); at least a /30's worth set.
        return 2 <= ones < host_bits
    return False


def classify(dst, src, etype, payload, lan=()):
    """Classify frame as violation type, or None if acceptable.

    lan is peering_lan() of the interface; without it ARP and ND aren't checked."""
    # ARP for a member's LAN address must come from the asker's own LAN address. A request from
    # a LAN address for one outside it isn't flagged: the target may be a second subnet on the
    # VLAN that PeeringDB doesn't list.
    # 0.0.0.0 as sender is an address-conflict probe (RFC 5227), and a host probes the address it
    # wants for itself, which on an IX is on the LAN. Probing addresses outside it is a router
    # checking addresses of its other ports or other networks (another IX's LAN) on this one.
    if etype == 0x0806:
        if len(payload) < 28 or payload[0:6] != b"\x00\x01\x08\x00\x06\x04":  # Ethernet/IPv4
            return None
        spa, tpa = payload[14:18], payload[24:28]
        if spa != b"\0\0\0\0" and _in_lan(lan, 4, tpa) and not _in_lan(lan, 4, spa):
            return "arp-offlan"
        # Only with an IPv4 prefix to compare against: on an IPv6-only LAN everything is "outside".
        if (spa == b"\0\0\0\0" and tpa != b"\0\0\0\0" and any(v == 4 for v, _, _ in lan)
                and not _in_lan(lan, 4, tpa)):
            return "arp-probe"
        return None

    # LLDP
    if etype == 0x88CC:
        return "lldp"

    # MikroTik loop detection
    if etype == 0x9003:
        return "mt-loop"

    # MikroTik MAC-Telnet / Winbox discovery
    if etype == 0x9998:
        return "mt-mactel"

    # MikroTik RoMON (Router Management Overlay Network)
    if etype == 0x88BF:
        return "romon"

    # Reverse ARP: something asking for its own IP address
    if etype == 0x8035:
        return "rarp"

    # STP / BPDU
    if dst.startswith("01:80:c2:00:00:0"):
        return "stp"

    # CDP
    if dst == "01:00:0c:cc:cc:cc":
        return "cdp"

    # IPv6 Router Advertisement
    if etype == 0x86DD and len(payload) >= 48:
        if payload[6] == 58 and payload[40] == 134:  # ICMPv6 type 134
            return "ra"

    # DHCPv4 — require the 67<->68 port pair, not just one side
    if etype == 0x0800 and len(payload) >= 28 and payload[9] == 17:
        ihl = (payload[0] & 0x0F) * 4
        if len(payload) >= ihl + 4:
            sport, dport = struct.unpack("!HH", payload[ihl:ihl + 4])
            if (sport == 67 and dport == 68) or (sport == 68 and dport == 67):
                return "dhcp"

    # DHCPv6 — require the 546<->547 port pair
    if etype == 0x86DD and len(payload) >= 48 and payload[6] == 17:
        if len(payload) >= 44:
            sport = struct.unpack("!H", payload[40:42])[0]
            dport = struct.unpack("!H", payload[42:44])[0]
            if (sport == 546 and dport == 547) or (sport == 547 and dport == 546):
                return "dhcp6"

    # MNDP / Syncthing — identify specific UDP broadcast protocols
    if dst == "ff:ff:ff:ff:ff:ff" and etype == 0x0800 and len(payload) >= 28 and payload[9] == 17:
        ihl = (payload[0] & 0x0F) * 4
        if len(payload) >= ihl + 4:
            sport, dport = struct.unpack("!HH", payload[ihl:ihl + 4])
            if sport == 5678 or dport == 5678:
                return "mndp"
            if dport == 21027:
                return "syncthing"
            if dport == 10001:
                return "ubnt"

    if dst == "ff:ff:ff:ff:ff:ff":
        # IPv6 has no broadcast: neighbour discovery uses solicited-node multicast.
        if etype == 0x86DD:
            return "v6-bcast"
        if etype == 0x0800 and len(payload) >= 20 and _netmask_broadcast(lan, payload[16:20]):
            return "netmask"
        # Non-ARP broadcast we don't have a more specific type for
        if etype != 0x0806:
            return "broadcast"

    # IPv6 NDP (Neighbor Solicitation/Advertisement) is normal on IX peering LANs. As with
    # ARP, only ND about a LAN address from a source that isn't (link-local, ::, or in the
    # LAN) is flagged.
    if etype == 0x86DD and len(payload) >= 41 and payload[6] == 58:
        icmp_type = payload[40]
        if icmp_type in (135, 136):  # NS / NA
            if len(payload) >= 64 and _in_lan(lan, 6, payload[48:64]) and not _lan_ok6(lan, payload[8:24]):
                return "nd-offlan"
            return None

    # Unknown multicast (skip IPv6 solicited-node 33:33:ff:* and all-nodes 33:33:00:*)
    # Also skip regular IPv4/IPv6 unicast traffic to MACs with the group bit set —
    # some vendors use such MACs for virtual interfaces on IX ports
    # ARP broadcasts are normal too: they skip the broadcast rule above and must not land here
    # (ix-watcher filters ARP before classify(); the standalone sensor loop did not).
    first = int(dst.split(":")[0], 16)
    if first & 1 and not dst.startswith("33:33:") and etype not in (0x0800, 0x86DD, 0x0806):
        return "multicast"

    return None


# Header decoding: headers only, never payload

ETHERTYPES = {0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP", 0x8035: "RARP", 0x88BF: "MikroTik RoMON", 0x88CC: "LLDP", 0x9003: "MikroTik loop detect",
              0x9998: "MikroTik MAC-Telnet", 0x8100: "802.1Q", 0x88A8: "802.1ad", 0x8809: "Slow protocols (LACP)"}
ARP_OPS = {1: "Request", 2: "Reply"}
IP_PROTOS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 89: "OSPF", 103: "PIM", 112: "VRRP"}
ICMP6_TYPES = {128: "Echo Request", 129: "Echo Reply", 130: "MLD Query", 131: "MLD Report", 133: "Router Solicitation",
               134: "Router Advertisement", 135: "Neighbor Solicitation", 136: "Neighbor Advertisement",
               137: "Redirect", 143: "MLDv2 Report"}
DHCP_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}


def _u16(b, o):
    return struct.unpack("!H", b[o:o + 2])[0]


def _u32(b, o):
    return struct.unpack("!I", b[o:o + 4])[0]


def _named(v, names):
    return f"{v} ({names[v]})" if v in names else str(v)


def decode_frame(data):
    """Decode L2-L4 headers into [{"layer": name, "fields": {...}}]. Never includes payload bytes."""
    layers = []
    if len(data) < 14:
        return layers
    eth = {"SrcMAC": mac_str(data[6:12]), "DstMAC": mac_str(data[0:6])}
    et, off = _u16(data, 12), 14
    if et == 0x8100 and len(data) >= 18:
        eth["VLAN"] = _u16(data, 14) & 0xFFF
        et, off = _u16(data, 16), 18
    p = data[off:]
    if et <= 1500:  # 802.3 length field: LLC (STP, CDP via SNAP, ...)
        eth["Length"] = et
        layers.append({"layer": "Ethernet", "fields": eth})
        if len(p) >= 3:
            layers.append({"layer": "LLC", "fields": {"DSAP": f"0x{p[0]:02x}", "SSAP": f"0x{p[1]:02x}", "Control": f"0x{p[2]:02x}"}})
            if p[0] == 0xAA and len(p) >= 8:
                oui, pid = p[3:6].hex(":"), _u16(p, 6)
                snap = {"OUI": oui, "ProtocolID": f"0x{pid:04x}"}
                if oui == "00:00:0c" and pid == 0x2000:
                    snap["Protocol"] = "CDP"
                layers.append({"layer": "SNAP", "fields": snap})
            elif p[0] == 0x42 and len(p) >= 7:
                layers.append({"layer": "STP", "fields": {"ProtocolID": _u16(p, 3), "Version": p[5], "BPDUType": f"0x{p[6]:02x}"}})
        return layers
    eth["EthernetType"] = f"0x{et:04x}" + (f" ({ETHERTYPES[et]})" if et in ETHERTYPES else "")
    layers.append({"layer": "Ethernet", "fields": eth})

    proto, l4 = None, b""
    if et == 0x0806 and len(p) >= 28 and p[0:6] == b"\x00\x01\x08\x00\x06\x04":
        layers.append({"layer": "ARP", "fields": {
            "Operation": _named(_u16(p, 6), ARP_OPS),
            "SenderMAC": mac_str(p[8:14]), "SenderIP": socket.inet_ntop(socket.AF_INET, p[14:18]),
            "TargetMAC": mac_str(p[18:24]), "TargetIP": socket.inet_ntop(socket.AF_INET, p[24:28])}})
    elif et == 0x0800 and len(p) >= 20:
        ihl = (p[0] & 0x0F) * 4
        proto, l4 = p[9], p[ihl:]
        layers.append({"layer": "IPv4", "fields": {
            "Version": p[0] >> 4, "IHL": ihl, "TOS": p[1], "Length": _u16(p, 2), "TTL": p[8],
            "Protocol": _named(p[9], IP_PROTOS),
            "SrcIP": socket.inet_ntop(socket.AF_INET, p[12:16]), "DstIP": socket.inet_ntop(socket.AF_INET, p[16:20])}})
    elif et == 0x86DD and len(p) >= 40:
        vtf = _u32(p, 0)
        proto, l4 = p[6], p[40:]
        layers.append({"layer": "IPv6", "fields": {
            "Version": vtf >> 28, "TrafficClass": (vtf >> 20) & 0xFF, "FlowLabel": vtf & 0xFFFFF,
            "Length": _u16(p, 4), "NextHeader": _named(p[6], IP_PROTOS), "HopLimit": p[7],
            "SrcIP": socket.inet_ntop(socket.AF_INET6, p[8:24]), "DstIP": socket.inet_ntop(socket.AF_INET6, p[24:40])}})

    if proto == 58 and len(l4) >= 4:
        t = l4[0]
        ic = {"Type": _named(t, ICMP6_TYPES), "Code": l4[1]}
        if t in (135, 136) and len(l4) >= 24:
            ic["TargetAddress"] = socket.inet_ntop(socket.AF_INET6, l4[8:24])
        if t == 134 and len(l4) >= 16:
            flags = l4[5]
            ic.update({"CurHopLimit": l4[4], "Flags": ("M" if flags & 0x80 else "") + ("O" if flags & 0x40 else "") or "none",
                       "RouterLifetime": _u16(l4, 6), "ReachableTime": _u32(l4, 8), "RetransTimer": _u32(l4, 12)})
            o, prefixes = 16, []
            while o + 2 <= len(l4):
                otype, olen = l4[o], l4[o + 1] * 8
                if olen == 0 or o + olen > len(l4):
                    break
                if otype == 1 and olen >= 8:
                    ic["SourceLinkAddr"] = mac_str(l4[o + 2:o + 8])
                elif otype == 3 and olen >= 32:
                    prefixes.append(f"{socket.inet_ntop(socket.AF_INET6, l4[o + 16:o + 32])}/{l4[o + 2]}")
                elif otype == 5 and olen >= 8:
                    ic["MTU"] = _u32(l4, o + 4)
                o += olen
            if prefixes:
                ic["Prefixes"] = ", ".join(prefixes)
        layers.append({"layer": "ICMPv6", "fields": ic})
    elif proto == 17 and len(l4) >= 8:
        sport, dport = _u16(l4, 0), _u16(l4, 2)
        layers.append({"layer": "UDP", "fields": {"SrcPort": sport, "DstPort": dport, "Length": _u16(l4, 4)}})
        d = l4[8:]
        if {sport, dport} == {67, 68} and len(d) >= 240 and d[236:240] == b"\x63\x82\x53\x63":
            dh = {"Op": "BOOTREQUEST" if d[0] == 1 else "BOOTREPLY", "XID": f"0x{_u32(d, 4):08x}"}
            o = 240
            while o + 2 <= len(d) and d[o] != 255:
                if d[o] == 0:
                    o += 1
                    continue
                if d[o] == 53 and d[o + 1] >= 1 and o + 2 < len(d):
                    dh["MessageType"] = _named(d[o + 2], DHCP_TYPES)
                o += 2 + d[o + 1]
            layers.append({"layer": "DHCP", "fields": dh})
    elif proto == 1 and len(l4) >= 2:
        layers.append({"layer": "ICMP", "fields": {"Type": l4[0], "Code": l4[1]}})
    elif proto == 6 and len(l4) >= 4:
        layers.append({"layer": "TCP", "fields": {"SrcPort": _u16(l4, 0), "DstPort": _u16(l4, 2)}})
    return layers


MAX_RAW = 1600  # bytes of each sampled frame kept for the public pcap download


def sampled_packet(ts, vtype, data):
    """A sampled frame as published: decoded headers for display, plus the raw bytes
    (capped) so bgp.rodeo can offer it as a pcap ("pcaps or it didn't happen")."""
    return {"ts": round(ts, 3), "type": vtype, "layers": decode_frame(data),
            "raw": base64.b64encode(data[:MAX_RAW]).decode()}


IFACE_CHECK = 30


def open_capture(iface):
    """Promiscuous raw socket on iface. Returns (socket, ifindex it is bound to)."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    try:
        sock.bind((iface, 0))
        ifindex = socket.if_nametoindex(iface)
        # Enable promiscuous mode to catch all L2 multicast
        ifreq = struct.pack("16sH", iface.encode(), 0)
        flags = struct.unpack("16sH", fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, ifreq))[1]
        ifreq = struct.pack("16sH", iface.encode(), flags | IFF_PROMISC)
        fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, ifreq)
        try:
            attach_prefilter(sock)
        except OSError as e:  # fail open: unfiltered is slower, never blinder
            log.warning(f"BPF pre-filter on {iface} not attached ({e}); capturing unfiltered")
        sock.settimeout(5)  # so recv() returns now and then and we can re-check the interface
        return sock, ifindex
    except Exception:
        sock.close()
        raise


# ======================================================================
# MQTT publishing (shared with ix-watcher)
# ======================================================================

class MqttPublisher:
    """Publishes under ixw/<name>/ (the broker only lets a user write under its own name):
         status                 retained {"online", "ixes": [{"ix", "up"}], "ts"}; last will flips online off
         <ix>/<mac>/state       retained full state of one source (absolute counts); empty when forgotten
         <ix>/<mac>/packet      each sampled frame, not retained
    get_status() -> dict and get_states() -> [(ix, mac, state)] are called on every (re)connect,
    so everything is republished and the broker needs no persistence.
    Several hosts can share one name, each with its own site: its status goes to status/<site>
    and its client id gets the site, so they don't take over each other's connection."""

    def __init__(self, cfg, name, get_status, get_states, site=None):
        import paho.mqtt.client as mqtt  # python3-paho-mqtt; 1.6 (Debian 12) and 2.x both work
        self.name, self.get_status, self.get_states = name, get_status, get_states
        self.site = self._seg(site) if site else None
        u = urllib.parse.urlparse(cfg["url"])
        ws = u.scheme in ("ws", "wss")
        tls = u.scheme in ("wss", "mqtts")
        client_id = f"ixw-{name}-{self.site}" if self.site else f"ixw-{name}"
        kwargs = {"client_id": client_id, "clean_session": True, "transport": "websockets" if ws else "tcp"}
        try:
            self.c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, **kwargs)
        except AttributeError:  # paho < 2
            self.c = mqtt.Client(**kwargs)
        if ws:
            self.c.ws_set_options(path=u.path or "/")
        if tls:
            self.c.tls_set()
        self.c.username_pw_set(cfg["username"], cfg["password"])
        self.c.will_set(self._status_t(), json.dumps({"online": False}), qos=1, retain=True)
        self.c.max_queued_messages_set(20000)
        self.c.reconnect_delay_set(1, 60)
        self.c.on_connect = self._on_connect
        self.c.on_disconnect = lambda c, ud, rc: log.warning(f"MQTT disconnected (rc={rc}), reconnecting")
        port = u.port or (443 if u.scheme == "wss" else 80 if ws else 8883 if tls else 1883)
        self.c.connect_async(u.hostname, port, keepalive=60)
        threading.Thread(target=self._run, name="mqtt", daemon=True).start()

    def _run(self):
        # Not loop_start(): paho 1.6 lets e.g. ssl.SSLEOFError from a send escape loop_forever,
        # which silently kills its thread and the watcher never publishes again (2026-10-01).
        # But paho only knows a loop thread exists through _thread (set by loop_start): with it
        # None, publish() writes to the socket from the calling thread, so sniffers, the status
        # timer and this loop all write the one TLS/websocket stream concurrently and corrupt it
        # (SSL BAD_LENGTH, "object cannot be re-sized", rc=7 flaps, then a wedged connection;
        # 2026-10-06). Claim it, so publish() only queues and wakes this thread to do the write.
        self.c._thread = threading.current_thread()
        first = True
        while True:
            try:
                if not first:
                    self.c.reconnect()
                first = False
                self.c.loop_forever(retry_first_connection=True)
            except Exception as e:
                log.warning(f"MQTT loop died ({e!r}), restarting it")
            time.sleep(5)

    @staticmethod
    def _seg(s):
        return re.sub(r"[/+#\s]", "_", str(s))

    def _t(self, *parts):
        return "/".join(["ixw", self._seg(self.name), *map(self._seg, parts)])

    def _status_t(self):
        return self._t("status", self.site) if self.site else self._t("status")

    def _on_connect(self, client, userdata, flags, rc):
        if rc != 0:
            log.error(f"MQTT connect refused (rc={rc}); check username/password")
            return
        states = self.get_states()
        if self.site:  # what this name sent before it had sites; another site's, now that it has
            self.c.publish(self._t("status"), b"", qos=1, retain=True)
        self.status()
        for ix, mac, st in states:
            self.state(ix, mac, st)
        log.info(f"MQTT connected as {self.name}; published {len(states)} source states")

    def status(self):
        self.c.publish(self._status_t(), json.dumps({"online": True, **self.get_status(), "ts": int(time.time())}),
                       qos=1, retain=True)

    def state(self, ix, mac, st):
        self.c.publish(self._t(ix, mac, "state"), json.dumps(st) if st else b"", qos=1, retain=True)

    def packet(self, event):
        self.c.publish(self._t(event["ix"], event["mac"], "packet"), json.dumps(event), qos=0)


# ======================================================================
# The sensor itself (only when run as a program)
# ======================================================================

class Sensor:
    MAX_AGE = 7 * 86400     # forget a source after a week without frames (the public page's window)
    RECENT = 5              # decoded frames kept per source
    SAMPLE = 2              # at most one decoded frame per (ix, type, mac) per this many seconds
    IFACE_CHECK = 30        # re-check the interface's ifindex this often; reopen if it was recreated

    def __init__(self, cfg):
        self.name = cfg["name"]
        self.ifaces = cfg["interfaces"]                      # iface -> IX name
        self.prefixes = cfg.get("prefixes", {})              # IX name -> peering LAN prefixes
        self.state_file = cfg.get("state_file", "/var/lib/ix-sensor/state.json")
        self.lock = threading.Lock()
        self.counts = defaultdict(int)                       # (ix, type, mac) -> frames
        self.first = {}                                      # (ix, type, mac) -> ts
        self.last = {}                                       # (ix, type, mac) -> ts
        self.sampled = {}                                    # (ix, type, mac) -> ts of last decode
        self.recent = {}                                     # (ix, mac) -> deque of decoded frames
        self.ips = {}                                        # (ix, mac) -> IP from the neighbour table
        self.up = {}                                         # ix -> capture healthy
        self.load()
        self.mqtt = MqttPublisher(cfg["mqtt"], self.name, self.status, self.all_states, site=cfg.get("site"))

    # -- state --
    def source(self, ix, mac):
        types = [{"type": vt, "count": n, "first": self.first[(vix, vt, vm)], "last": self.last[(vix, vt, vm)]}
                 for (vix, vt, vm), n in self.counts.items() if vix == ix and vm == mac]
        if not types:
            return None
        types.sort(key=lambda t: -t["last"])
        return {"ix": ix, "mac": mac, "types": types, "total": sum(t["count"] for t in types),
                "first": min(t["first"] for t in types), "last": max(t["last"] for t in types),
                "asn": "", "name": "", "ip": self.ips.get((ix, mac), ""),
                "recent": list(self.recent.get((ix, mac), []))}

    def all_states(self):
        with self.lock:
            return [(ix, mac, self.source(ix, mac)) for ix, mac in {(ix, mac) for ix, _, mac in self.counts}]

    def status(self):
        return {"ixes": [{"ix": ix, "up": bool(self.up.get(ix))} for ix in sorted(set(self.ifaces.values()))]}

    def save(self):
        with self.lock:
            st = {"counts": [[*k, n] for k, n in self.counts.items()],
                  "first": [[*k, t] for k, t in self.first.items()],
                  "last": [[*k, t] for k, t in self.last.items()],
                  "recent": [[*k, list(d)] for k, d in self.recent.items()],
                  "ips": [[*k, ip] for k, ip in self.ips.items()]}
        os.makedirs(os.path.dirname(self.state_file) or ".", exist_ok=True)
        tmp = self.state_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump(st, f)
        os.replace(tmp, self.state_file)

    def load(self):
        try:
            with open(self.state_file) as f:
                st = json.load(f)
        except FileNotFoundError:
            return
        except Exception as e:
            log.error(f"Ignoring unreadable state file {self.state_file}: {e}")
            return
        for ix, vt, mac, n in st.get("counts", []):
            self.counts[(ix, vt, mac)] = n
        for ix, vt, mac, t in st.get("first", []):
            self.first[(ix, vt, mac)] = t
        for ix, vt, mac, t in st.get("last", []):
            self.last[(ix, vt, mac)] = t
        for ix, mac, pkts in st.get("recent", []):
            self.recent[(ix, mac)] = deque(pkts, maxlen=self.RECENT)
        for ix, mac, ip in st.get("ips", []):
            self.ips[(ix, mac)] = ip
        log.info(f"Restored {len(self.counts)} violation series from {self.state_file}")

    # -- capture --
    def neighbour_ip(self, iface, mac):
        """The MAC's IP on the peering LAN, if we've talked to it (helps bgp.rodeo attribute it)."""
        try:
            out = subprocess.run(["ip", "neigh", "show", "dev", iface], capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                if mac in line.lower():
                    return line.split()[0]
        except Exception:
            pass
        return ""

    def capture(self, iface, ix):
        sock, bound, next_check = None, None, 0
        while True:
            if sock is None:
                try:
                    sock, bound = open_capture(iface)
                    self.up[ix] = True
                    lan = peering_lan(iface, self.prefixes.get(ix))
                    log.info(f"Monitoring {iface} ({ix}), ifindex {bound}, {describe_lan(lan)}")
                except Exception as e:
                    self.up[ix] = False
                    log.error(f"Failed to open {iface} ({ix}): {e}; retrying in 10s")
                    time.sleep(10)
                    continue
                next_check = time.time() + self.IFACE_CHECK
            if time.time() >= next_check:
                next_check = time.time() + self.IFACE_CHECK
                try:
                    current = socket.if_nametoindex(iface)
                except OSError:
                    current = None
                if current != bound:
                    log.warning(f"{iface} ({ix}) changed: ifindex {bound} -> {current}; reopening")
                    self.up[ix] = False
                    sock.close()
                    sock = None
                    continue
            try:
                data = sock.recv(65535)
            except socket.timeout:
                continue
            except OSError as e:
                log.error(f"Capture on {iface} ({ix}) failed: {e}; reopening")
                self.up[ix] = False
                sock.close()
                sock = None
                time.sleep(1)
                continue
            try:
                parsed = parse_frame(data)
                if not parsed:
                    continue
                dst, src, etype, payload = parsed
                vtype = classify(dst, src, etype, payload, lan)
                if vtype:
                    self.record(iface, ix, vtype, src, data)
            except Exception as e:
                log.error(f"Error on {iface}: {e}")

    def record(self, iface, ix, vtype, mac, data):
        key, now = (ix, vtype, mac), time.time()
        with self.lock:
            new = key not in self.counts
            self.counts[key] += 1
            self.last[key] = now
            self.first.setdefault(key, now)
            if now - self.sampled.get(key, 0) < self.SAMPLE:
                return
            self.sampled[key] = now
        if new or not self.ips.get((ix, mac)):
            self.ips[(ix, mac)] = self.neighbour_ip(iface, mac)
        if new:
            log.info(f"New: {vtype} from {mac} on {ix}")
        pkt = sampled_packet(now, vtype, data)
        with self.lock:
            self.recent.setdefault((ix, mac), deque(maxlen=self.RECENT)).appendleft(pkt)
            event = {"ix": ix, "mac": mac, "type": vtype, "count": self.counts[key], "first": self.first[key],
                     "ip": self.ips.get((ix, mac), ""), "packet": pkt}
            st = self.source(ix, mac)
        self.mqtt.packet(event)
        self.mqtt.state(ix, mac, st)

    # -- housekeeping --
    def housekeeping(self):
        while True:
            time.sleep(60)
            cutoff = time.time() - self.MAX_AGE
            with self.lock:
                old = [k for k, t in self.last.items() if t < cutoff]
                for k in old:
                    for d in (self.counts, self.first, self.last, self.sampled):
                        d.pop(k, None)
                changed = {(ix, mac) for ix, _, mac in old}
                states = []
                for ix, mac in changed:
                    st = self.source(ix, mac)
                    if not st:
                        self.recent.pop((ix, mac), None)
                        self.ips.pop((ix, mac), None)
                    states.append((ix, mac, st))
            for ix, mac, st in states:
                self.mqtt.state(ix, mac, st)
            self.mqtt.status()
            try:
                self.save()
            except Exception as e:
                log.error(f"Saving state failed: {e}")

    def run(self):
        for iface, ix in self.ifaces.items():
            threading.Thread(target=self.capture, args=(iface, ix), daemon=True).start()
        threading.Thread(target=self.housekeeping, daemon=True).start()
        # The handler only sets a flag: saving inside it deadlocks when a second signal
        # arrives mid-save (sudo relays SIGTERM, so a process can get it twice).
        stop = threading.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *a: stop.set())
        while not stop.wait(1):
            pass
        self.save()
        log.info("State saved, exiting")


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Report IX peering LAN violations to ix.watch")
    ap.add_argument("--config", default="/etc/ix-sensor.json")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    with open(args.config) as f:
        cfg = json.load(f)
    try:
        sensor = Sensor(cfg)
    except ImportError:
        sys.exit("paho-mqtt is missing: apt install python3-paho-mqtt (or pip install paho-mqtt)")
    log.info(f"ix-sensor {cfg['name']} watching {', '.join(f'{i} ({x})' for i, x in cfg['interfaces'].items())}")
    sensor.run()


if __name__ == "__main__":
    main()
