# ix-sensor

ix-sensor watches an IXP peering LAN for traffic that doesn't belong there and reports
it to [ix.watch](https://ix.watch), which lists the networks sending it.

A peering LAN should only carry IP unicast, ARP and IPv6 neighbour discovery between
member routers. The sensor flags everything else it can recognise:

| Type | What |
|---|---|
| `ra` | IPv6 router advertisements |
| `dhcp`, `dhcp6` | DHCP client/server traffic (the port pair must match) |
| `lldp`, `cdp`, `stp` | discovery protocols and spanning tree BPDUs |
| `mndp`, `mt-mactel`, `mt-loop` | MikroTik neighbour discovery, MAC-Telnet/Winbox, loop protect |
| `syncthing` | Syncthing local discovery (a workstation bridged onto the LAN) |
| `netmask` | IPv4 broadcast to a smaller subnet's broadcast address inside the LAN: the sender's prefix is too long |
| `v6-bcast` | IPv6 sent to the Ethernet broadcast address |
| `romon`, `ubnt`, `rarp` | MikroTik RoMON, Ubiquiti discovery (UDP 10001), reverse ARP |
| `broadcast`, `multicast` | other L2 broadcast and multicast |
| `arp-offlan`, `nd-offlan` | ARP or IPv6 ND for a LAN address, sent from an address outside the LAN |

## What it sends

Per source (a MAC on an IX): counts per type, first and last seen, the MAC's IP if the
local neighbour table knows it, and the last few frames. For each frame that's the decoded
headers plus the raw frame (at most 1600 bytes), for the public pcap download. These are
frames the source sent to the whole peering LAN (broadcast or multicast), or to your router.
ix.watch resolves who owns the MAC.

## Install

Python 3.9+ on Linux, standard library plus paho-mqtt. Needs root (raw sockets,
promiscuous mode).

```sh
apt install python3-paho-mqtt          # or: pip install paho-mqtt
install -m 755 ixsensor.py /usr/local/bin/ixsensor.py
install -m 600 ix-sensor.json /etc/ix-sensor.json
cp ix-sensor.service /etc/systemd/system/ && systemctl enable --now ix-sensor
```

`/etc/ix-sensor.json` (mode 0600, it holds the MQTT password; ask us for an account):

```json
{
  "name": "as64500",
  "interfaces": { "eth1.100": "NL-IX" },
  "prefixes": { "NL-IX": ["193.239.116.0/22", "2001:7f8:13::/64"] },
  "mqtt": { "url": "wss://mqtt.bgp.rodeo/", "username": "as64500", "password": "..." },
  "state_file": "/var/lib/ix-sensor/state.json"
}
```

- `interfaces` maps the peering LAN interface to the IX name.
- `prefixes` is optional. The ARP/ND checks need the IX's prefixes. Without this entry the
  sensor uses the interface's own global addresses, and without those the checks are off.
  It logs the prefixes it uses at startup (`Monitoring … peering LAN …`).

A kernel BPF filter drops plain unicast IP before it reaches Python, so the sensor uses
little CPU even on busy LANs.

## License

MIT, see [LICENSE](LICENSE). The header in `ixsensor.py` carries it, so a copy of the single
file keeps its license. The ix.watch name and service are not covered by it.
