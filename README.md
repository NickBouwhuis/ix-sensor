# ix-sensor

ix-sensor watches an IXP peering LAN for traffic that doesn't belong there and reports
it to [ix.watch](https://ix.watch), which lists the networks sending it.

A peering LAN should only carry IP unicast, ARP and IPv6 neighbour discovery between
member routers. The sensor flags everything else it can recognise:

| Type                           | What                                                                                                   |
| ------------------------------ | ------------------------------------------------------------------------------------------------------ |
| `ra`                           | IPv6 router advertisements                                                                             |
| `dhcp`, `dhcp6`                | DHCP client/server traffic (the port pair must match)                                                  |
| `lldp`, `cdp`, `stp`           | discovery protocols and spanning tree BPDUs                                                            |
| `mndp`, `mt-mactel`, `mt-loop` | MikroTik neighbour discovery, MAC-Telnet/Winbox, loop protect                                          |
| `syncthing`                    | Syncthing local discovery (a workstation bridged onto the LAN)                                         |
| `netmask`                      | IPv4 broadcast to a smaller subnet's broadcast address inside the LAN: the sender's prefix is too long |
| `v6-bcast`                     | IPv6 sent to the Ethernet broadcast address                                                            |
| `romon`, `ubnt`, `rarp`        | MikroTik RoMON, Ubiquiti discovery (UDP 10001), reverse ARP                                            |
| `broadcast`, `multicast`       | other L2 broadcast and multicast                                                                       |
| `arp-offlan`, `nd-offlan`      | ARP or IPv6 ND for a LAN address, sent from an address outside the LAN                                 |
| `arp-probe`                    | ARP probes (sender 0.0.0.0) for addresses outside the LAN                                              |

## What it sends

Per source (a MAC on an IX): counts per type, first and last seen, the MAC's IP if the
local neighbour table knows it, and the last few frames. For each frame that's the decoded
headers plus the raw frame (at most 1600 bytes), for the public pcap download. These are
frames the source sent to the whole peering LAN (broadcast or multicast), or to your router.
ix.watch resolves who owns the MAC.

Per IX, every minute: whether the capture is up, and how many frames it has read in all
(a count, no contents), for the frames-per-second figure on ix.watch.

## Add an IX to ix.watch

You're a member of an IXP that ix.watch doesn't watch yet, and you'd like it to. The sensor
runs on one of your machines, sees what reaches your port on the peering LAN, and reports it.
Your IXP then gets its own section on ix.watch, credited "via" your network.

### 0. You need

- **A Linux machine with an interface on the peering LAN.** Any of these works:
  - a Linux router with its IX port or VLAN, where the sensor runs alongside your routing daemon;
  - a server with its own port or VLAN on the IX;
  - a server that gets a mirror (SPAN) of your router's IX port.
- **Python 3.9 or newer** and **paho-mqtt**.
- **Root**, for the raw socket and promiscuous mode.
- **The IXP's peering LAN prefixes**, IPv4 and IPv6. They're on the IXP's PeeringDB page
  under "Prefixes".

The sensor uses next to no CPU: a kernel filter drops plain unicast IP before Python sees it.

### 1. Ask us for an account

Mail **noc at ix dot watch** with:

- your ASN and a contact for the sensor;
- the IXP's name, its PeeringDB page, and its peering LAN prefixes;
- how the sensor is connected (router, server port, or mirror).

You get back an MQTT username (your AS, like `as64500`) and a password. We add the IXP to
ix.watch and set the "via" credit on our side; the sensor doesn't send it.

### 2. Install the sensor

Clone this repository to `/opt/ix-sensor`; the service runs the sensor from there.

```sh
apt install git python3-paho-mqtt      # or: pip install paho-mqtt
git clone https://github.com/NickBouwhuis/ix-sensor.git /opt/ix-sensor
```

### 3. Find your peering interface

```sh
ip -br addr
```

It's the interface that carries your address on the IXP's LAN, for example `eth1.100` with
`193.239.117.42/22`. On a mirror port there's no address: use the interface the mirror
arrives on.

### 4. Write the config

Create `/etc/ix-sensor.json` with your interface, the IXP's name and prefixes, and the
account from step 1:

```json
{
  "name": "as64500",
  "interfaces": { "eth1.100": "NL-IX" },
  "prefixes": { "NL-IX": ["193.239.116.0/22", "2001:7f8:13::/64"] },
  "mqtt": { "url": "wss://mqtt.ix.watch/", "username": "as64500", "password": "..." },
  "state_file": "/var/lib/ix-sensor/state.json"
}
```

```sh
chmod 600 /etc/ix-sensor.json          # it holds the MQTT password
```

- `name` is your MQTT username.
- `interfaces` maps each peering LAN interface to the IXP's name. One sensor can watch several IXPs.
- `prefixes` is keyed by the same IXP name. The ARP and ND checks need it to tell what's on
  the LAN. Without it the sensor uses the interface's own addresses (none on a mirror port),
  and without those it turns those checks off.
- `state_file` keeps the counts across restarts. It's optional.
- `site` is only for running sensors on more than one host with the same account: give each
  host its own short `site` (like `"ams"` and `"fra"`). Without it, two hosts on one account
  keep knocking each other off the broker.

### 5. Run it once by hand

```sh
python3 /opt/ix-sensor/ixsensor.py --config /etc/ix-sensor.json
```

Within a few seconds you should see these lines (each after a timestamp and `INFO`):

```
ix-sensor as64500 watching eth1.100 (NL-IX)
Monitoring eth1.100 (NL-IX), ifindex 7, peering LAN 193.239.116.0/22, 2001:7f8:13::/64
MQTT connected as as64500; published 0 source states
```

Then a `New: ...` line for each source it catches, for example `New: ra from
44:4c:a8:ce:07:f3 on NL-IX`. A quiet LAN can take a while to show one. Stop it with Ctrl-C;
it saves its state and exits.

### 6. Run it as a service

```sh
cp /opt/ix-sensor/ix-sensor.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ix-sensor
journalctl -u ix-sensor -f             # the same lines as in step 5
```

### 7. Check it on ix.watch

Once we've added the IXP (step 1), it appears on [ix.watch](https://ix.watch): in the IXP
filter above the table, and as a line card in "The fabric", credited via your network. A
network caught on your IXP shows up in the table within seconds of the sensor seeing it.

### Updating and stopping

- **Update:** `git -C /opt/ix-sensor pull && systemctl restart ix-sensor`. The state file
  keeps the counts.
- **Stop:** `systemctl disable --now ix-sensor`, and mail us so we take the IXP off the site.

### If something's wrong

| Log line                                                | What to do                                                                                 |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `paho-mqtt is missing`                                  | Install it (step 2).                                                                       |
| `peering LAN unknown, ARP/ND address checks off`        | Add the IXP to `prefixes` (step 4). The other checks still run.                            |
| `MQTT connect refused (rc=4)` or `(rc=5)`               | The username or password is wrong. Check `name` and `mqtt` against our mail.               |
| `MQTT disconnected (rc=…), reconnecting`, over and over | The sensor can't reach `mqtt.ix.watch` on port 443. Check outbound HTTPS from the machine. |
| `BPF pre-filter on … not attached`                      | It still works, but sees all traffic, so it uses more CPU. Mail us the full line.          |
| `… changed: ifindex … reopening`                        | The interface was recreated (a VLAN or link flap). It picks it up again by itself.         |

## Changing the sensor

The detection rules are in `classify()` in `ixsensor.py`. ix.watch's own captures import
that same function, so every IXP is judged by the same rules, and a change here applies to all of
them. Keep the file importable without paho-mqtt. To suggest a new check or a fix, mail
noc at ix dot watch with a patch (`git format-patch`) or a pcap of the traffic it should
catch.

## License

MIT, see [LICENSE](LICENSE). The header in `ixsensor.py` carries it, so a copy of the single
file keeps its license. The ix.watch name and service are not covered by it.
