# airodump

Minimal airodump-style monitor.

## Syntax

```text
airodump <interface>
```

## Sample

```text
airodump mon0
```

The monitor displays Beacon BSSID, PWR, Beacons, #Data, ENC, and ESSID.
It also displays Stations and Probe Request ESSIDs. PWR is read from the
Radiotap Antenna Signal field.

## Build

```bash
qmake airodump.pro
make
./airodump mon0
```

Use a monitor-mode interface on a network you own or are authorized to test.
