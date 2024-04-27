# Roca2pcap.

Some Roku gear creates "roca" files for packet dump level debugs. These files like look.

```
1714050818223,0,0,2048,CAAAAAAAAAIAAQAGdKy5qFyfAABFAABUAAAAAHMBiAsICAgIrBsDcwAAVThligADRlwqZgAAAAAMpQkAAAAAABAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc=
```

There is no official documentation, but it appears to be.

```
<TIME>,<PACKET_COUNT>,0,<ETHERTYPE>,<PACKET>
```

- `<TIME>` is the number of milliseconds since the unix epoch.
- `<PACKET_COUNT>` is 0 for the first packet that matches a time, 1 for the second and so on.
- The third field appears to always be zero.
- `<ETHERTYPE>` is the ieee802 ethernet type in decimal (so 2048 = 0x0800 = IPv4)
- `<PACKET>` is the raw bytes of the packet, encoded in Base64 format.

This program converts the roca file to a pcap file, which can be read by tcpdump, wireshark, etc.

## Usage.

```bash
$ roca2pcap --input sample_input.roca --output output.pcap
$ tcpdump -r output.pcap
14:13:38.223000 IP dns.google > 172.27.3.157: ICMP echo reply, id 39924, seq 3, length 64
```
