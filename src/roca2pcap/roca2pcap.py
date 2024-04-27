import base64
import dataclasses
import pathlib
import sys
import typing

import macaddress
import scapy.all as scapy  # type: ignore


@dataclasses.dataclass
class Packet:
    timestamp: int
    count: int
    ethertype: int
    packet_content: bytes

    def __repr__(self):
        return f"Packet(timestamp={self.timestamp}, count={self.count}, ethertype={self.ethertype}, packet_content={self.packet_content.hex()})"

    @property
    def dstmac_bytes(self) -> bytes:
        return self.packet_content[0:6]

    @property
    def srcmac_bytes(self) -> bytes:
        return self.packet_content[6:11]

    @property
    def srcmac(self) -> str:
        return str(macaddress.MAC(self.srcmac_bytes)).replace("-", ":")

    @property
    def dstmac(self) -> str:
        return str(macaddress.MAC(self.dstmac_bytes)).replace("-", ":")


    @property
    def l3payload(self) -> bytes:
        return self.packet_content[14:]


    @classmethod
    def from_string(cls, line: str) -> typing.Self:
        # Parse the line into components.
        try:
            timestamp, count, reserved, ethertype, contents = line.split(",")
        except ValueError as e:
            sys.stderr.write(f"Could not parse line {line}.\n")
            raise e

        # Convert the components into correct types.
        try:
            ret_timestamp = int(timestamp)
        except Exception as e:
            sys.stderr.write(f"Could not parse timestamp (first field) in {line}.\n")
            raise e
        if ret_timestamp < 0:
            sys.stderr.write(f"Timestamp is negative (first field) in {line}.\n")
            raise ValueError("Timestamp is negative.")

        try:
            ret_count = int(count)
        except Exception as e:
            sys.stderr.write(f"Could not parse count (second field) in {line}.\n")
            raise e
        if ret_count < 0:
            sys.stderr.write(f"Count is negative (second field) in {line}.\n")
            raise ValueError("Count is negative.")

        if reserved != "0":
            sys.stderr.write("Purpose of third field is unknown, only 0 is currently accepted.\n")
            sys.stderr.write("Please contact the developer of this application to report\n")
            sys.stderr.write("this new discovery !\n")
            sys.stderr.write(f"Your line: {line}\n")
            raise ValueError("Non 0 reserved field found.")

        try:
            ret_ethertype = int(ethertype)
        except Exception as e:
            sys.stderr.write(f"Could not parse ethertype (fourth field) in {line}\n")
            raise e

        try:
            ret_packet_content = base64.b64decode(contents, validate=True)
        except Exception as e:
            sys.stderr.write(f"Could not parse base64 packet contents (fifth field) in {line}\n")
            raise e

        return cls(ret_timestamp, ret_count, ret_ethertype, ret_packet_content)

    def to_scapy(self) -> scapy.Ether:
        s = scapy.Ether(self.packet_content)
        s.time = self.timestamp / 1000
        s.microsecond = self.count
        return s

def read_file(filename: pathlib.Path) -> typing.Generator[Packet, None, None]:
    """Read a file of roca lines and generate Packet objects from it."""
    with open(filename, "r") as f:
        for line in f:
            yield Packet.from_string(line)


def main():
    output_filename = "output.pcap"
    with scapy.PcapWriter(filename=output_filename) as writer:
        for packet in read_file("input.roca"):
            writer.write(packet.to_scapy())


if __name__ == "__main__":
    main()
