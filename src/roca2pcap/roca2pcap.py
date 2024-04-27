import argparse
import base64
import dataclasses
import pathlib
import sys
import typing

import macaddress  # type: ignore
import scapy.all as scapy  # type: ignore


@dataclasses.dataclass
class Packet:
    """A class representing a roca packet, as found in a roca file.

    Attributes:
        timestamp: The timestamp of the packet, in milliseconds since the unix epoch.
        count: The count of the packet, starting at 0 for the first packet in a time period.
        ethertype: The ethertype of the packet, in decimal format.
        packet_content: The raw bytes of the packet, as found in the roca file.
    """
    timestamp: int
    count: int
    ethertype: int
    packet_content: bytes

    def __repr__(self):
        """Return a string representation of the Packet object.

        Returns:
            str: A string representation of the Packet object.
        """
        return f"Packet(timestamp={self.timestamp}, count={self.count}, ethertype={self.ethertype}, packet_content={self.packet_content.hex()})"

    @property
    def dstmac_bytes(self) -> bytes:
        """Return the destination mac address of the packet.

        Returns:
            bytes: The destination mac address of the packet, as bytes.
        """
        return self.packet_content[0:6]

    @property
    def srcmac_bytes(self) -> bytes:
        """Return the source mac address of the packet.

        Returns:
            bytes: The source mac address of the packet, as bytes.
        """
        return self.packet_content[6:11]

    @property
    def srcmac(self) -> str:
        """Return the source mac address of the packet.

        Returns:
            str: The source mac address of the packet, in the format "aa:bb:cc:dd:ee:ff".
        """
        return str(macaddress.MAC(self.srcmac_bytes)).replace("-", ":")

    @property
    def dstmac(self) -> str:
        """Return the destination mac address of the packet.

        Returns:
            str: The destination mac address of the packet, in the format "aa:bb:cc:dd:ee:ff".
        """
        return str(macaddress.MAC(self.dstmac_bytes)).replace("-", ":")


    @property
    def l3payload(self) -> bytes:
        """Return the l3 payload of the packet.

        Returns:
            bytes: The l3 payload of the packet as bytes.
        """
        return self.packet_content[14:]


    @classmethod
    def from_string(cls, line: str) -> typing.Self:
        """Parse a roca line into a Packet object.

        Args:
            line: The roca line to parse.

        Returns:
            Packet: A Packet object.
        """
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
        """Convert the Packet object to a scapy Ether object.

        Returns:
            scapy.Ether: A scapy Ether object.
        """
        s = scapy.Ether(self.packet_content)
        s.time = self.timestamp / 1000
        s.microsecond = self.count
        return s

def read_file(filename: pathlib.Path) -> typing.Generator[Packet, None, None]:
    """Read a file of roca lines and generate Packet objects from it.

    Args:
        filename: The path to the roca file.

    Yields:
        Packet: A Packet object for each line in the roca file.
    """
    with open(filename, "r") as f:
        for line in f:
            yield Packet.from_string(line)

def parse_args() -> argparse.Namespace:
    """Parse the command line arguments.

    Returns:
        argparse.Namespace: The parsed command line arguments.
    """
    parser = argparse.ArgumentParser(description="Convert a roca file to a pcap file.")
    parser.add_argument("--input", type=pathlib.Path, help="The input roca file. example: input.roca")
    parser.add_argument("--output", type=pathlib.Path, help="The output pcap file. example: output.pcap")
    return parser.parse_args()

def main():
    args = parse_args()
    with scapy.PcapWriter(filename=str(args.output)) as writer:
        for packet in read_file(str(args.input)):
            writer.write(packet.to_scapy())


if __name__ == "__main__":
    main()
