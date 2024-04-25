import base64
import dataclasses
import typing
import sys
import pprint


@dataclasses.dataclass
class Packet:
    timestamp: int
    count: int
    ethertype: int
    packet_content: bytes

    def __repr__(self):
        return f"Packet(timestamp={self.timestamp}, count={self.count}, ethertype={self.ethertype}, packet_content={self.packet_content.hex()})"

    @classmethod
    def from_string(cls, line: str) -> typing.Self:
        # Parse the line into components.
        try:
            timestamp, count, reserved, ethertype, contents = line.split(",")
        except ValueError:
            sys.stderr.write(f"Could not parse line {line}.")
            raise e

        # Convert the components into correct types.
        try:
            cls.timestamp = int(timestamp)
        except Exception as e:
            sys.stderr.write(f"Could not parse timestamp (first field) in {line}.")
            raise e

        try:
            cls.count = int(count)
        except Exception as e:
            sys.stderr.write(f"Could not parse count (second field) in {line}.")
            raise e

        if reserved != "0":
            sys.stderr.write("Purpose of third field is unknown, only 0 is currently accepted.")
            sys.stderr.write("Please contact the developer of this application to report")
            sys.stderr.write("this new discovery !")
            sys.stderr.write(f"Your line: {line}")
            raise ValueError("Non 0 reserved field found.")

        try:
            cls.ethertype = int(ethertype)
        except Exception as e:
            sys.stderr.write(f"Could not parse ethertype (fourth field) in {line}")
            raise e

        try:
            cls.packet_content = base64.b64decode(contents)
        except Exception as e:
            sys.stderr.write(f"Could not parse base64 packet contents (fifth field) in {line}")
            raise e

        return cls
