import roca2pcap.roca2pcap as r2p
import pytest

def test_ping_packet_parses():
    line = "1714050818223,0,0,2048,CAAAAAAAAAIAAQAGdKy5qFyfAABFAABUAAAAAHMBiAsICAgIrBsDcwAAVThligADRlwqZgAAAAAMpQkAAAAAABAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc="
    packet = r2p.Packet.from_string(line)
    assert packet.timestamp == 1714050818223
    assert packet.ethertype == 2048
    assert packet.count == 0
    assert packet.packet_content == bytes(b'\x08\x00\x00\x00\x00\x00\x00\x02\x00\x01\x00\x06t\xac\xb9\xa8\\\x9f\x00\x00E\x00\x00T\x00\x00\x00\x00s\x01\x88\x0b\x08\x08\x08\x08\xac\x1b\x03s\x00\x00U8e\x8a\x00\x03F\\*f\x00\x00\x00\x00\x0c\xa5\t\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567')


def test_timestamp_not_a_number():
    with pytest.raises(ValueError):
        r2p.Packet.from_string("ABCD,0,0,2048,CA")
