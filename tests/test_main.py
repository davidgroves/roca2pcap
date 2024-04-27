import pytest
import roca2pcap.roca2pcap as r2p


@pytest.fixture
def ping_test_packet():
    return "1714050818223,0,0,2048,qrvM3e7/dKy5qFyfCABFAABUAAAAAHMBh+EICAgIrBsDnQAAAbeb9AADGK8qZgAAAABZaQcAAAAAABAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc="


def test_ping_packet_dpkt(ping_test_packet):
    packet = r2p.Packet.from_string(ping_test_packet)
    dpkt_packet = packet.to_scapy()
    print("*****")
    print(dpkt_packet)

def test_ping_packet_parses(ping_test_packet):
    packet = r2p.Packet.from_string(ping_test_packet)
    assert packet.timestamp == 1714050818223
    assert packet.ethertype == 2048
    assert packet.count == 0
    assert packet.packet_content == b'\xaa\xbb\xcc\xdd\xee\xfft\xac\xb9\xa8\\\x9f\x08\x00E\x00\x00T\x00\x00\x00\x00s\x01\x87\xe1\x08\x08\x08\x08\xac\x1b\x03\x9d\x00\x00\x01\xb7\x9b\xf4\x00\x03\x18\xaf*f\x00\x00\x00\x00Yi\x07\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567'

def test_ping_dstmac(ping_test_packet):
    packet = r2p.Packet.from_string(ping_test_packet)
    assert packet.dstmac_bytes == b'\xaa\xbb\xcc\xdd\xee\xff'

def test_ping_srcmac(ping_test_packet):
    packet = r2p.Packet.from_string(ping_test_packet)
    assert packet.srcmac_bytes == b't\xac\xb9\xa8\\'

def test_ping_l3payload(ping_test_packet):
    packet = r2p.Packet.from_string(ping_test_packet)
    print(packet.l3payload)
    assert packet.l3payload == b'E\x00\x00T\x00\x00\x00\x00s\x01\x87\xe1\x08\x08\x08\x08\xac\x1b\x03\x9d\x00\x00\x01\xb7\x9b\xf4\x00\x03\x18\xaf*f\x00\x00\x00\x00Yi\x07\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567'

def test_timestamp_not_a_number():
    with pytest.raises(ValueError):
        r2p.Packet.from_string("ABCD,0,0,2048,CA==")

def test_timestamp_is_negative():
    with pytest.raises(ValueError):
        r2p.Packet.from_string("-1,0,0,2048,CA==")

def test_count_is_negative():
    with pytest.raises(ValueError):
        r2p.Packet.from_string("1714050818223,-1,0,2048,CA==")

def test_packet_content_is_not_base64():
    with pytest.raises(ValueError):
        r2p.Packet.from_string("1714050818223,0,0,2048,$%^&*(){}")

@pytest.mark.skip(reason="Test is correct, but data is not")
def test_src_in_text_matches_packet(ping_test_packet):
    packet = r2p.Packet.from_string(ping_test_packet)
    print(packet.srcmac)
    print(type(packet.srcmac))

    assert packet.srcmac.replace("-", ":") == packet.to_scapy().src

