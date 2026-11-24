"""Minimal READ-ONLY SNMP v2c client (GET and GETBULK). Standard library only.

It never writes to a switch. It reads uptime and the status of every port from the
standard IF-MIB, which Ruckus ICX switches support.
"""
import os
import re
import socket
import time

SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_ADMIN = "1.3.6.1.2.1.2.2.1.7"
IF_OPER = "1.3.6.1.2.1.2.2.1.8"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"

END = object()  # "no more data" marker (endOfMibView / noSuchObject / noSuchInstance)


class SnmpError(Exception):
    pass


# ------------------------------------------------------------------ BER encoding
def _length(n):
    if n < 128:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag, body):
    return bytes([tag]) + _length(len(body)) + body


def _int(n):
    size = 1
    while True:
        try:
            return _tlv(0x02, n.to_bytes(size, "big", signed=True))
        except OverflowError:
            size += 1


def _base128(n):
    out = [n & 0x7F]
    n >>= 7
    while n:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    return bytes(reversed(out))


def _oid(dotted):
    parts = [int(p) for p in dotted.strip(".").split(".")]
    body = bytes([parts[0] * 40 + parts[1]]) + b"".join(_base128(p) for p in parts[2:])
    return _tlv(0x06, body)


def build_request(tag, community, request_id, oids, field_a=0, field_b=0):
    """tag 0xA0 = GET, 0xA5 = GETBULK (field_a = non-repeaters, field_b = max-repetitions)."""
    varbinds = b"".join(_tlv(0x30, _oid(o) + b"\x05\x00") for o in oids)
    pdu = _tlv(tag, _int(request_id) + _int(field_a) + _int(field_b) + _tlv(0x30, varbinds))
    return _tlv(0x30, _int(1) + _tlv(0x04, community.encode()) + pdu)  # version 1 = SNMP v2c


# ------------------------------------------------------------------ BER decoding
def _read(buf, pos):
    if pos + 2 > len(buf):
        raise SnmpError("truncated reply")
    tag, length = buf[pos], buf[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(buf[pos:pos + count], "big")
        pos += count
    end = pos + length
    if end > len(buf):
        raise SnmpError("truncated reply")
    return tag, buf[pos:end], end


def _decode_oid(body):
    first = body[0]
    parts = [2, first - 80] if first >= 80 else [first // 40, first % 40]
    value = 0
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def _decode_value(tag, body):
    if tag == 0x02:
        return int.from_bytes(body, "big", signed=True)
    if tag in (0x41, 0x42, 0x43, 0x46, 0x47):  # counter32, gauge32, timeticks, counter64, uinteger
        return int.from_bytes(body, "big")
    if tag == 0x06:
        return _decode_oid(body)
    if tag == 0x40:
        return ".".join(str(b) for b in body)
    if tag in (0x80, 0x81, 0x82):
        return END
    return body  # octet string and anything else


def parse_response(data):
    """Return (request_id, error_status, error_index, [(oid, value), ...])."""
    tag, message, _ = _read(data, 0)
    if tag != 0x30:
        raise SnmpError("not an SNMP message")
    _, _, pos = _read(message, 0)          # version
    _, _, pos = _read(message, pos)        # community
    tag, pdu, _ = _read(message, pos)
    if tag != 0xA2:
        raise SnmpError("not a response")
    _, rid, p = _read(pdu, 0)
    _, status, p = _read(pdu, p)
    _, index, p = _read(pdu, p)
    _, varlist, _ = _read(pdu, p)
    result, q = [], 0
    while q < len(varlist):
        _, varbind, q = _read(varlist, q)
        _, oid_body, r = _read(varbind, 0)
        vtag, vbody, _ = _read(varbind, r)
        result.append((_decode_oid(oid_body), _decode_value(vtag, vbody)))
    return (int.from_bytes(rid, "big", signed=True), int.from_bytes(status, "big"),
            int.from_bytes(index, "big"), result)


# ------------------------------------------------------------------------ client
class Snmp:
    def __init__(self, host, community, port=161, timeout=2.0, retries=1):
        self.host, self.community, self.port = host, community, port
        self.timeout, self.retries = timeout, retries

    def _ask(self, tag, oids, field_a=0, field_b=0):
        request_id = int.from_bytes(os.urandom(3), "big") + 1
        packet = build_request(tag, self.community, request_id, oids, field_a, field_b)
        last_error = "timeout"
        for _ in range(self.retries + 1):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                try:
                    sock.sendto(packet, (self.host, self.port))
                    deadline = time.monotonic() + self.timeout
                    while time.monotonic() < deadline:
                        sock.settimeout(max(0.05, deadline - time.monotonic()))
                        data, addr = sock.recvfrom(65535)
                        if addr[0] != self.host:
                            continue
                        rid, status, index, varbinds = parse_response(data)
                        if rid != request_id:
                            continue
                        if status:
                            raise SnmpError(f"switch returned SNMP error {status}")
                        return varbinds
                except socket.timeout:
                    last_error = "no reply (wrong community, SNMP off, or blocked)"
                except OSError as exc:
                    last_error = str(exc)
        raise SnmpError(last_error)

    def get(self, oid):
        for got_oid, value in self._ask(0xA0, [oid]):
            return None if value is END else value
        return None

    def walk(self, base, max_repetitions=20):
        """Return {oid: value} for everything under `base`."""
        found, current = {}, base
        for _ in range(400):  # safety limit
            varbinds = self._ask(0xA5, [current], 0, max_repetitions)
            if not varbinds:
                break
            advanced = False
            for oid, value in varbinds:
                if value is END or not oid.startswith(base + "."):
                    return found
                found[oid] = value
                current, advanced = oid, True
            if not advanced:
                break
        return found


# -------------------------------------------------------------------- port reading
_PORT_LABEL = re.compile(r"\d{1,2}/\d{1,2}/\d{1,3}")
_REAL_PORT = re.compile(r"ethernet|gigabit|\bport\b|\bge\b|\bgi\b|\bte\b", re.I)
_NOT_PORT = re.compile(r"vlan|loopback|lag|trunk|null|cpu|stack|management|\bve\d|\btunnel", re.I)


def _text(value):
    return value.decode("utf-8", "replace").strip() if isinstance(value, (bytes, bytearray)) else str(value)


def read_switch(host, community, port=161, timeout=2.0):
    """Read uptime and all ports. Returns {"uptime": seconds, "ports": {label: {...}}}.

    Raises SnmpError if the switch does not answer SNMP.
    """
    client = Snmp(host, community, port, timeout)
    ticks = client.get(SYS_UPTIME)
    if ticks is None:
        raise SnmpError("no uptime returned")

    names = {int(o.rsplit(".", 1)[1]): _text(v) for o, v in client.walk(IF_NAME).items()}
    descr = {int(o.rsplit(".", 1)[1]): _text(v) for o, v in client.walk(IF_DESCR).items()}
    oper = {int(o.rsplit(".", 1)[1]): v for o, v in client.walk(IF_OPER).items()}
    admin = {int(o.rsplit(".", 1)[1]): v for o, v in client.walk(IF_ADMIN).items()}
    alias = {int(o.rsplit(".", 1)[1]): _text(v) for o, v in client.walk(IF_ALIAS).items()}

    ports = {}
    for index, state in oper.items():
        text = f"{names.get(index, '')} {descr.get(index, '')}"
        match = _PORT_LABEL.search(text)
        if match:
            label = match.group(0)
        elif _REAL_PORT.search(text) and not _NOT_PORT.search(text):
            label = (names.get(index) or descr.get(index) or f"port {index}")[:20]
        else:
            continue
        if state == 6:  # notPresent
            continue
        ports[label] = {
            "oper": "up" if state == 1 else "down",
            "admin": "down" if admin.get(index) == 2 else "up",
            "alias": alias.get(index, ""),
        }
    return {"uptime": int(ticks) // 100, "ports": ports}
