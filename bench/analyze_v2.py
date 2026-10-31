import struct, sys
from collections import Counter

def parse_pcap(path):
    with open(path, "rb") as f:
        hdr = f.read(24)
        magic = struct.unpack("<I", hdr[:4])[0]
        endian = "<" if magic == 0xa1b2c3d4 else ">"
        pkts = []
        while True:
            phdr = f.read(16)
            if len(phdr) < 16: break
            ts_sec, ts_usec, caplen, origlen = struct.unpack(endian + "IIII", phdr)
            data = f.read(caplen)
            if len(data) < caplen: break
            pkts.append((ts_sec+ts_usec/1e6, data))
        return pkts

def parse_tcp(data):
    if len(data) < 34 or data[12:14] != b"\x08\x00": return None
    ihl = (data[14] & 0x0f)*4
    if data[23] != 6: return None
    tot = struct.unpack(">H", data[16:18])[0]
    src = struct.unpack(">H", data[14+ihl:14+ihl+2])[0]
    dst = struct.unpack(">H", data[14+ihl+2:14+ihl+4])[0]
    tcp_off = (data[14+ihl+12] >> 4)*4
    flags = data[14+ihl+13]
    payload_start = 14 + ihl + tcp_off
    payload = data[payload_start:14+tot]
    return src, dst, flags, payload

def parse_tls_records(payload):
    records = []
    i = 0
    while i + 5 <= len(payload):
        ct = payload[i]
        ver = payload[i+1:i+3]
        ln = struct.unpack(">H", payload[i+3:i+5])[0]
        if ver not in (b"\x03\x01", b"\x03\x02", b"\x03\x03", b"\x03\x04"): break
        if ct not in (0x14, 0x15, 0x16, 0x17): break
        if i + 5 + ln > len(payload): break
        records.append((ct, ln))
        i += 5 + ln
    return records

for path in sys.argv[1:]:
    print(f"\n=== {path} ===")
    pkts = parse_pcap(path)
    ack = 0; data_pkts = []
    dir_data = {"c2s": [], "s2c": []}
    for ts, data in pkts:
        r = parse_tcp(data)
        if not r: continue
        src, dst, flags, payload = r
        if len(payload) == 0:
            ack += 1; continue
        d = "s2c" if src == 9449 else ("c2s" if dst == 9449 else None)
        data_pkts.append((d, payload))
        if d: dir_data[d].append(payload)
    print(f"total: {len(pkts)}, ACK: {ack}, DATA: {len(data_pkts)}")
    for d in ("c2s", "s2c"):
        arr = dir_data[d]
        if not arr: continue
        print(f"  {d}: {len(arr)} packets, total={sum(len(p) for p in arr)} bytes")
        sizes = Counter(len(p) for p in arr)
        print(f"  {d} TCP payload sizes (top-10):")
        for sz, cnt in sizes.most_common(10):
            print(f"    {sz:6d}: {cnt} ({100*cnt/len(arr):.1f}%)")
        tls = Counter()
        for p in arr:
            for ct, ln in parse_tls_records(p):
                tls[(ct, ln)] += 1
        if tls:
            print(f"  {d} TLS records (top-10):")
            for (ct, ln), cnt in tls.most_common(10):
                print(f"    ct={ct:#x} len={ln}: {cnt}")
