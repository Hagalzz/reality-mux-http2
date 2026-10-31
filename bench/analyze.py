import struct
import sys
from collections import Counter

def parse_pcap(path):
    """Возвращает список (ts, caplen, origlen) для каждого пакета."""
    with open(path, "rb") as f:
        hdr = f.read(24)
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic == 0xa1b2c3d4:
            endian = "<"
        elif magic == 0xd4c3b2a1:
            endian = ">"
        else:
            raise ValueError(f"unknown magic: {magic:08x}")
        
        packets = []
        while True:
            phdr = f.read(16)
            if len(phdr) < 16:
                break
            ts_sec, ts_usec, caplen, origlen = struct.unpack(endian + "IIII", phdr)
            data = f.read(caplen)
            if len(data) < caplen:
                break
            packets.append((ts_sec + ts_usec/1e6, caplen, origlen, data))
        return packets

def direction(data):
    """Определяем направление по портам: 127.0.0.1:1081/1084 → сервер (c2s), иначе (s2c)."""
    if len(data) < 34:
        return "?"
    # IPv4 header
    if data[12:14] != b"\x08\x00":
        return "?"
    ihl = (data[14] & 0x0f) * 4
    proto = data[23]
    if proto != 6:
        return "?"
    src_port = struct.unpack(">H", data[14+ihl:14+ihl+2])[0]
    dst_port = struct.unpack(">H", data[14+ihl+2:14+ihl+4])[0]
    # SOCKS5-порт клиента в src → c2s
    if src_port in (1081, 1084):
        return "c2s"
    if dst_port in (1081, 1084):
        return "s2c"
    # Между Xray-client и Xray-server
    if src_port in (9445, 9447, 9448, 1081, 1082, 1083, 1084):
        return "c2s"
    if dst_port in (9445, 9447, 9448, 1081, 1082, 1083, 1084):
        return "s2c"
    return "?"

def payload_len(data):
    if len(data) < 34:
        return 0
    if data[12:14] != b"\x08\x00":
        return 0
    ihl = (data[14] & 0x0f) * 4
    proto = data[23]
    if proto != 6:
        return 0
    total_len = struct.unpack(">H", data[16:18])[0]
    # TCP data offset
    tcp_start = 14 + ihl
    if len(data) < tcp_start + 20:
        return 0
    data_offset = (data[tcp_start + 12] >> 4) * 4
    payload = total_len - ihl - data_offset
    return max(0, payload)

for path in sys.argv[1:]:
    print(f"\n=== {path} ===")
    pkts = parse_pcap(path)
    print(f"total packets: {len(pkts)}")
    
    c2s = []
    s2c = []
    for ts, caplen, origlen, data in pkts:
        d = direction(data)
        p = payload_len(data)
        if d == "c2s":
            c2s.append(p)
        elif d == "s2c":
            s2c.append(p)
    
    print(f"c2s: {len(c2s)} packets, total_payload={sum(c2s)} bytes")
    print(f"s2c: {len(s2c)} packets, total_payload={sum(s2c)} bytes")
    
    # Гистограмма размеров payload
    for label, arr in [("c2s", c2s), ("s2c", s2c)]:
        if not arr:
            continue
        buckets = Counter()
        for p in arr:
            b = (p // 100) * 100
            buckets[b] += 1
        print(f"\n  {label} payload histogram (bucketed by 100 bytes):")
        for b in sorted(buckets.keys())[:20]:
            print(f"    {b:5d}-{b+99:5d}: {buckets[b]}")
    
    # Inter-arrival
    if len(pkts) > 1:
        iats = [pkts[i+1][0] - pkts[i][0] for i in range(len(pkts)-1)]
        iats.sort()
        print(f"\n  inter-arrival: min={iats[0]:.6f} p50={iats[len(iats)//2]:.6f} p95={iats[int(len(iats)*0.95)]:.6f} max={iats[-1]:.6f}")
