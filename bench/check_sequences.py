import sys
from scapy.all import PcapReader, TCP, IP

def extract_sequences(pcap_path, label_name, max_sessions=3):
    streams = {}
    try:
        with PcapReader(pcap_path) as pcap_reader:
            for pkt in pcap_reader:
                if IP in pkt and TCP in pkt and pkt[TCP].payload:
                    src = (pkt[IP].src, pkt[TCP].sport)
                    dst = (pkt[IP].dst, pkt[TCP].dport)
                    direction_id = (src, dst)
                    if direction_id not in streams: streams[direction_id] = {}
                    seq = pkt[TCP].seq
                    streams[direction_id][seq] = (float(pkt.time), bytes(pkt[TCP].payload))
    except Exception as e:
        return

    count = 0
    for direction_id, packets in streams.items():
        if count >= max_sessions: break
        sorted_seqs = sorted(packets.keys())
        payload = bytearray()
        for seq in sorted_seqs:
            t, p = packets[seq]
            payload.extend(p)

        lengths = []
        pos = 0
        while len(payload) - pos >= 5:
            content_type = payload[pos]
            length = int.from_bytes(payload[pos+3:pos+5], 'big')
            total = 5 + length
            if length > 16384 + 256: break
            if len(payload) - pos < total: break
            if content_type == 0x17: lengths.append(length)
            pos += total

        if lengths and sum(lengths) > 10000:
            print(f"[{label_name}] Session {count+1} | Total Records: {len(lengths)} | Total Bytes: {sum(lengths)}")
            print(f"  First 20 sizes: {lengths[:20]}\n")
            count += 1

if __name__ == "__main__":
    extract_sequences(sys.argv[1], sys.argv[2])
