from scapy.all import PcapReader, TCP, IP

def dump_pcap_lens(path, label):
    streams = {}
    with PcapReader(path) as pr:
        for pkt in pr:
            if IP in pkt and TCP in pkt and pkt[TCP].payload:
                src = (pkt[IP].src, pkt[TCP].sport)
                dst = (pkt[IP].dst, pkt[TCP].dport)
                direction = (src, dst)
                if direction not in streams:
                    streams[direction] = {}
                streams[direction][pkt[TCP].seq] = bytes(pkt[TCP].payload)

    for direction, packets in streams.items():
        sorted_seqs = sorted(packets.keys())
        payload = bytearray()
        for seq in sorted_seqs:
            payload.extend(packets[seq])

        lengths = []
        pos = 0
        while len(payload) - pos >= 5:
            content_type = payload[pos]
            length = int.from_bytes(payload[pos+3:pos+5], 'big')
            if length > 16384 + 256: break
            if len(payload) - pos < 5 + length: break
            
            if content_type == 0x17:
                lengths.append(length)
            pos += 5 + length
        
        # Выводим только то направление, где много данных (сервер -> клиент)
        if len(lengths) > 5:
            print(f"\n[{label}] {direction[0]} -> {direction[1]}")
            print(f"Всего записей: {len(lengths)}")
            print(f"Первые 30 размеров: {lengths[:30]}")
            print(f"Максимальный размер: {max(lengths)}")

dump_pcap_lens('pcap/run/D4_mux_1.pcap', 'Ghost ')
dump_pcap_lens('pcap/run/A_vision_1.pcap', 'Vision')
