import sys
from scapy.all import PcapReader, TCP, IP
from collections import Counter

def dump_pcap(path, label):
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
        if len(packets) < 5: continue
        
        sorted_seqs = sorted(packets.keys())
        payload = bytearray()
        for seq in sorted_seqs:
            payload.extend(packets[seq])

        lengths = []
        pos = 0
        while len(payload) - pos >= 5:
            content_type = payload[pos]
            length = int.from_bytes(payload[pos+3:pos+5], 'big')
            if length > 16384 + 256: 
                print(f"[{label}] Ошибка парсинга (битый заголовок)")
                break
            if len(payload) - pos < 5 + length: break
            
            if content_type == 0x17:
                lengths.append(length)
            pos += 5 + length
        
        if lengths:
            print(f"\n[{label}] Направление: {direction[0]} -> {direction[1]}")
            print(f"Всего записей (count): {len(lengths)}")
            top_20 = sorted(lengths, reverse=True)[:20]
            print(f"ТОП-20 самых больших записей: {top_20}")
            
            # Смотрим, сколько раз встречается максимум
            c = Counter(lengths)
            print("Частота топ-5 размеров:")
            for size, freq in c.most_common(5):
                print(f"  Размер {size}: {freq} раз")

dump_pcap('/tmp/ghost_small.pcap', 'Ghost ')
dump_pcap('/tmp/vision_small.pcap', 'Vision')
