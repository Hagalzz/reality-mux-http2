import numpy as np
from scapy.all import PcapReader, TCP, IP
from collections import Counter

def analyze_pcap(path):
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

    all_lengths = []
    all_iats = []
    burst_sizes = []

    for direction, packets in streams.items():
        sorted_seqs = sorted(packets.keys())
        payload = bytearray()
        times = []
        for seq in sorted_seqs:
            payload.extend(packets[seq])
            # Время нам нужно от самих пакетов, но для простоты пока опустим точный timeline
        
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
        
        if len(lengths) > 5:
            all_lengths.extend(lengths)

    print(f"=== АНАЛИЗ ТРАФИКА {path} ===")
    print(f"Всего TLS-записей: {len(all_lengths)}")
    
    print("\n-- Распределение размеров (ТОП-10) --")
    counts = Counter(all_lengths)
    for size, freq in counts.most_common(10):
        print(f"  Размер {size}: {freq} раз")
        
    print("\n-- Статистика размеров --")
    print(f"  Мин: {np.min(all_lengths)}")
    print(f"  Медиана: {np.median(all_lengths)}")
    print(f"  Среднее: {np.mean(all_lengths):.2f}")
    print(f"  Макс: {np.max(all_lengths)}")
    print(f"  Станд. отклонение (std): {np.std(all_lengths):.2f}")
    
analyze_pcap('/tmp/http2_small.pcap')
