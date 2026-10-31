import sys
from scapy.all import PcapReader, TCP, IP

def analyze_real_time(pcap_path, target_port):
    streams = []
    current_stream = {'packets': {}, 'start_time': 0, 'last_time': 0}
    
    with PcapReader(pcap_path) as pr:
        for pkt in pr:
            if IP in pkt and TCP in pkt and pkt[TCP].payload:
                # Фильтруем только направление Server -> Client
                if pkt[TCP].sport == target_port:
                    t = float(pkt.time)
                    # Если пауза больше 0.5с — это новое соединение
                    if t - current_stream['last_time'] > 0.5 or not current_stream['packets']:
                        if current_stream['packets']:
                            streams.append(current_stream)
                        current_stream = {'packets': {}, 'start_time': t, 'last_time': t}
                    
                    current_stream['packets'][pkt[TCP].seq] = (t, bytes(pkt[TCP].payload))
                    current_stream['last_time'] = t
                    
    if current_stream['packets']:
        streams.append(current_stream)

    print(f"\n=== АНАЛИЗ {pcap_path} (Порт {target_port}) ===")
    for i, s in enumerate(streams[:5]): # Берем первые 5 соединений
        sorted_seqs = sorted(s['packets'].keys())
        payload = bytearray()
        times = []
        for seq in sorted_seqs:
            t, p = s['packets'][seq]
            payload.extend(p)
            times.append(t)
            
        lengths = []
        pos = 0
        while len(payload) - pos >= 5:
            c_type = payload[pos]
            length = int.from_bytes(payload[pos+3:pos+5], 'big')
            if length > 16384 + 256: break
            if len(payload) - pos < 5 + length: break
            if c_type == 0x17: lengths.append(length)
            pos += 5 + length
            
        if lengths:
            duration = times[-1] - times[0]
            avg_iat = duration / (len(lengths) - 1) if len(lengths) > 1 else 0
            print(f"Сессия {i+1}: Пакетов={len(lengths)}, Max={max(lengths)}, Avg={sum(lengths)/len(lengths):.1f}, Длительность={duration*1000:.2f} мс, Avg IAT={avg_iat*1000:.4f} мс")

analyze_real_time('/tmp/ghost_small.pcap', 9449)
analyze_real_time('/tmp/http2_small.pcap', 8444)
