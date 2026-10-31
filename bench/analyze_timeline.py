import sys
import numpy as np
from scapy.all import PcapReader, TCP, IP

def analyze_timeline(pcap_path, label, target_port):
    streams = {}
    with PcapReader(pcap_path) as pr:
        for pkt in pr:
            if IP in pkt and TCP in pkt and pkt[TCP].payload:
                # Фильтруем только нужный порт (чтобы не смешивать направления)
                if pkt[TCP].sport != target_port and pkt[TCP].dport != target_port:
                    continue
                
                src = (pkt[IP].src, pkt[TCP].sport)
                dst = (pkt[IP].dst, pkt[TCP].dport)
                direction = (src, dst)
                
                if direction not in streams:
                    streams[direction] = {}
                seq = pkt[TCP].seq
                if seq not in streams[direction]:
                    streams[direction][seq] = (float(pkt.time), bytes(pkt[TCP].payload))
    
    print(f"\n=== TIMELINE: {label} (Порт {target_port}) ===")
    
    # Ищем направление с наибольшим количеством данных (Server -> Client)
    best_dir = None
    max_bytes = 0
    for d, pkts in streams.items():
        total = sum(len(p[1]) for p in pkts.values())
        if total > max_bytes:
            max_bytes = total
            best_dir = d
            
    if not best_dir:
        print("Нет данных.")
        return

    packets = streams[best_dir]
    sorted_seqs = sorted(packets.keys())
    
    payload = bytearray()
    times = []
    for seq in sorted_seqs:
        t, p = packets[seq]
        payload.extend(p)
        times.append(t)
        
    lengths = []
    record_times = []
    pos = 0
    
    # Восстанавливаем временной таймлайн TLS-записей
    current_byte = 0
    byte_timeline = []
    for seq in sorted_seqs:
        t, p = packets[seq]
        byte_timeline.append((current_byte, current_byte + len(p), t))
        current_byte += len(p)

    while len(payload) - pos >= 5:
        content_type = payload[pos]
        length = int.from_bytes(payload[pos+3:pos+5], 'big')
        if length > 16384 + 256: break
        total = 5 + length
        if len(payload) - pos < total: break
        
        end_of_record = pos + total
        t_record = None
        for start, end, t in byte_timeline:
            if end >= end_of_record:
                t_record = t
                break
                
        if content_type == 0x17: # Application Data
            lengths.append(length)
            if t_record: record_times.append(t_record)
        pos += total
        
    if not lengths:
        return

    start_time = record_times[0]
    
    print(f"Всего записей: {len(lengths)}")
    print(f"{'Time (ms)':<10} | {'Delta (ms)':<10} | {'Size (bytes)':<12} | {'Type'}")
    print("-" * 50)
    
    # Выводим первые 50 записей
    for i in range(min(50, len(lengths))):
        t = record_times[i]
        delta = (t - start_time) * 1000
        prev_delta = (t - record_times[i-1]) * 1000 if i > 0 else 0
        
        print(f"{delta:<10.3f} | {prev_delta:<10.3f} | {lengths[i]:<12} | {'DATA' if lengths[i] > 100 else 'CTRL'}")

# Запускаем анализ для HTTP/2 (порт 8444) и Ghost (порт 9449)
analyze_timeline('/tmp/http2_small.pcap', 'HTTP/2', 8444)
analyze_timeline('/tmp/ghost_small.pcap', 'Ghost ', 9449)
