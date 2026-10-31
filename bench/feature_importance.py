import sys
import numpy as np
import pandas as pd
from scapy.all import PcapReader, TCP, IP
from sklearn.ensemble import RandomForestClassifier

def extract_session_features(pcap_path, label_name):
    streams = {}
    try:
        with PcapReader(pcap_path) as pcap_reader:
            for pkt in pcap_reader:
                if IP in pkt and TCP in pkt and pkt[TCP].payload:
                    src = (pkt[IP].src, pkt[TCP].sport)
                    dst = (pkt[IP].dst, pkt[TCP].dport)
                    sid = tuple(sorted([src, dst]))
                    if sid not in streams:
                        streams[sid] = {'payload': bytearray(), 'times': []}
                    streams[sid]['payload'].extend(bytes(pkt[TCP].payload))
                    streams[sid]['times'].append(float(pkt.time))
    except:
        return []

    data = []
    for sid, s in streams.items():
        payload = s['payload']
        times = s['times']
        lengths = []
        pos = 0
        while len(payload) - pos >= 5:
            ct = payload[pos]
            ln = int.from_bytes(payload[pos+3:pos+5], 'big')
            if ln > 16384 + 256: break
            total = 5 + ln
            if len(payload) - pos < total: break
            if ct == 0x17: lengths.append(ln)
            pos += total

        if lengths:
            iats = [times[i+1] - times[i] for i in range(len(times)-1)] if len(times) > 1 else [0]
            data.append({
                'avg_len': np.mean(lengths),
                'max_len': np.max(lengths),
                'count': len(lengths),
                'avg_iat': np.mean(iats),
                'label': label_name
            })
    return data

if __name__ == "__main__":
    all_data = []
    for arg in sys.argv[1:]:
        label, pcap = arg.split(':')
        all_data.extend(extract_session_features(pcap, label))
    
    df = pd.DataFrame(all_data)
    X = df[['avg_len', 'max_len', 'count', 'avg_iat']].values
    feature_names = ['avg_len', 'max_len', 'count', 'avg_iat']
    
    labels = df['label'].unique()
    target = labels[0]
    y = (df['label'] == target).astype(int).values
    
    clf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=5)
    clf.fit(X, y)
    
    print(f"\n=== FEATURE IMPORTANCE (target: {target}) ===")
    for name, imp in sorted(zip(feature_names, clf.feature_importances_), key=lambda x: -x[1]):
        print(f"{name:12s}: {imp:.3f}")
        
    print(f"\n=== ВЫВОД ===")
    top_feat = feature_names[np.argmax(clf.feature_importances_)]
    print(f"Модель использует '{top_feat}' для детекта {target}")
