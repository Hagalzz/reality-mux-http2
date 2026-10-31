import sys
import numpy as np
import pandas as pd
from scapy.all import PcapReader, TCP, IP
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
import gc

def extract_session_features(pcap_path, label_name):
    streams = {}
    try:
        with PcapReader(pcap_path) as pcap_reader:
            for pkt in pcap_reader:
                if IP in pkt and TCP in pkt and pkt[TCP].payload:
                    src = (pkt[IP].src, pkt[TCP].sport)
                    dst = (pkt[IP].dst, pkt[TCP].dport)
                    direction_id = (src, dst)
                    session_id = tuple(sorted([str(src), str(dst)]))
                    if direction_id not in streams:
                        streams[direction_id] = {'packets': {}, 'session_id': session_id}
                    seq = pkt[TCP].seq
                    if seq not in streams[direction_id]['packets']:
                        streams[direction_id]['packets'][seq] = (float(pkt.time), bytes(pkt[TCP].payload))
    except Exception: return []

    gc.collect()
    data = []
    for direction_id, stream_info in streams.items():
        packets = stream_info['packets']
        session_id = stream_info['session_id']
        sorted_seqs = sorted(packets.keys())
        
        payload = bytearray()
        byte_timeline = []
        current_byte = 0
        
        for seq in sorted_seqs:
            t, p = packets[seq]
            payload.extend(p)
            byte_timeline.append((current_byte, current_byte + len(p), t))
            current_byte += len(p)
            
        lengths = []
        record_times = []
        pos = 0
        while len(payload) - pos >= 5:
            content_type = payload[pos]
            length = int.from_bytes(payload[pos+3:pos+5], 'big')
            if length > 16384 + 256: break
            total = 5 + length
            if len(payload) - pos < total: break
            
            # Находим время, когда был получен последний байт TLS-записи
            end_of_record = pos + total
            t_record = None
            for start, end, t in byte_timeline:
                if end >= end_of_record:
                    t_record = t
                    break
                    
            if content_type == 0x17:
                lengths.append(length)
                if t_record: record_times.append(t_record)
            pos += total
            
        if lengths:
            record_times.sort()
            iats = [record_times[i+1] - record_times[i] for i in range(len(record_times)-1)] if len(record_times) > 1 else [0.0]
            data.append({
                'session_id': session_id,
                'total_bytes': sum(lengths),
                'avg_len': np.mean(lengths),
                'max_len': np.max(lengths),
                'count': len(lengths),
                'avg_iat': np.mean(iats),
                'label': label_name
            })
            
    df = pd.DataFrame(data)
    df = df.loc[df.groupby('session_id')['total_bytes'].idxmax()]
    return df.to_dict('records')

if __name__ == "__main__":
    all_data = []
    for arg in sys.argv[1:]:
        label, pcap = arg.split(':')
        data = extract_session_features(pcap, label)
        if data: all_data.extend(data)

    df = pd.DataFrame(all_data)
    print("\n=== РЕАЛЬНЫЕ РАЗМЕРЫ (Только скачивание) ===")
    print(df.groupby("label")[['avg_len', 'max_len', 'count', 'avg_iat']].mean())

    gss = GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=42)
    train_idx, test_idx = next(gss.split(df, groups=df['session_id']))
    train_df, test_df = df.iloc[train_idx], df.iloc[test_idx]
    
    features = ['avg_len', 'max_len', 'count', 'avg_iat']
    X_train, y_train = train_df[features].values, pd.factorize(train_df['label'])[0]
    X_test, y_test = test_df[features].values, pd.factorize(test_df['label'])[0]

    clf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=3).fit(X_train, y_train)
    y_pred = clf.predict_proba(X_test)[:, 1]
    
    print(f"\nROC-AUC = {roc_auc_score(y_test, y_pred):.3f}")
    
    print("\n=== SINGLE-FEATURE MODELS ===")
    for f in features:
        c = RandomForestClassifier(n_estimators=50, random_state=42, max_depth=3).fit(train_df[[f]].values, y_train)
        print(f"{f:15}: {roc_auc_score(y_test, c.predict_proba(test_df[[f]].values)[:, 1]):.3f}")
