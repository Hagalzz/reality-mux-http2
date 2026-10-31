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
    except Exception as e:
        print(f"Error reading {pcap_path}: {e}")
        return []

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
            active_span = record_times[-1] - record_times[0] if len(record_times) > 1 else 0.0
            total_tls_bytes = sum(lengths)
            hit_limit = sum(1 for l in lengths if l > 8000)

            data.append({
                'session_id': session_id,
                'avg_len': np.mean(lengths),
                'max_len': np.max(lengths),
                'count': len(lengths),
                'avg_iat': np.mean(iats),
                'active_span': active_span,
                'total_tls_bytes': total_tls_bytes,
                'hit_limit_count': hit_limit,
                'label': label_name
            })
    return data

if __name__ == "__main__":
    all_data = []
    for arg in sys.argv[1:]:
        label, pcap = arg.split(':')
        print(f"Extracting sessions from {pcap} as {label}...")
        data = extract_session_features(pcap, label)
        if data: all_data.extend(data)

    if not all_data:
        print("No TLS data extracted.")
        sys.exit(1)

    df = pd.DataFrame(all_data)
    print(f"\nTotal sessions extracted: {len(df)}")
    print("\n=== FEATURE MEANS ===")
    cols_to_show = ['avg_len', 'max_len', 'count', 'avg_iat', 'active_span', 'total_tls_bytes', 'hit_limit_count']
    print(df.groupby("label")[cols_to_show].mean())

    # Групповое разбиение
    gss = GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=42)
    train_idx, test_idx = next(gss.split(df, groups=df['session_id']))
    train_df = df.iloc[train_idx]
    test_df = df.iloc[test_idx]
    
    features = ['avg_len', 'max_len', 'count', 'avg_iat', 'active_span', 'total_tls_bytes']
    X_train = train_df[features].values
    y_train = pd.factorize(train_df['label'])[0]
    X_test = test_df[features].values
    y_test = pd.factorize(test_df['label'])[0]

    clf_full = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=3)
    clf_full.fit(X_train, y_train)
    y_pred_full = clf_full.predict_proba(X_test)[:, 1]
    
    print("\n=== FULL MODEL ===")
    try:
        auc = roc_auc_score(y_test, y_pred_full)
        print(f"ROC-AUC = {auc:.3f}")
        print("Feature Importances:")
        for f, imp in zip(features, clf_full.feature_importances_):
            print(f"  {f}: {imp:.3f}")
    except ValueError:
        print("Test set has only one class.")

    print("\n=== SINGLE-FEATURE MODELS (ROC-AUC) ===")
    for f in features:
        X_tr = train_df[[f]].values
        X_te = test_df[[f]].values
        clf_single = RandomForestClassifier(n_estimators=50, random_state=42, max_depth=3)
        clf_single.fit(X_tr, y_train)
        y_pred_single = clf_single.predict_proba(X_te)[:, 1]
        try:
            auc_single = roc_auc_score(y_test, y_pred_single)
            print(f"{f:15}: {auc_single:.3f}")
        except ValueError:
            print(f"{f:15}: Error (one class)")
