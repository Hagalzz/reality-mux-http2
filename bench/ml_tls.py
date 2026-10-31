import sys
import numpy as np
import pandas as pd
from scapy.all import PcapReader, TCP, IP
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

def extract_session_features(pcap_path, label_name):
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
        return []

    data = []
    for direction_id, packets in streams.items():
        sorted_seqs = sorted(packets.keys())
        payload = bytearray()
        times = []
        tcp_bytes = 0

        for seq in sorted_seqs:
            t, p = packets[seq]
            payload.extend(p)
            times.append(t)
            tcp_bytes += len(p)

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

        # Пропускаем первые 4 записи (TLS Handshake)
        if len(lengths) > 4:
            lengths = lengths[4:]
            
            times.sort()
            iats = [times[i+1] - times[i] for i in range(len(times)-1)] if len(times) > 1 else [0.0]
            run_id = f"{direction_id[0][0]}:{direction_id[0][1]}-{direction_id[1][0]}:{direction_id[1][1]}"
            
            data.append({
                'run_id': run_id,
                'avg_len': np.mean(lengths),
                'max_len': np.max(lengths),
                'count': len(lengths),
                'avg_iat': np.mean(iats),
                'tcp_bytes': tcp_bytes,
                'label': label_name
            })
    return data

if __name__ == "__main__":
    all_data = []
    for arg in sys.argv[1:]:
        label, pcap = arg.split(':')
        data = extract_session_features(pcap, label)
        if data: all_data.extend(data)

    df = pd.DataFrame(all_data)
    df = df[df["tcp_bytes"] > 5000]
    print(f"Total sessions extracted: {len(df)}")

    feats = ['avg_len', 'max_len', 'count', 'avg_iat']
    X = df[feats].values
    y = pd.factorize(df['label'])[0]
    groups = df['run_id'].values

    cv = StratifiedGroupKFold(n_splits=2, shuffle=True, random_state=42)
    
    print("\n=== SINGLE-FEATURE MODELS (Honest CV) ===")
    for i, f in enumerate(feats):
        X_single = X[:, i].reshape(-1, 1)
        aucs = []
        for train_idx, test_idx in cv.split(X_single, y, groups):
            clf = RandomForestClassifier(n_estimators=100, max_depth=3, random_state=42)
            clf.fit(X_single[train_idx], y[train_idx])
            probs = clf.predict_proba(X_single[test_idx])
            preds = probs[:, 1] if probs.shape[1] > 1 else np.zeros(len(probs))
            aucs.append(roc_auc_score(y[test_idx], preds))
        print(f"{f}: {np.mean(aucs):.3f}")

    print("\n=== FULL MODEL (Honest CV) ===")
    aucs = []
    for train_idx, test_idx in cv.split(X, y, groups):
        clf = RandomForestClassifier(n_estimators=100, max_depth=3, random_state=42)
        clf.fit(X[train_idx], y[train_idx])
        preds = clf.predict_proba(X[test_idx])[:, 1]
        aucs.append(roc_auc_score(y[test_idx], preds))
    print(f"Combined AUC: {np.mean(aucs):.3f} +/- {np.std(aucs):.3f}")
