import sys
import numpy as np
import pandas as pd
import subprocess
import re
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score, roc_curve
from sklearn.model_selection import train_test_split

def extract_tcp_features(pcap_path, label_name):
    cmd = f"tcpdump -r {pcap_path} -nn -tt -q 2>/dev/null"
    try:
        output = subprocess.check_output(cmd, shell=True, text=True).strip()
    except subprocess.CalledProcessError:
        return pd.DataFrame()
    
    if not output:
        return pd.DataFrame()

    data = []
    last_ts = None
    for line in output.split('\n'):
        match = re.search(r'tcp (\d+)', line)
        if match:
            length = int(match.group(1))
            if length > 0:
                parts = line.split(' ')
                ts = float(parts[0])
                iat = ts - last_ts if last_ts is not None else 0.0
                last_ts = ts
                data.append({'len': length, 'iat': iat, 'label': label_name})
            
    return pd.DataFrame(data)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 ml_classifier.py <label1:pcap1> <label2:pcap2> ...")
        sys.exit(1)

    dfs = []
    for arg in sys.argv[1:]:
        label, pcap = arg.split(':')
        print(f"Extracting TCP payloads from {pcap} as {label}...")
        df = extract_tcp_features(pcap, label)
        if not df.empty:
            dfs.append(df)
        
    if not dfs:
        print("No data extracted.")
        sys.exit(1)

    df = pd.concat(dfs, ignore_index=True)
    
    X = df[['len', 'iat']].values
    y = (df['label'].str.contains('ghost')).astype(int).values

    print(f"Total packets: {len(X)}, Ghost packets: {sum(y)}")

    # Стратифицированное разделение, чтобы гарантировать оба класса в train и test
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

    clf = RandomForestClassifier(n_estimators=50, random_state=42)
    clf.fit(X_train, y_train)
    
    if len(clf.classes_) < 2:
        print("Error: Only one class in training data. Cannot predict.")
        sys.exit(1)
        
    y_pred = clf.predict_proba(X_test)[:, 1]
    
    auc = roc_auc_score(y_test, y_pred)
    fpr, tpr, thresholds = roc_curve(y_test, y_pred)
    tpr_at_fpr = np.interp(0.01, fpr, tpr)
    
    print(f"ROC-AUC = {auc:.3f}")
    print(f"TPR@FPR=1% = {tpr_at_fpr:.3f} (вероятность детекта при 1% ложных срабатываний)")
