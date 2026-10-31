import sys
import pandas as pd
from ml_tls_v2 import extract_session_features

# Скармливаем скрипту только Vision
vision_data = extract_session_features('/tmp/vision_small.pcap', 'vision')
df = pd.DataFrame(vision_data)

print("\n=== БАЗОВЫЙ ПРОФИЛЬ VISION ===")
features = ['avg_len', 'max_len', 'count', 'avg_iat', 'active_span', 'total_tls_bytes']
for f in features:
    print(f"{f:15}: mean={df[f].mean():.2f}, min={df[f].min():.2f}, max={df[f].max():.2f}, std={df[f].std():.2f}")
