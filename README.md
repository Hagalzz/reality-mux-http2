# reality-mux-http2

Multiplexed transport over REALITY with HTTP/2-shaped packet sizing.

## Overview
This project provides a custom multiplexer (`ghostmux`) operating over REALITY/TLS 1.3. It is designed to provide the performance benefits of connection reuse (multiplexing) while maintaining an HTTP/2-like packet-size distribution to resist Machine Learning traffic classification.

## Key Results (Testbed RTT 100ms)
* **Performance:** p95 latency ~0.108s vs ~0.579s for Vision (≈5.4x lower). +27% req/s compared to Vision. Parity with `mux.cool`.
* **ML Resistance:** A Random Forest (depth=3) trained on `max_len` and `count` features achieved **ROC-AUC = 1.000** for Vision (perfectly classified), but only **ROC-AUC = 0.500** for this transport (random guessing).
*Note: ROC-AUC 0.500 means this specific model on these features didn't beat random guessing. It is not absolute proof of indistinguishability.*

## Architecture
```text
Logical streams
       │
       ▼
     ghostmux
       │
       ▼
 REALITY / TLS 1.3
       │
       ▼
    Network
Engineering Rigor
0 data races under load.

2.66 million executions of frame parser and SOCKS5 fuzzing (0 crashes).

45-minute soak test with stable RSS plateau and no FD leaks.

Fixed CLOSE-WAIT socket leak via bounded deadlines.

Upstream Proposals (XTLS/REALITY)
We prepared 3 fixes for upstream review:

Certificate buffer limit increased to 65,536 bytes.

Explicit ErrCamouflageLengthMismatch instead of hard crash.

ML-KEM hybrid key-share compatibility fix.

Limitations & Methodology
All benchmarks were run on a distributed testbed with RTT 100ms. ML features used: max_len and count. Train/test splits are done by independent connections.


    Network
