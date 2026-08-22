# Version 1 acceptance matrix

`spec.md`の完成条件を、実装と検証境界に対応付ける。

| # | 条件 | 実装/証拠 | 状態 |
|---:|---|---|---|
| 1 | IPv4リスト入力 | `target::parse_targets`、file/stdin/positional CLI | unit test済み |
| 2 | TCP 1-65535 | range parser、default `1-65535` | unit test済み |
| 3 | 任意open port | connect/raw backendはport非依存 | integration test済み |
| 4 | high-port HTTP | 31337優先fixture | integration test済み |
| 5 | high-port HTTPS | 49152優先・自己署名fixture | integration test済み |
| 6 | non-HTTP negative control | SSH banner fixture | integration test済み |
| 7 | HFS fingerprint | server/title/bodyの複数根拠とconfidence | unit test済み |
| 8 | directory listing | Index/Directory/Parent heuristics | unit/integration test済み |
| 9 | login/admin | password form/admin keywords | unit/integration test済み |
| 10 | unknown Web保持 | `is_unknown_web`、`known_product: null` | pipeline test済み |
| 11 | host JSONL | 1行1host、同一hostのservice配列 | end-to-end test済み |
| 12 | CSV | 必須分析カラム | end-to-end test済み |
| 13 | URL list | detected HTTP/HTTPSのみ | end-to-end test済み |
| 14 | rate制御 | backend分離token bucket、burst | unit test済み |
| 15 | timeout/retry | TCP/TLS/HTTP CLI/TOML | unit/integration経路で検証 |
| 16 | Ctrl+C安全終了 | cancellation、writer flush、checkpoint | コード経路検証。手動signal試験は未実施 |
| 17 | connect mode | Tokio TCP、bounded in-flight futures | Windows end-to-end test済み |
| 18 | Linux raw SYN | sequence/ACK validation、retry、dedupe、RST | Linux CAP_NET_RAW container loopback実行済み |
| 19 | 同一IP複数surface | host-centric `services` | serializer/pipeline検証済み |
| 20 | 70 IP × full TCP | 50k pps設定可能、raw sender/receiver分離 | 専用lab性能試験が必要。達成を未主張 |

## 検証コマンド

```text
cargo check --all-targets
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
docker run --rm ... rust:1.94-slim cargo check --all-targets --locked
docker run --rm --cap-add NET_RAW ... cargo test --test raw_syn_linux --locked -- --ignored
```

性能条件はネットワーク、NIC、kernel、capabilityに依存するため、`scripts/benchmark.py`を使い、許可されたLinux labでTCP discovery duration、recall、CPU/RAM、packet loss時のretryを記録する。

