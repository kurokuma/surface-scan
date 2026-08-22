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
| 15 | timeout/retry | TCP/TLS/HTTP CLI/TOML。`--http-body-timeout`でレスポンス全体も打ち切り | 遅延ドリップサーバに対する実測回帰テスト済み |
| 16 | Ctrl+C安全終了 | cancellation、writer flush、checkpoint。中断hostは完了扱いにしない | `tests/interrupt_resume.rs`で検証済み。実signal試験はWindows端末制約により未実施 |
| 17 | connect mode | Tokio TCP、bounded pipeline、全体semaphore | Windows end-to-end test済み |
| 18 | Linux raw SYN | sequence/ACK validation、有効なRST/ACK、closed追跡、retry、dedupe、timeout cleanup、同期pacer | Linux Docker + CAP_NET_RAWでopen/closed/cancelの3件を実行済み。外部interface/packet loss性能は未検証 |
| 19 | 同一IP複数surface | host-centric `services` | serializer/pipeline検証済み |
| 20 | 70 IP × full TCP | 50k pps設定可能、raw sender/receiver分離、host並行discovery | 専用lab性能試験が必要。達成を未主張 |

追加の設計要件についても対応状況を示す。

| 仕様 | 実装 | 状態 |
|---|---|---|
| §11 bounded queue pipeline | `runtime::pipeline`。target/open-port/fingerprint/eventはbounded mpsc、各worker数も固定、unbounded不使用 | 高open比率100 portをqueue depth 2/probe concurrency 3で回帰試験済み |
| §16 TLS metadata | 証明書検証は行わず観測結果を保持。TLS成立・非HTTPも`protocol: "tls"`で保持 | 回帰テスト済み |
| §20 suspicion scoring | 全加点項目を実装。`[suspicion]`で重み変更可、`suspicion_reasons`で根拠を出力 | unit test済み |
| §22 known C2 port | `IP:port` / `IP,port` / CSV列（`--known-service-field`）。`--ports`外でも必ず走査 | end-to-end test済み |
| §26 config | `[scan]` `[protocol]` `[fingerprint]` `[suspicion]` `[output]`。CLI優先、未知key/0 timeoutを拒否 | unit/integration test済み |
| §30 error handling | host単位のdiscovery失敗、raw SYN送信失敗はいずれも非fatal | コード経路検証 |
| checkpoint/output整合性 | host JSONLをbyte位置へ復元し派生出力を再生成。Windows既存stateもatomic replace | unit/end-to-end test済み |
| 出力メタデータ | 全レコードに`meta`（tool/version、scan_id、パラメータ、tls_verification、target_set_hash） | end-to-end test済み |

## 検証コマンド

```text
cargo check --all-targets
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
docker run --rm ... rust:1.94-slim cargo check --all-targets --locked
docker run --rm --cap-add NET_RAW ... cargo test --test raw_syn_linux --locked -- --ignored
```

性能条件はネットワーク、NIC、kernel、capabilityに依存するため、`scripts/benchmark.py`を使い、許可されたLinux labでTCP discovery duration、recall、CPU/RAM、packet loss時のretryを記録する。
