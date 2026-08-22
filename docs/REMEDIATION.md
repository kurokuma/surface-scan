# 修正記録

[`docs/REVIEW.md`](REVIEW.md) で指摘した全項目への対応。各項目に検証方法を付す。

---

## 1. 重大不具合

### 1.1 HTTPレスポンス全体のデッドライン（REVIEW 2.1）

`http_timeout` は1回のread無通信タイムアウト、`http_body_timeout` はレスポンス全体の期限として分離した。両者を `timeout_at` の `min` で適用するため、どちらが先に来ても部分データを保持したまま打ち切る。

- 追加: `--http-body-timeout`（既定1500ms）、TOML `protocol.http_body_timeout_ms`
- 二重防御として `ProbeContext::probe_budget()` を導入し、1ポートあたりの最大滞留時間をパイプライン側でも打ち切る

**検証**: 400msごとに1バイトを永久に送るサーバへ実測。

```text
修正前: 100秒経過しても完了せず（強制終了、出力0バイト）
修正後: 3秒で完了、protocol=http / status=200 / server=slow / response_latency_ms=1501
```

回帰テスト: `tests/hardening.rs::a_slow_drip_server_cannot_outlast_the_body_deadline`

### 1.2 中断hostのcheckpoint扱い（REVIEW 2.2）

`DiscoveryOutcome` に `complete` フラグを追加し、backendが「完走したか」を明示するようにした。writerステージは `complete == false` のhostを `completed_hosts` へ入れず、既存エントリがあれば削除する。部分結果自体は `scan.complete: false` 付きで出力するため、観測済みの情報は失われない。

**検証**: 回帰テスト `tests/interrupt_resume.rs::an_interrupted_host_is_not_checkpointed_as_completed`（中断を模したbackendでcheckpointが空のままであることを確認）

### 1.3 TLS成立・非HTTPのメタデータ全損（REVIEW 2.3）

TLS試行の結果を `TlsOutcome::{Web, TlsOnly, NoTls}` の3値に分離した。ハンドシェイクが成立してHTTPパースだけ失敗した場合は `protocol: "tls"` / `classification: "unknown_tls"` として証明書情報を保持する。plain HTTPへのフォールバックは `NoTls` のときだけ行う。

証明書検証は従来どおり無効（`NoCertificateVerification`）。検証を強制せず観測結果を記録する方針を明示するため、`TlsMetadata.verification_skipped` と `meta.tls_verification` を追加した。あわせて `public_key_sha256`（SPKIハッシュ）を追加。

**検証**: 自己署名TLS + 非HTTP応答サーバへ実測。

```text
修正前: {"protocol":"unknown","tls":null,"error":"not an HTTP response"}
修正後: protocol=tls / classification=unknown_tls
        subject=CN=evil-panel / issuer=CN=evil-panel / self_signed=true
        certificate_sha256, public_key_sha256, TLSv1_3, TLS13_AES_256_GCM_SHA384
```

回帰テスト: `tests/hardening.rs::tls_without_http_keeps_the_certificate_metadata`、`::an_untrusted_certificate_never_stops_the_probe`

---

## 2. 中程度の不具合

### 2.1 CSVヘッダ消失（REVIEW 2.4）

ヘッダ要否の判定を「ファイルを開く前のサイズ」から「非append、または追記先が空」へ変更した。新規実行は必ず truncate するため常にヘッダを書き、resume時の追記だけが既存ヘッダを引き継ぐ。

回帰テスト: `tests/pipeline_outputs.rs::rerunning_over_an_existing_csv_keeps_a_header`、および resume 時の重複ヘッダ検査

### 2.2 known C2 portが走査対象外（REVIEW 2.5）

パイプラインのdiscoveryステージで、host単位に `--ports` と `Target.known_c2_ports` を union する（`merge_known_ports`）。

**検証**: `-p 1` かつ target `127.0.0.1:31337` で 31337 を検出し `known_c2_port: true` を付与。

回帰テスト: `tests/pipeline_outputs.rs::a_known_c2_port_outside_the_range_is_still_scanned`、`runtime::pipeline::tests::known_ports_are_added_to_the_sweep`

### 2.3 favicon検証（REVIEW 2.6）

`/favicon.ico` の応答を Content-Type とマジックバイト（ICO/PNG/GIF/JPEG/SVG/RIFF）で検証し、実際にアイコンだった場合のみハッシュ化する。`text/html` / `application/json` は明示的に棄却。

あわせて Shodan/Censys と突合できるよう `favicon_mmh3`（MIME base64 → MurmurHash3 x86_32、符号付き32bit）を追加した。`favicon_hash`（SHA-256）も従来どおり保持する。

回帰テスト: `tests/high_port_detection.rs::html_at_the_favicon_path_yields_no_favicon_hash`、`protocol::tests::{html_served_at_favicon_path_is_not_an_icon, real_icons_are_accepted}`、`util::tests::mmh3_matches_known_vectors`（公開ベクタ `hello`=613153351、`foo`=-156908512 で照合）

---

## 3. bounded queue pipeline（REVIEW 3.1）

host逐次ループを廃し、spec §11 のステージ構成を `src/runtime/pipeline.rs` に実装した。

```text
Target Generator ─(bounded)→ TCP Discovery ×N ─(bounded)→ Protocol Probe ×M ─(bounded)→ Fingerprint ×F ─(bounded)→ Writer ×1
```

- 全チャネルが `tokio::sync::mpsc::channel(queue_depth)` の bounded。unbounded channel は不使用
- `--host-concurrency`（既定: connect 8 / syn 1）でdiscovery並列度、`--probe-concurrency`でprobe並列度、`--fingerprint-concurrency`でfingerprint並列度、`--queue-depth`でキュー深度を制御
- socket上限は `ConnectScanner` 内の全体semaphore（`--concurrency`）で保証し、host並列化してもFD枯渇しない
- token bucketは backend インスタンス保持となり、`--rate` がプロセス全体の上限として機能する（従来はhostごとに再生成）
- writerは単一consumer。短時間のI/Oはqueueで吸収し、詰まった場合はbounded backpressureを返してmemory増大を防ぐ
- host単位の失敗（`discover` のErr）はwarnログのみで、scan全体を止めない

**検証**: 4 host × 1000 port（うち3 hostは到達不能なTEST-NET）を並列走査し、5.05秒で完了。`ports_attempted` はknown C2 port分だけ1001に増えている。

### 3.1 connect backendの改善

- `ConnectionRefused` / `ConnectionReset` を closed と確定扱いし、retryを消費しない（従来はclosedポートにも一律再試行）
- `probes_sent` を実際の試行数（retry込み）で計上。`metrics.tcp_probes` が論理値ではなく実測値になった
- 中断時は新規投入を止め、in-flightの結果は捨てずに回収する

---

## 4. raw SYN backend（REVIEW 4章）

| 指摘 | 対応 |
|---|---|
| 送信失敗がscan全体のfatal | 1000件ごとにwarnを出す per-probe イベントへ降格。`ENOBUFS` でscanが落ちない（spec §30） |
| outstanding の timeout cleanup 未実装 | `Outstanding.expires_at` を持たせ、テーブルが4096件を超えたら期限切れを掃除（spec §8） |
| 受信スレッド起動レース | 終了条件を「テーブルが空」から `sending_done` フラグへ変更。起動直後にテーブルが空でも終了しない |
| 50k pps が困難 | パケットごとの `block_on(tokio Mutex)` を廃止し、同期 `Pacer`（burst許容の絶対時刻ペーシング）へ置換 |
| retry時のseq上書きで遅延応答を破棄 | seq を (host, port) で固定し、前回試行への遅延SYN/ACKも検証を通るようにした |
| RST（closed）を追跡していない | closed集合を追加。確定済みポートはretry対象から除外し、`attempted` に算入 |

Linux実機での確認は `tests/raw_syn_linux.rs`（`--ignored`、`CAP_NET_RAW` 必要）に3ケース追加した。

---

## 5. 軽微な指摘（REVIEW 5章）

| 項目 | 対応 |
|---|---|
| nodejs fingerprint | `RuleFingerprint` に header matcher を追加し、`X-Powered-By: Express` をヘッダから判定。回帰テスト `express_is_detected_from_its_header_not_the_body` |
| go-http fingerprint | `gin` / `echo` のServer banner、Go特有のエラー文言、`X-Content-Type-Options: nosniff` を追加 |
| suspicion score | spec §20 の全項目を実装（`uncommon_server` +2、`unknown_fingerprint` +2 を追加）。`[suspicion]` テーブルで全weightと高位ポート閾値を変更可能。`suspicion_reasons` を出力し、スコアの根拠を監査可能にした |
| config `[fingerprint]` | 12ルールの個別ON/OFFを実装。`config.example.toml` に記載。回帰テスト `disabled_rules_do_not_fire` |
| `--known-service-field` | 実装。CSVヘッダ行を検出し、指定列を known C2 port として読む。フラグ未指定でもヘッダ行はfatalにせず、`port`/`c2_port` 等の慣用列名を自動採用 |
| CIDR展開 | network/broadcastを含む全アドレスを展開（`/30` は4アドレス）。`/32` も1アドレスとして扱う |
| HTTP/2専用サーバ | TLSメタデータとsuspicion scoreを保持し、`error` にh2フレーム未解析である旨を明示（従来はメタデータなしで `known_product: null` のみ） |
| Windows CTRL_BREAK | `ctrl_c` / `ctrl_break` / `ctrl_close` / `ctrl_shutdown`、Unixは `SIGINT` / `SIGTERM` を捕捉。2回目のシグナルで即時終了（exit 130） |
| connect retry | 上記3.1のとおりclosed確定で打ち切り |
| `metrics.tcp_probes` | 上記3.1のとおり実測値へ |

---

## 6. 出力メタデータ

全出力レコードに `meta` ブロックを付与した。S3へ蓄積したJSONLを後日Athenaで読む際、実行時のコマンドラインを知らなくても解釈できる。

```json
{
  "tool": "operator-surface-scanner", "tool_version": "0.1.0", "schema_version": "2",
  "scan_id": "198e60e2cae5423b", "scan_label": "campaign-2026-08",
  "scan_started_at": "2026-08-22T15:59:41Z", "scan_mode": "connect",
  "port_spec": "1", "port_count": 1, "target_count": 1, "target_set_hash": "ebd75c1b...",
  "rate": 10000, "burst": 1000, "concurrency": 1024, "probe_concurrency": 128, "fingerprint_concurrency": 32, "host_concurrency": 8, "queue_depth": 64,
  "tcp_timeout_ms": 200, "tcp_retries": 0, "tls_timeout_ms": 1000,
  "http_enabled": true, "https_enabled": true, "http_timeout_ms": 1000, "http_body_timeout_ms": 1500, "max_body_bytes": 262144,
  "tls_verification": "skipped", "resumed": false, "host_os": "windows"
}
```

- host JSONL、`--flat-output`、`--metrics-json` の全てに同一の `meta` を付与
- CSVには `scan_id` と `scan_started_at` 列を追加（レコードとscanの突合用）
- `--scan-label` でキャンペーン名等を任意に刻める
- host側に `scan.ports_attempted` / `scan.tcp_probes_sent` / `scan.complete` を追加
- service側に `suspicion_reasons` / `favicon_mmh3` / `tls.public_key_sha256` / `tls.verification_skipped` を追加

---

## 7. 修正後の二次監査で追加した是正

- open-port workを1件ずつbounded queueへ流し、高open比率hostでもfuture数を`probe_concurrency`以下に制限
- protocol detectionとfingerprintを独立したbounded queue/workerへ分離し、body sampleはfingerprint後に破棄して出力しない
- resume時はhost JSONLをcheckpointの`output_position`へ復元し、CSV/flat/URL/NmapをそのJSONLから再生成
- Windows checkpointを同期済み一時fileからreplace-existingで更新し、2回目以降の保存失敗を解消
- input/config/output/metrics/checkpointのpath aliasを起動前に拒否
- empty scanでもCSV headerを生成
- faviconはraster magic、またはSVG MIME + rootを必須化
- configの未知key、0 timeout、無効なprotocol組合せを拒否し、`http`/`https` switchをprobeへ反映
- target CSVを引用符対応parserで処理し、欠損列とport 0を拒否
- raw SYNのRST/ACKに正しいlocal/remote sequenceを使用
- discovery wall-clockを分離し、平均ppsの分母をscan全体時間から修正

## 8. 検証結果

```text
cargo fmt --all -- --check   clean
cargo check --all-targets --locked   clean (Windows / Linux container)
cargo clippy --all-targets --locked -- -D warnings   clean
cargo test --all-targets --locked     55 passed / 0 failed (Windows)
docker ... cargo test --all-targets --locked   55 passed / 0 failed (Linux, raw SYN 3 ignored)
docker ... cargo test --test raw_syn_linux --locked -- --ignored   3 passed / 0 failed
python -m py_compile scripts/benchmark.py   clean
```

Windows内訳: unit 38、`bounded_pipeline` 1、`high_port_detection` 4、`hardening` 5、`pipeline_outputs` 5、`interrupt_resume` 1、`multiprocess` 1。Linuxの`raw_syn_linux` 3件は`CAP_NET_RAW`付きDockerで実行した。

未主張の項目は `docs/REVIEW.md` および `docs/ACCEPTANCE.md` の記載どおり、外部interface・packet loss条件を含むraw SYN性能（10k/50k pps）と70 IP × 65535の受入時間、および実console eventによるgraceful shutdownである。これらは専用labまたは対話consoleでの計測が必要で、本修正では達成を主張しない。

## 9. Multi-thread / Multi-process高速化

- `--worker-threads`でTokio multi-thread runtimeを動的構築（既定は論理CPU数）
- `--processes`でdeduplicate済みtargetをround-robin shardし、同一実行fileの子processを並列起動
- rate、burst、connect socket、protocol/fingerprint concurrency、thread予算を均等分割し、合計上限を維持
- 全workerで共通`scan_id`/metadataを使用し、親processがhost順にJSONL/CSV/flat/URL/Nmapを再生成
- process別checkpointとcoordinator stateを分離し、resume時も重複host/serviceを生成しない
- 中断hostのcheckpoint byte位置を進めず、resume時に部分host行をrollback

回帰試験はWindows上で2 target × 2 processを実際に起動し、初回走査とresumeの両方でhost JSONL 2行、CSV 1 header + 2 service、metrics `hosts_completed=2`を確認した。
