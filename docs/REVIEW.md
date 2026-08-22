# spec.md 適合性レビュー

対象コミット: `e740a08` / レビュー日: 2026-08-23
検証環境: Windows 11 (connect mode 実機実行) + 静的解析

`spec.md` の全41章と実装（約2,470行）を突き合わせ、ビルド・実機実行・負荷ケース再現によって検証した結果をまとめる。

---

## 1. 総評

**骨格は仕様どおりに実装されている。** spec §40 が「実装途中で変更してはならない」と定める8つの Design Rule は、いずれも守られている。

| Rule | 内容 | 判定 |
|---|---|---|
| Rule 1 | C2通信ポートとoperator management portを別物として扱う | 適合 |
| Rule 2 | well-known portだけで探索しない | 適合 |
| Rule 3 | TCP 1-65535を探索可能 | 適合 |
| Rule 4 | HTTP/HTTPS判定をprotocol responseで行う | 適合（実測確認） |
| Rule 5 | 全portにHTTP requestを送らない | 適合（実測確認） |
| Rule 6 | unknown HTTP/HTTPSを保持する | 適合 |
| Rule 7 | 高速discoveryに集中する | 適合 |
| Rule 8 | protocol追加をcore変更なしで行える | 適合（3 trait分離） |

品質ゲートも通過している。

```text
cargo test --all-targets   13 passed (unit 9 / integration 4)
cargo clippy -- -D warnings  clean
```

一方で、**実測で再現できた不具合が6件、仕様との構造的乖離が1件**ある。特に「HTTPレスポンス全体のデッドライン欠如」は、敵性インフラを対象とする本ツールでスキャンが無限に停止する重大な問題である。

---

## 2. 実測で確認した不具合

### 2.1 [重大] HTTPレスポンス全体のデッドラインが無い

`--http-timeout 1s` を指定しても、1バイトを400msごとに送り続けるサーバに対して **100秒経過しても probe が完了しなかった**（強制終了、出力0バイト）。

`request_http` の読み取りループは `timeout()` を **1回の read ごと** に適用しているため、相手がタイムアウト未満の間隔でデータを流し続ける限りループが終わらない。上限は `max_body + 64KiB = 327,680` バイトに達するまでで、400ms/バイトなら理論上約36時間。favicon取得で同一ポートへ再接続するため露出は2倍になる。

spec §13 が定義する **`HTTP body timeout: 1500ms`（レスポンス全体の期限）が未実装** で、`http_timeout` が read の無通信タイムアウトとして流用されていた。

### 2.2 [重大] Ctrl+Cで中断したhostがcheckpoint上「完了」になる

`discover()` はキャンセル時に部分的なopenポート一覧を返すが、その部分結果をそのまま書き出して `completed_hosts` に登録していた。結果、`--resume` すると **当該hostは走査済みとしてスキップされ、未走査ポートが恒久的に欠落** する。

README の「中断時に走査中だったhostは次回再走査されます」という記述とも矛盾し、受入条件#16「Ctrl+Cで結果を壊さず終了できる」を満たしていなかった。

### 2.3 [重大] TLS成立・非HTTPのサービスでTLSメタデータが全損する

自己署名証明書のTLSサーバがHTTP以外のバイト列を返すケースを実際に立てて確認した。

```json
{ "port": 44443, "protocol": "unknown", "tls": null, "error": "not an HTTP response" }
```

TLSハンドシェイク成功後にHTTPパースが失敗すると plain HTTP へフォールバックし、最終的に `unknown_tcp`（`tls: None`）を返していた。**取得済みの証明書 subject / issuer / SHA-256 / SAN / 有効期限がすべて破棄される。**

spec §16「証明書検証失敗でもscanを停止しない…情報として保持する」および §18 に反する。実務上、C2サーバのTLS証明書は最も価値の高い pivot であり、spec §2 が想定する「C2通信ポート」そのものがこのケースに該当する。

### 2.4 [中] 既存CSVに再実行するとヘッダ行が消える

```text
run1: ip,port,protocol,...       ← ヘッダあり
run2: 127.0.0.1,31337,http,...   ← ヘッダなし
```

`csv_empty` をファイルを開く前の既存サイズで判定していたが、非resume時は直後に `truncate(true)` で中身を捨てるため、`has_headers(false)` のまま空ファイルへ書き始めていた。

### 2.5 [中] `IP:known_c2_port` の既知ポートが `-p` 範囲外だとスキャンされない

`surface-scan -p 80 127.0.0.1:31337` で、31337 に待ち受けがあるにもかかわらず `open_ports: 0` / `services: []` となった。

spec §22 は「known C2 portも通常通りHTTP/TLS probe対象にする」と明記している。走査対象が `settings.ports` のみで、`Target.known_c2_ports` は照合にしか使われていなかった。

### 2.6 [中] `favicon_hash` がfaviconでないものをハッシュ化する

判定条件が `status < 400 && !body.is_empty()` のみで Content-Type を検証していないため、`/favicon.ico` に 200 + HTML を返すサーバ（SPAのcatch-all、HFS、多くの管理パネル）では **`favicon_hash` にindexページのハッシュがそのまま入る**。実測でも `favicon_hash == body_sha256` となった。favicon hash はクラスタリングの鍵であり、静かに偽の相関を生む。

---

## 3. 仕様との構造的乖離

### 3.1 [中] spec §11 の bounded queue pipeline が未実装

`grep -rn "mpsc\|channel" src/` の結果はゼロ件。実装は `for target in targets` による **host完全逐次ループ** で、1hostのTCP discoveryが終わってから同じhostのprobeを開始していた。

spec §11 が要求する `Target Generator → TCP Scan Queue → Open Port Queue → Protocol Probe Queue → Fingerprint Queue → Output Queue` の bounded channel 構成と、ステージ間のオーバーラップが存在しない。`--concurrency` / `--probe-concurrency` は「host内の同時実行数」であってステージ並列度ではなかった。

実測: 65535ポート×1host（loopback, concurrency 1024）で **21.5秒 / 3,050 pps**。実インターネットのfilteredポートでは `65535/1024 × 0.7s ≈ 45秒/host` が下限となり、70 IP なら約52分。syn modeでも host ごとに `TokenBucket` と raw socket を作り直し、host ごとに `thread::sleep(tcp_timeout) × (retries+1)` が入るため、70 IP で約98秒が純粋な待機時間になる。

受入条件#20「現実的な時間」は辛うじて満たすものの、仕様が指定したアーキテクチャではなく、性能を構造的に取り逃していた。

---

## 4. raw SYN backend の懸念

Linux実機が無いため静的解析による指摘。

| 項目 | 内容 |
|---|---|
| 送信失敗がfatal | `tx.send_to` のエラーを `return Err` しており、`main` の `?` で全体が異常終了する。高レート時の `ENOBUFS` は日常的に発生し、spec §30「individual target failure をfatalにしない」に反する |
| timeout cleanup 未実装 | spec §8 の明示要件。closedポートのエントリが `outstanding` に残り続け、受信スレッドの終了条件 `outstanding.is_empty()` が実質デッドコードになっていた |
| 受信スレッド起動レース | 送信開始前に100ms経過すると `outstanding` が空のため受信スレッドが即終了し、以後のSYN/ACKを取りこぼす |
| 50k pps が困難 | パケット1本ごとに `runtime.block_on(limiter.acquire())`（tokio Mutex）を呼んでおり、spec §27 の目標レートに届かないと見込まれる |
| retry時のseq上書き | 再送でseqを更新するため、初回送信への遅延SYN/ACKが検証失敗で破棄される |

なお `docs/ACCEPTANCE.md` は #18/#20 について「専用lab性能試験が必要」「達成を未主張」と記載しており、この姿勢自体は適切である。

---

## 5. 軽微な指摘

| 項目 | 内容 |
|---|---|
| nodejs fingerprint | body regex `x-powered-by.{0,20}express` が **ヘッダをbodyから探している** ため機能しない |
| go-http fingerprint | Go標準 `net/http` は Server ヘッダを送らないため、実質 fasthttp しか検出できない |
| suspicion score | spec §20 の「+2 uncommon Server header」「+2 unknown favicon/body fingerprint」が未実装。設定ファイルからの変更（§20後段）も未対応 |
| config §26 | `[fingerprint]` セクションが未対応。`config.example.toml` にも存在しない |
| `--known-service-field` | spec §22 のCSV列指定が未実装。ヘッダ行があるとfatalになる |
| CIDR展開 | `/25`〜`/30` でnetwork/broadcastアドレスが除外される（nmapは全て走査） |
| HTTP/2専用サーバ | ALPNで h2 が選ばれると status/title/header を取得しない |
| Windows CTRL_BREAK | 実測で `0xC000013A` 終了・出力0バイト・checkpoint無し。`ctrl_c` のみハンドルしていた |
| connect mode の retry | closedポートにも一律で再試行するため試行回数が実質2倍 |
| `metrics.tcp_probes` | retryを含まない論理値で、中断時も満数が計上される |

---

## 6. 適合が確認できた項目

受入条件（spec §39）のうち、以下は実測で確認した。

①IPv4リスト入力 ②1-65535指定 ③④31337でのHTTP検出 ⑤自己署名HTTPS検出 ⑥SSHバナーを非HTTPとして正しく除外 ⑦⑧⑨HFS/directory listing/login・admin分類 ⑩unknown web保持 ⑪host集約JSONL ⑫CSV（§23.3の14カラム完全一致）⑬URL/Nmapエクスポート ⑰connect mode

設計面では以下が仕様意図に忠実である。

- `ScannerBackend` / `ProtocolProbe` / `Fingerprint` の3traitによる拡張境界（§35, Rule 8）
- Set-Cookieの値を保存せずcookie名のみ記録する秘匿配慮（§15）
- `Accept-Encoding: identity` による decompression bomb 回避（§32）
- GETのみ・リダイレクト非追跡のガードレール（§32）
- `schema_version` 付きJSONL（S3/Athena想定）

---

## 7. 対応方針と結果

本レビューで指摘した全項目に対応した。詳細は [`docs/REMEDIATION.md`](REMEDIATION.md) を参照。

| 優先度 | 項目 | 状態 |
|---|---|---|
| 1 | 2.1 HTTPボディ全体のデッドライン | 修正済み |
| 2 | 2.2 中断hostのcheckpoint扱い | 修正済み |
| 3 | 2.3 TLSメタデータ保持 | 修正済み |
| 4 | 2.4 CSVヘッダ / 2.5 known C2 port / 2.6 favicon検証 | 修正済み |
| 5 | 3.1 bounded queue pipeline化 | 修正済み |
| 6 | 4. raw SYN の fatal 解消・timeout cleanup・pacing | 修正済み |
| 7 | 5. 軽微な指摘（全10件） | 修正済み |

---

## 8. 修正後の二次監査（2026-08-23）

上表を「修正済み」という記載だけで判定せず、`spec.md`、実装、回帰テストを再度突き合わせた。その結果、元レビューの指摘は全件で実装を確認できた一方、修正後コードに次の不足を追加で検出し、是正した。

| 追加検出事項 | 是正内容 | 回帰確認 |
|---|---|---|
| open portをhostごとの`FuturesUnordered`へ全件投入しており、高open比率では実質unbounded | 1 open port = 1 `ProbeJob` とし、bounded queueと固定数workerへ変更 | `bounded_pipeline::open_port_work_is_bounded_by_probe_concurrency` |
| protocol detection内でfingerprintまで実行し、仕様§5/§11のstage分離が未完了 | bounded Fingerprint Queueと`--fingerprint-concurrency`を追加。body sampleは非serializeの中間値として消費 | pipeline/high-port/output tests |
| checkpointの`output_position`をresume時に使っていない | primary JSONLをcheckpoint位置へ厳密にtruncate/seek | `output::resume_truncates_uncheckpointed_jsonl_tail` |
| crash後のresumeでCSV/flat/URL/Nmapに重複tailが残り得る | checkpoint済みhost JSONLから全派生出力を再生成 | `pipeline_outputs::cli_scans_open_only_and_writes_all_output_shapes` |
| Windowsでは既存checkpointへの`std::fs::rename`が失敗する | `MoveFileExW(REPLACE_EXISTING, WRITE_THROUGH)`で同期済み一時fileを置換 | `runtime::checkpoint_round_trip`で同一pathへ連続保存 |
| 異なるartifactに同一pathを指定すると相互truncateし得る | input/config/output/metrics/checkpoint間のaliasを起動前に拒否 | output path衝突unit test |
| empty scanのCSVにheaderが生成されない | headerを明示的に先行出力 | `output::an_empty_scan_still_creates_a_csv_header` |
| `image/*`というMIMEだけでfaviconを受理していた | raster magic必須、SVGはMIMEと`<svg` rootの両方を要求 | favicon unit/integration tests |
| `X-Content-Type-Options: nosniff`だけでGoと誤認し得る | bannerまたは複数の相関証拠を要求 | `nosniff_alone_does_not_claim_a_go_server` |
| TOMLの未知key、timeout 0、`protocol.http/https`が無視される | `deny_unknown_fields`、範囲検証、protocol switch反映 | config unit + protocol integration tests |
| CSVの引用符、欠損列、port 0を厳密に処理していない | `csv` parser採用、header/列/port検証を追加 | target parser unit tests |
| known C2 portを追加走査しても`ports_scanned`がCLI選択数のまま | hostごとの実走査port数を記録 | known C2 port end-to-end test |
| raw SYNのRST/ACKがlocal sequenceを使わず無効になり得る | SYNのlocal/remote sequenceを保持し正しいRST/ACKを生成 | Linux CAP_NET_RAW open/closed test |
| TCP probe rateがscan全体時間を分母にしていた | discovery stageのwall-clockとhost累積時間を分離 | metrics end-to-end出力 |

二次監査後の検証結果は [`docs/REMEDIATION.md`](REMEDIATION.md) §8 と [`docs/ACCEPTANCE.md`](ACCEPTANCE.md) に記録した。専用labを必要とする10k/50k ppsおよび70 IP×65535 portの性能受入だけは、引き続き達成を主張しない。
