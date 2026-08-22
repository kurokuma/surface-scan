# ValleyRAT Suspected C2 — Operator Surface Report

> suspicion scoreは悪性判定ではなく、確認順序を決めるtriage指標です。反復hashはpivot候補であり、単独で同一operatorを証明しません。

## サマリー

| 項目 | 値 |
|---|---:|
| Host records | 53 |
| 完了host | 53 |
| Open services | 523 |
| Web surfaces | 83 |
| TLS-only | 51 |
| Score 6以上のhost | 34 |
| Admin/Login | 3 |

## Scan provenance

- Scan ID: `0cdf7fc920a99979`
- 開始: `2026-08-22T18:39:02.275428193Z`
- Mode: `syn`
- Ports: `1-65535`
- Rate / retries: `10000` / `1`
- Source: `valleyrat_susp_c2.jsonl`
- Source SHA-256: `a29dd54fdba3dc85fb085813802c27c913d534b972399efaa8f9b966cb4c2edf`

## Protocol / classification

| 種別 | 件数 |
|---|---:|
| protocol: `unknown` | 389 |
| protocol: `http` | 83 |
| protocol: `tls` | 51 |
| classification: `unclassified` | 389 |
| classification: `unknown_web` | 73 |
| classification: `unknown_tls` | 51 |
| classification: `generic_web` | 7 |
| classification: `admin_panel` | 3 |

## 優先確認キュー — score 6以上

| Score | Endpoint | Classification | Title | 根拠 |
|---:|---|---|---|---|
| 10 | `http://112.213.103.58:18080/` | admin_panel | JiuDuanRAT · 战术监控墙 | +2 port >= 10000; +2 uncommon server header; +2 admin keywords; +2 executable/archive files referenced; +2 unknown favicon/body fingerprint |
| 10 | `http://112.213.103.61:18080/` | admin_panel | JiuDuanRAT · 战术监控墙 | +2 port >= 10000; +2 uncommon server header; +2 admin keywords; +2 executable/archive files referenced; +2 unknown favicon/body fingerprint |
| 10 | `http://118.107.1.216:18080/` | admin_panel | JiuDuanRAT · 战术监控墙 | +2 port >= 10000; +2 uncommon server header; +2 admin keywords; +2 executable/archive files referenced; +2 unknown favicon/body fingerprint |
| 6 | `http://112.213.103.58:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://112.213.103.61:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://118.107.40.30:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://118.107.40.33:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://118.107.40.38:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://118.107.43.220:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://118.107.43.227:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://118.107.43.230:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://121.127.253.206:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://121.127.254.27:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://134.122.128.66:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://134.122.128.69:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://134.122.128.73:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://134.122.139.118:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://134.122.139.120:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://134.122.139.122:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://134.122.155.52:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://134.122.155.61:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://134.122.155.70:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://134.122.173.138:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://134.122.173.171:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://134.122.173.181:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://134.122.204.10:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://134.122.204.16:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://134.122.204.23:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://137.220.153.75:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://137.220.153.80:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://137.220.155.201:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://137.220.155.213:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://137.220.155.65:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://137.220.155.75:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://202.61.139.206:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |
| 6 | `http://202.61.139.46:47001/` | unknown_web | Not Found | +2 port >= 10000; +2 uncommon server header; +2 unknown favicon/body fingerprint |

## Host triage

| Max score | IP | Open | Web | TLS-only | Review endpoints |
|---:|---|---:|---:|---:|---|
| 10 | `112.213.103.58` | 16 | 3 | 1 | 5985/http (4), 18080/http (10), 47001/http (6) |
| 10 | `112.213.103.61` | 16 | 3 | 1 | 5985/http (4), 18080/http (10), 47001/http (6) |
| 10 | `118.107.1.216` | 15 | 1 | 1 | 18080/http (10) |
| 6 | `118.107.40.30` | 6 | 2 | 1 | 5985/http (4), 23389/tls (3), 47001/http (6) |
| 6 | `118.107.40.33` | 5 | 2 | 1 | 5985/http (4), 23389/tls (3), 47001/http (6) |
| 6 | `118.107.40.38` | 5 | 2 | 1 | 5985/http (4), 23389/tls (3), 47001/http (6) |
| 6 | `118.107.43.220` | 15 | 2 | 1 | 5985/http (4), 23389/tls (3), 47001/http (6) |
| 6 | `118.107.43.227` | 14 | 2 | 1 | 5985/http (4), 23389/tls (3), 47001/http (6) |
| 6 | `118.107.43.230` | 14 | 2 | 1 | 5985/http (4), 23389/tls (3), 47001/http (6) |
| 6 | `121.127.253.206` | 16 | 3 | 1 | 5357/http (4), 5985/http (4), 47001/http (6) |
| 6 | `121.127.254.27` | 16 | 3 | 1 | 80/http (4), 5985/http (4), 47001/http (6) |
| 6 | `134.122.128.66` | 14 | 3 | 1 | 5357/http (4), 5985/http (4), 23389/tls (3), 47001/http (6) |
| 6 | `134.122.128.69` | 13 | 3 | 1 | 5357/http (4), 5985/http (4), 23389/tls (3), 47001/http (6) |
| 6 | `134.122.128.73` | 13 | 3 | 1 | 5357/http (4), 5985/http (4), 23389/tls (3), 47001/http (6) |
| 6 | `134.122.139.118` | 5 | 2 | 1 | 5985/http (4), 23389/tls (3), 47001/http (6) |
| 6 | `134.122.139.120` | 4 | 2 | 1 | 5985/http (4), 23389/tls (3), 47001/http (6) |
| 6 | `134.122.139.122` | 4 | 2 | 1 | 5985/http (4), 23389/tls (3), 47001/http (6) |
| 6 | `134.122.155.52` | 19 | 3 | 1 | 5985/http (4), 23389/tls (3), 47001/http (6) |
| 6 | `134.122.155.61` | 18 | 3 | 1 | 5985/http (4), 23389/tls (3), 47001/http (6) |
| 6 | `134.122.155.70` | 18 | 3 | 1 | 5985/http (4), 23389/tls (3), 47001/http (6) |
| 6 | `134.122.173.138` | 10 | 2 | 1 | 5985/http (4), 23389/tls (3), 47001/http (6) |
| 6 | `134.122.173.171` | 9 | 2 | 1 | 5985/http (4), 23389/tls (3), 47001/http (6) |
| 6 | `134.122.173.181` | 9 | 2 | 1 | 5985/http (4), 23389/tls (3), 47001/http (6) |
| 6 | `134.122.204.10` | 6 | 2 | 1 | 5985/http (4), 23389/tls (3), 47001/http (6) |
| 6 | `134.122.204.16` | 5 | 2 | 1 | 5985/http (4), 23389/tls (3), 47001/http (6) |
| 6 | `134.122.204.23` | 5 | 2 | 1 | 5985/http (4), 23389/tls (3), 47001/http (6) |
| 6 | `137.220.153.75` | 18 | 2 | 1 | 5985/http (4), 47001/http (6), 61067/tls (3) |
| 6 | `137.220.153.80` | 18 | 2 | 1 | 5985/http (4), 47001/http (6), 61067/tls (3) |
| 6 | `137.220.155.201` | 30 | 4 | 1 | 5985/http (4), 47001/http (6), 47756/tls (3) |
| 6 | `137.220.155.213` | 30 | 4 | 1 | 5985/http (4), 47001/http (6), 47756/tls (3) |
| 6 | `137.220.155.65` | 15 | 2 | 1 | 5985/http (4), 47001/http (6), 54595/tls (3) |
| 6 | `137.220.155.75` | 15 | 2 | 1 | 5985/http (4), 47001/http (6), 54595/tls (3) |
| 6 | `202.61.139.206` | 14 | 3 | 1 | 5357/http (4), 5985/http (4), 47001/http (6) |
| 6 | `202.61.139.46` | 15 | 3 | 1 | 5357/http (4), 5985/http (4), 47001/http (6) |
| 3 | `134.122.129.20` | 3 | 0 | 1 | 23389/tls (3) |
| 3 | `134.122.129.5` | 4 | 0 | 1 | 23389/tls (3) |
| 3 | `134.122.129.6` | 3 | 0 | 1 | 23389/tls (3) |
| 3 | `134.122.130.202` | 5 | 0 | 1 | 23389/tls (3) |
| 3 | `134.122.130.243` | 4 | 0 | 1 | 23389/tls (3) |
| 3 | `134.122.130.246` | 4 | 0 | 1 | 23389/tls (3) |
| 3 | `143.92.61.11` | 3 | 0 | 1 | 23389/tls (3) |
| 3 | `143.92.61.14` | 3 | 0 | 1 | 23389/tls (3) |
| 3 | `143.92.61.19` | 3 | 0 | 1 | 23389/tls (3) |
| 3 | `143.92.61.2` | 4 | 0 | 1 | 23389/tls (3) |
| 3 | `143.92.61.212` | 4 | 0 | 1 | 23389/tls (3) |
| 3 | `143.92.61.219` | 3 | 0 | 1 | 23389/tls (3) |
| 3 | `143.92.61.220` | 3 | 0 | 1 | 23389/tls (3) |
| 1 | `112.213.108.202` | 2 | 0 | 1 | — |
| 1 | `121.127.246.76` | 14 | 0 | 1 | — |
| 1 | `137.220.242.10` | 6 | 0 | 1 | — |
| 1 | `137.220.242.47` | 6 | 0 | 1 | — |
| 0 | `137.220.202.180` | 2 | 0 | 0 | — |
| 0 | `137.220.202.253` | 2 | 0 | 0 | — |

## Body SHA-256 clusters

| 件数 | Hash | Endpoints |
|---:|---|---|
| 66 | `ce7127c38e30e92a021ed2bd09287713c6a923db9ffdb43f126e8965d777fbf0` | http://112.213.103.58:5985/, http://112.213.103.58:47001/, http://112.213.103.61:5985/, http://112.213.103.61:47001/, http://118.107.40.30:5985/, http://118.107.40.30:47001/, http://118.107.40.33:5985/, http://118.107.40.33:47001/, http://118.107.40.38:5985/, http://118.107.40.38:47001/, http://118.107.43.220:5985/, http://118.107.43.220:47001/, http://118.107.43.227:5985/, http://118.107.43.227:47001/, http://118.107.43.230:5985/, http://118.107.43.230:47001/, http://121.127.253.206:5985/, http://121.127.253.206:47001/, http://121.127.254.27:5985/, http://121.127.254.27:47001/, http://134.122.128.66:5985/, http://134.122.128.66:47001/, http://134.122.128.69:5985/, http://134.122.128.69:47001/, http://134.122.128.73:5985/, http://134.122.128.73:47001/, http://134.122.139.118:5985/, http://134.122.139.118:47001/, http://134.122.139.120:5985/, http://134.122.139.120:47001/, http://134.122.139.122:5985/, http://134.122.139.122:47001/, http://134.122.155.52:5985/, http://134.122.155.52:47001/, http://134.122.155.61:5985/, http://134.122.155.61:47001/, http://134.122.155.70:5985/, http://134.122.155.70:47001/, http://134.122.173.138:5985/, http://134.122.173.138:47001/, http://134.122.173.171:5985/, http://134.122.173.171:47001/, http://134.122.173.181:5985/, http://134.122.173.181:47001/, http://134.122.204.10:5985/, http://134.122.204.10:47001/, http://134.122.204.16:5985/, http://134.122.204.16:47001/, http://134.122.204.23:5985/, http://134.122.204.23:47001/, http://137.220.153.75:5985/, http://137.220.153.75:47001/, http://137.220.153.80:5985/, http://137.220.153.80:47001/, http://137.220.155.65:5985/, http://137.220.155.65:47001/, http://137.220.155.75:5985/, http://137.220.155.75:47001/, http://137.220.155.201:5985/, http://137.220.155.201:47001/, http://137.220.155.213:5985/, http://137.220.155.213:47001/, http://202.61.139.46:5985/, http://202.61.139.46:47001/, http://202.61.139.206:5985/, http://202.61.139.206:47001/ |
| 6 | `fb2d9f058c2010c57f86a05ae33d282f33e3825290c66b8b120cd177416c6bdf` | http://121.127.253.206:5357/, http://134.122.128.66:5357/, http://134.122.128.69:5357/, http://134.122.128.73:5357/, http://202.61.139.46:5357/, http://202.61.139.206:5357/ |
| 3 | `19c130e5420ab63e4b68a1e4f4e4318c27bf83842af831ec8748963f22b78000` | http://134.122.155.52:80/, http://134.122.155.61:80/, http://134.122.155.70:80/ |
| 3 | `a2b8556549f3dd5deb1a7d9ae8165fcc54860df5b54a01d479f98d00a931cfde` | http://112.213.103.58:18080/, http://112.213.103.61:18080/, http://118.107.1.216:18080/ |
| 2 | `301bd9f16f94feedfae7a946a14bac38cb73c43efe6117bc5586835af03d7d6f` | http://137.220.155.201:8888/, http://137.220.155.213:8888/ |
| 2 | `c603b4dc9df18f3f53ed5c08b1c50727cd505081c15f45c6b1d2544076fae203` | http://137.220.155.201:80/, http://137.220.155.213:80/ |

## Certificate SHA-256 clusters

| 件数 | Hash | Endpoints |
|---:|---|---|
| 4 | `6d14c31dc669d66e3894c73bcccf9440bae237f1897cc42807afb5004b4c4e80` | 143.92.61.2:23389/tls, 143.92.61.11:23389/tls, 143.92.61.14:23389/tls, 143.92.61.19:23389/tls |
| 3 | `0a4ccbe0eb10adc28dfef6a198d5682a9f254e5e32f950c270b1f38c258cb940` | 143.92.61.212:23389/tls, 143.92.61.219:23389/tls, 143.92.61.220:23389/tls |
| 3 | `16c1aef79e6d9ec025502e2a9eff78c0e10853bcfae7ed0f7906ff48e60c6188` | 118.107.40.30:23389/tls, 118.107.40.33:23389/tls, 118.107.40.38:23389/tls |
| 3 | `31c0ba44889345f1fe787e7d1d9554374383c72a579559d3267b9a883706680f` | 134.122.128.66:23389/tls, 134.122.128.69:23389/tls, 134.122.128.73:23389/tls |
| 3 | `37bca30bf0dc6eadb3c8992979e86efb79cf6a74c7743cd3bba67a32869dfa35` | 134.122.155.52:23389/tls, 134.122.155.61:23389/tls, 134.122.155.70:23389/tls |
| 3 | `4c923def3a8c70bdddde853dbe29c91fd37c8619969b6f4a42e06c62930cb803` | 134.122.204.10:23389/tls, 134.122.204.16:23389/tls, 134.122.204.23:23389/tls |
| 3 | `76687035990896d983b3c90190845084c715dd2e10e5c88b31cd566164157621` | 134.122.130.202:23389/tls, 134.122.130.243:23389/tls, 134.122.130.246:23389/tls |
| 3 | `a99fbc723409fc365a1b668ebdc51814a71e8959290c4c46258650265c487c8a` | 134.122.129.5:23389/tls, 134.122.129.6:23389/tls, 134.122.129.20:23389/tls |
| 3 | `ae07217e69c19dfc7dfafb53b182ee3f6397f9884a3f4678ab9e3a3444acf95e` | 134.122.139.118:23389/tls, 134.122.139.120:23389/tls, 134.122.139.122:23389/tls |
| 3 | `b404fb6354021514db997b80aa41a237b95dc31f9caf2cb63d68268bcf26282c` | 134.122.173.138:23389/tls, 134.122.173.171:23389/tls, 134.122.173.181:23389/tls |
| 3 | `b4a5565354eb5d21f5475e40d71892f08db1d9f4acc6c7d9ae742087198768dc` | 118.107.43.220:23389/tls, 118.107.43.227:23389/tls, 118.107.43.230:23389/tls |
| 2 | `3c706935dbf38493ab6c931c9db6699de7fb05bedc2ddbcef12b243a467e2c95` | 137.220.153.75:61067/tls, 137.220.153.80:61067/tls |
| 2 | `a2c287ca4cd84ed33feb5f332c3b61f2799d7837918742c7da625fa3f6a0d01a` | 202.61.139.46:3389/tls, 202.61.139.206:3389/tls |
| 2 | `bb6f1dfd88041f6e13b2178f062880b363fd8553a05b9a8bb0ffc1913279339c` | 137.220.155.201:47756/tls, 137.220.155.213:47756/tls |
| 2 | `c4a90b486c45e381d02e4f4ce2f7385ee8c8db27fdf806be124a7351d567e68a` | 137.220.242.10:3389/tls, 137.220.242.47:3389/tls |
| 2 | `e2d56e154b24b2a0aaba2a2b6049a26480b2e494a057279416a6b8e6d4abbc0b` | 137.220.155.65:54595/tls, 137.220.155.75:54595/tls |

_Generated at 2026-08-22T19:06:32.262775Z_
