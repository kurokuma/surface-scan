#!/usr/bin/env python3
"""Render Operator Surface Scanner host JSONL as standalone HTML and Markdown."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import html
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass
class ReportData:
    hosts: list[dict[str, Any]]
    warnings: list[str]
    source_name: str
    source_sha256: str
    generated_at: str

    @property
    def services(self) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        return [(host, service) for host in self.hosts for service in host.get("services", [])]


def load_jsonl(path: Path) -> ReportData:
    hosts: list[dict[str, Any]] = []
    warnings: list[str] = []
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for line_number, raw in enumerate(source, 1):
            digest.update(raw)
            if not raw.strip():
                continue
            try:
                record = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {error}") from error
            if not isinstance(record, dict) or not isinstance(record.get("services"), list):
                raise ValueError(f"{path}:{line_number}: expected a host record with a services array")
            if not record.get("ip") or not isinstance(record.get("scan"), dict):
                raise ValueError(f"{path}:{line_number}: host record is missing ip or scan")
            hosts.append(record)
    if not hosts:
        raise ValueError(f"{path}: no host records found")

    scan_ids = {str(host.get("meta", {}).get("scan_id", "unknown")) for host in hosts}
    schemas = {str(host.get("schema_version", "missing")) for host in hosts}
    ip_counts = collections.Counter(str(host.get("ip")) for host in hosts)
    duplicate_ips = [ip for ip, count in ip_counts.items() if count > 1]
    if len(scan_ids) > 1:
        warnings.append(f"複数のscan_idが混在しています: {', '.join(sorted(scan_ids))}")
    if len(schemas) > 1:
        warnings.append(f"複数のschema_versionが混在しています: {', '.join(sorted(schemas))}")
    if duplicate_ips:
        warnings.append(f"重複host recordがあります: {len(duplicate_ips)} IP")
    for host in hosts:
        declared = host.get("scan", {}).get("open_ports")
        actual = len(host.get("services", []))
        if declared != actual:
            warnings.append(
                f"{host.get('ip')}: scan.open_ports={declared} と services件数={actual} が一致しません"
            )

    return ReportData(
        hosts=hosts,
        warnings=warnings,
        source_name=path.name,
        source_sha256=digest.hexdigest(),
        generated_at=dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    )


def text(value: Any, fallback: str = "—") -> str:
    if value is None or value == "":
        return fallback
    return str(value)


def esc(value: Any, fallback: str = "—") -> str:
    return html.escape(text(value, fallback), quote=True)


def md(value: Any, fallback: str = "—") -> str:
    return text(value, fallback).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def endpoint(ip: str, service: dict[str, Any]) -> str:
    protocol = service.get("protocol")
    if protocol in ("http", "https"):
        return f"{protocol}://{ip}:{service.get('port')}/"
    return f"{ip}:{service.get('port')}/{protocol or 'tcp'}"


def priority(score: int) -> tuple[str, str]:
    if score >= 8:
        return "critical", "優先確認"
    if score >= 6:
        return "high", "要確認"
    if score >= 3:
        return "medium", "観察"
    return "low", "低"


def host_score(host: dict[str, Any]) -> int:
    return max((int(service.get("suspicion_score") or 0) for service in host.get("services", [])), default=0)


def counter_rows(counter: collections.Counter[str], total: int) -> str:
    rows = []
    for name, count in counter.most_common():
        percent = 0 if total == 0 else count * 100 / total
        rows.append(
            f'<div class="bar-row"><span>{esc(name)}</span><div class="bar-track">'
            f'<i style="width:{percent:.2f}%"></i></div><strong>{count}</strong>'
            f'<small>{percent:.1f}%</small></div>'
        )
    return "".join(rows)


def clusters(
    services: Iterable[tuple[dict[str, Any], dict[str, Any]]], field: str
) -> list[tuple[str, list[str]]]:
    grouped: dict[str, list[str]] = collections.defaultdict(list)
    for host, service in services:
        value: Any
        if field == "certificate_sha256":
            value = (service.get("tls") or {}).get(field)
        else:
            value = service.get(field)
        if value:
            grouped[str(value)].append(endpoint(str(host.get("ip")), service))
    return sorted(
        ((value, endpoints) for value, endpoints in grouped.items() if len(endpoints) >= 2),
        key=lambda item: (-len(item[1]), item[0]),
    )


def render_cluster_table(items: list[tuple[str, list[str]]], label: str) -> str:
    if not items:
        return '<p class="empty">反復clusterはありません。</p>'
    rows = []
    for value, endpoints in items[:20]:
        endpoint_list = "".join(f"<li>{esc(item)}</li>" for item in endpoints[:12])
        remainder = len(endpoints) - 12
        if remainder > 0:
            endpoint_list += f"<li>ほか {remainder} endpoints</li>"
        rows.append(
            "<tr>"
            f'<td><span class="count-pill">{len(endpoints)}</span></td>'
            f'<td><code title="{esc(value)}">{esc(value[:20])}…</code>'
            f'<button class="copy" type="button" data-copy="{esc(value)}">copy</button></td>'
            f'<td><details><summary>{esc(label)}を共有するendpoint</summary><ul>{endpoint_list}</ul></details></td>'
            "</tr>"
        )
    return '<div class="table-wrap"><table class="cluster-table"><thead><tr><th>件数</th><th>hash</th><th>影響範囲</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table></div>"


def service_html(ip: str, service: dict[str, Any]) -> str:
    score = int(service.get("suspicion_score") or 0)
    level, level_label = priority(score)
    protocol = text(service.get("protocol"), "unknown")
    classification = text(service.get("classification"), "unclassified")
    title = text(service.get("title"), "titleなし")
    server = text(service.get("server"), "Serverなし")
    url = endpoint(ip, service)
    tls = service.get("tls") or {}
    fingerprints = service.get("fingerprints") or []
    reasons = service.get("suspicion_reasons") or []
    reason_html = "".join(f"<li>{esc(reason)}</li>" for reason in reasons) or "<li>加点根拠なし</li>"
    fingerprint_html = ", ".join(
        f"{esc(item.get('name'))} ({float(item.get('confidence') or 0):.2f})" for item in fingerprints
    ) or "—"
    search = " ".join(
        text(value, "")
        for value in (
            ip,
            service.get("port"),
            protocol,
            classification,
            title,
            server,
            service.get("known_product"),
            service.get("body_sha256"),
            tls.get("certificate_sha256"),
            tls.get("subject"),
            " ".join(reasons),
        )
    ).lower()
    detail_pairs = [
        ("endpoint", f'<code>{esc(url)}</code><button class="copy" type="button" data-copy="{esc(url)}">copy</button>'),
        ("HTTP", f"status {esc(service.get('status'))} · {esc(service.get('content_type'))} · body {esc(service.get('body_length'))} bytes"),
        ("fingerprint", fingerprint_html),
        ("body SHA-256", f"<code>{esc(service.get('body_sha256'))}</code>"),
        ("favicon", f"SHA-256 {esc(service.get('favicon_hash'))} · mmh3 {esc(service.get('favicon_mmh3'))}"),
        ("TLS", f"{esc(tls.get('version'))} · {esc(tls.get('cipher'))} · validity {esc(tls.get('validity'))} · self-signed {esc(tls.get('self_signed'))}"),
        ("certificate", f"subject {esc(tls.get('subject'))}<br>issuer {esc(tls.get('issuer'))}<br><code>{esc(tls.get('certificate_sha256'))}</code>"),
        ("error/判定情報", f"<span class=\"error-text\">{esc(service.get('error'))}</span>"),
    ]
    detail_html = "".join(
        f'<div class="detail-key">{esc(key)}</div><div class="detail-value">{value}</div>'
        for key, value in detail_pairs
    )
    return (
        f'<details class="service {level}" data-score="{score}" data-protocol="{esc(protocol)}" '
        f'data-classification="{esc(classification)}" data-web="{str(protocol in ("http", "https")).lower()}" '
        f'data-known="{str(bool(service.get("known_c2_port"))).lower()}" data-search="{esc(search)}">'
        '<summary>'
        f'<span class="score {level}">{score}</span><span class="port">:{esc(service.get("port"))}</span>'
        f'<span class="protocol">{esc(protocol)}</span><span class="service-main"><b>{esc(title)}</b><small>{esc(server)} · {esc(classification)}</small></span>'
        f'<span class="priority-label">{level_label}</span>'
        '</summary>'
        f'<div class="service-body"><ul class="reasons">{reason_html}</ul><div class="detail-grid">{detail_html}</div></div>'
        '</details>'
    )


def host_html(host: dict[str, Any]) -> str:
    ip = str(host.get("ip"))
    services = sorted(host.get("services", []), key=lambda item: (-int(item.get("suspicion_score") or 0), int(item.get("port") or 0)))
    score = host_score(host)
    level, label = priority(score)
    protocols = collections.Counter(text(item.get("protocol"), "unknown") for item in services)
    classifications = {text(item.get("classification"), "unclassified") for item in services}
    web_count = sum(item.get("protocol") in ("http", "https") for item in services)
    known_count = sum(bool(item.get("known_c2_port")) for item in services)
    incomplete = not bool(host.get("scan", {}).get("complete"))
    search = " ".join(
        [ip]
        + [
            " ".join(
                text(value, "")
                for value in (item.get("port"), item.get("title"), item.get("server"), item.get("classification"))
            )
            for item in services
        ]
    ).lower()
    protocol_badges = "".join(f'<span class="badge">{esc(name)} {count}</span>' for name, count in protocols.items())
    open_attr = " open" if score >= 6 or incomplete else ""
    return (
        f'<details class="host-card {level}" data-score="{score}" data-protocols="{esc(" ".join(protocols))}" '
        f'data-classifications="{esc(" ".join(classifications))}" data-web="{web_count}" data-known="{known_count}" '
        f'data-incomplete="{str(incomplete).lower()}" data-search="{esc(search)}"{open_attr}>'
        '<summary class="host-summary">'
        f'<span class="host-priority {level}"><strong>{score}</strong><small>{label}</small></span>'
        f'<span class="host-id"><b>{esc(ip)}</b><small>{esc(host.get("completed_at"))}</small></span>'
        f'<span class="host-stats"><span><b>{len(services)}</b> open</span><span><b>{web_count}</b> web</span><span><b>{known_count}</b> known</span></span>'
        f'<span class="host-badges">{protocol_badges}</span>'
        '</summary>'
        f'<div class="host-services">{"".join(service_html(ip, item) for item in services)}</div>'
        '</details>'
    )


def render_html(data: ReportData, title: str) -> str:
    services = data.services
    protocol_counts = collections.Counter(text(service.get("protocol"), "unknown") for _, service in services)
    classification_counts = collections.Counter(text(service.get("classification"), "unclassified") for _, service in services)
    score_counts = collections.Counter(int(service.get("suspicion_score") or 0) for _, service in services)
    web_count = sum(service.get("protocol") in ("http", "https") for _, service in services)
    tls_count = sum(service.get("protocol") == "tls" for _, service in services)
    review_count = sum(int(service.get("suspicion_score") or 0) >= 6 for _, service in services)
    review_hosts = sum(host_score(host) >= 6 for host in data.hosts)
    incomplete = sum(not bool(host.get("scan", {}).get("complete")) for host in data.hosts)
    admin_count = sum(service.get("classification") in ("admin_panel", "login_panel") for _, service in services)
    known_count = sum(bool(service.get("known_c2_port")) for _, service in services)
    body_clusters = clusters(services, "body_sha256")
    cert_clusters = clusters(services, "certificate_sha256")
    sorted_hosts = sorted(data.hosts, key=lambda host: (-host_score(host), str(host.get("ip"))))
    meta = data.hosts[0].get("meta", {})
    warnings_html = "".join(f'<li>{esc(item)}</li>' for item in data.warnings)
    warning_panel = f'<section class="warning"><h2>データ品質上の注意</h2><ul>{warnings_html}</ul></section>' if warnings_html else ""
    high_services = sorted(
        ((host, service) for host, service in services if int(service.get("suspicion_score") or 0) >= 6),
        key=lambda item: (-int(item[1].get("suspicion_score") or 0), str(item[0].get("ip")), int(item[1].get("port") or 0)),
    )
    queue_rows = "".join(
        "<tr>"
        f'<td><span class="score {priority(int(service.get("suspicion_score") or 0))[0]}">{int(service.get("suspicion_score") or 0)}</span></td>'
        f'<td><code>{esc(endpoint(str(host.get("ip")), service))}</code></td>'
        f'<td>{esc(service.get("classification"))}</td><td>{esc(service.get("title"))}</td>'
        f'<td>{esc("; ".join(service.get("suspicion_reasons") or []))}</td>'
        "</tr>"
        for host, service in high_services
    ) or '<tr><td colspan="5" class="empty">score 6以上のserviceはありません。</td></tr>'
    host_options = "".join(f'<option value="{esc(name)}">{esc(name)}</option>' for name in sorted(protocol_counts))
    class_options = "".join(f'<option value="{esc(name)}">{esc(name)}</option>' for name in sorted(classification_counts))
    host_markup = "".join(host_html(host) for host in sorted_hosts)
    max_score = max(score_counts, default=0)
    circumference = 2 * 3.14159 * 54
    web_fraction = 0 if not services else web_count / len(services)
    tls_fraction = 0 if not services else tls_count / len(services)
    donut_web = circumference * web_fraction
    donut_tls = circumference * tls_fraction

    return f'''<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>{esc(title)}</title><style>
:root{{--ink:#142033;--muted:#64748b;--line:#dce5ef;--panel:#fff;--bg:#f3f6fa;--blue:#1769aa;--cyan:#18a6a6;--critical:#b42318;--high:#d97706;--medium:#4f6f8f;--low:#8091a5;--shadow:0 12px 35px rgba(31,50,73,.08)}}
*{{box-sizing:border-box}} html,body{{max-width:100%;overflow-x:hidden}} body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 Inter,"Noto Sans JP","Segoe UI",sans-serif}} button,input,select{{font:inherit}} code{{font-family:"Cascadia Code",Consolas,monospace;word-break:break-all}}
.hero{{background:linear-gradient(115deg,#0b2942,#124d68 56%,#167c80);color:#fff;padding:38px max(24px,calc((100% - 1440px)/2)) 34px}} .hero-top{{display:flex;justify-content:space-between;gap:20px;align-items:flex-start}} .eyebrow{{letter-spacing:.14em;text-transform:uppercase;color:#9fe5df;font-weight:800;font-size:12px}} h1{{font-size:clamp(26px,4vw,46px);line-height:1.12;margin:7px 0 12px}} .hero p{{max-width:820px;color:#d5e7ef;margin:0}} .provenance{{display:grid;grid-template-columns:repeat(5,minmax(120px,1fr));gap:10px;margin-top:25px}} .provenance div{{padding:10px 12px;background:#ffffff10;border:1px solid #ffffff24;border-radius:10px}} .provenance small{{display:block;color:#9fc2d0}} .provenance b{{font-size:13px;word-break:break-word}}
main{{max-width:1440px;min-width:0;margin:auto;padding:22px}} section{{min-width:0;margin:0 0 22px}} h2{{font-size:19px;margin:0 0 12px}} h3{{font-size:15px;margin:0 0 9px}} .kpis{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-top:-38px;position:relative}} .kpi{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:17px;box-shadow:var(--shadow)}} .kpi small{{color:var(--muted);display:block}} .kpi strong{{font-size:28px;line-height:1.2}} .kpi.alert strong{{color:var(--critical)}} .kpi.warn strong{{color:var(--high)}}
.dashboard{{display:grid;grid-template-columns:1.25fr 1fr 1fr;gap:14px}} .panel{{min-width:0;background:#fff;border:1px solid var(--line);border-radius:14px;padding:17px;box-shadow:var(--shadow)}} .donut-wrap{{display:flex;align-items:center;gap:25px}} .donut{{width:140px;height:140px}} .donut circle{{fill:none;stroke-width:16;transform:rotate(-90deg);transform-origin:50% 50%}} .donut .base{{stroke:#e6edf3}} .donut .web{{stroke:var(--cyan);stroke-dasharray:{donut_web:.2f} {circumference:.2f}}} .donut .tls{{stroke:#6f8fad;stroke-dasharray:{donut_tls:.2f} {circumference:.2f};stroke-dashoffset:-{donut_web:.2f}}} .donut text{{fill:var(--ink);font-weight:800;font-size:18px;text-anchor:middle;dominant-baseline:middle}}
.bar-row{{display:grid;grid-template-columns:100px 1fr 35px 46px;align-items:center;gap:7px;margin:7px 0}} .bar-row>span{{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}} .bar-track{{height:9px;background:#e8eef4;border-radius:10px;overflow:hidden}} .bar-track i{{display:block;height:100%;background:linear-gradient(90deg,var(--blue),var(--cyan));border-radius:10px}} .bar-row small{{color:var(--muted);text-align:right}}
.warning{{background:#fff7ed;border:1px solid #fed7aa;padding:16px;border-radius:12px}} .warning h2{{color:#9a3412}} .table-wrap{{max-width:100%;overflow:auto;overscroll-behavior-inline:contain;border:1px solid var(--line);border-radius:12px;background:#fff}} table{{width:100%;border-collapse:collapse}} th{{position:sticky;top:0;background:#edf3f8;text-align:left;color:#40546a;font-size:12px;letter-spacing:.03em}} th,td{{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}} tbody tr:hover{{background:#f7fafc}} .queue-table td:nth-child(2){{min-width:190px}} .queue-table td:last-child{{min-width:280px}}
.tabs-grid{{display:grid;grid-template-columns:1fr 1fr;gap:14px}} .count-pill,.badge{{display:inline-flex;align-items:center;border-radius:999px;padding:3px 8px;background:#eaf1f7;color:#34506a;font-size:12px}} .copy{{margin-left:7px;border:1px solid #b9c9d7;background:#fff;border-radius:6px;color:#315b7a;cursor:pointer;font-size:11px;padding:2px 6px}} .copy:hover{{background:#eaf4fb}} .cluster-table td:nth-child(2){{min-width:210px}} .cluster-table ul{{columns:2;margin:8px 0}}
.toolbar{{position:sticky;top:0;z-index:20;background:#f3f6faee;backdrop-filter:blur(12px);border:1px solid var(--line);border-radius:13px;padding:12px;display:grid;grid-template-columns:2fr repeat(3,1fr) auto auto;gap:9px;margin-bottom:12px}} .toolbar input,.toolbar select{{width:100%;border:1px solid #b9c9d7;background:#fff;border-radius:8px;padding:9px}} .check{{display:flex;align-items:center;gap:5px;white-space:nowrap}} .result-count{{color:var(--muted);margin:6px 2px 12px}}
.host-card{{background:#fff;border:1px solid var(--line);border-left:5px solid var(--low);border-radius:12px;margin:9px 0;box-shadow:0 3px 12px #243d5910;overflow:hidden}} .host-card.high{{border-left-color:var(--high)}} .host-card.critical{{border-left-color:var(--critical)}} .host-card.medium{{border-left-color:var(--medium)}} summary{{cursor:pointer}} .host-summary{{display:grid;grid-template-columns:80px minmax(210px,1.2fr) 250px 1fr;gap:15px;align-items:center;padding:13px 16px;list-style:none}} .host-summary::-webkit-details-marker,.service>summary::-webkit-details-marker{{display:none}} .host-priority{{display:flex;align-items:center;gap:7px}} .host-priority strong{{font-size:23px}} .host-priority small{{font-size:10px;color:var(--muted)}} .host-priority.critical strong{{color:var(--critical)}} .host-priority.high strong{{color:var(--high)}} .host-id b{{font:700 16px "Cascadia Code",Consolas,monospace}} .host-id small{{display:block;color:var(--muted)}} .host-stats{{display:flex;gap:16px}} .host-stats b{{font-size:16px}} .host-badges{{display:flex;flex-wrap:wrap;gap:5px;justify-content:flex-end}} .host-services{{padding:5px 14px 15px;background:#f8fafc;border-top:1px solid var(--line)}}
.service{{border:1px solid var(--line);background:#fff;border-radius:9px;margin:8px 0;overflow:hidden}} .service>summary{{display:grid;grid-template-columns:38px 65px 65px minmax(220px,1fr) 70px;align-items:center;gap:8px;padding:9px 11px;list-style:none}} .score{{display:inline-flex;width:30px;height:30px;justify-content:center;align-items:center;border-radius:8px;background:#e8eef4;font-weight:800}} .score.critical{{background:#fee4e2;color:var(--critical)}} .score.high{{background:#fff0d5;color:#a24d00}} .score.medium{{background:#e7eef5;color:#3f607f}} .port{{font:bold 13px monospace}} .protocol{{text-transform:uppercase;font-size:11px;font-weight:800;color:var(--blue)}} .service-main small{{display:block;color:var(--muted)}} .priority-label{{font-size:11px;color:var(--muted)}} .service-body{{border-top:1px solid var(--line);padding:12px 14px;display:grid;grid-template-columns:minmax(190px,.7fr) 2fr;gap:18px}} .reasons{{margin:0;padding-left:18px}} .detail-grid{{display:grid;grid-template-columns:125px 1fr;gap:5px 12px}} .detail-key{{color:var(--muted);font-size:12px}} .detail-value{{min-width:0;overflow-wrap:anywhere}} .error-text{{color:#7c4a30}} .empty{{color:var(--muted);text-align:center;padding:18px}} .hidden{{display:none!important}} footer{{max-width:1440px;margin:auto;padding:0 22px 35px;color:var(--muted)}}
@media(max-width:1050px){{.kpis{{grid-template-columns:repeat(3,1fr)}}.dashboard{{grid-template-columns:1fr 1fr}}.dashboard .panel:first-child{{grid-column:1/-1}}.provenance{{grid-template-columns:repeat(3,1fr)}}.host-summary{{grid-template-columns:70px 1fr 1fr}}.host-badges{{display:none}}.toolbar{{grid-template-columns:1fr 1fr 1fr}}}}
@media(max-width:700px){{main{{padding:12px}}.hero{{padding:25px 15px 55px}}.hero-top{{display:block}}.provenance{{grid-template-columns:1fr 1fr}}.kpis{{grid-template-columns:1fr 1fr;gap:8px}}.dashboard,.tabs-grid{{grid-template-columns:1fr}}.dashboard .panel:first-child{{grid-column:auto}}.toolbar{{position:static;grid-template-columns:1fr}}.host-summary{{grid-template-columns:60px 1fr}}.host-stats{{grid-column:1/-1}}.service>summary{{grid-template-columns:35px 55px 55px 1fr}}.priority-label{{display:none}}.service-body{{grid-template-columns:1fr}}.detail-grid{{grid-template-columns:1fr}}.detail-key{{font-weight:700;margin-top:5px}}}}
@media print{{.toolbar,.copy{{display:none}}body{{background:#fff}}.hero{{background:#123;color:#fff}}.host-card{{break-inside:avoid}}details{{display:block}}details>*{{display:block}}}}
</style></head><body>
<header class="hero"><div class="hero-top"><div><span class="eyebrow">Operator Surface Scanner / Analysis Report</span><h1>{esc(title)}</h1><p>スコアは悪性判定ではなく、確認順序を決めるtriage指標です。反復hashや同一UIは共有実装の手掛かりですが、同一operatorを単独で証明しません。</p></div></div>
<div class="provenance"><div><small>scan ID</small><b>{esc(meta.get('scan_id'))}</b></div><div><small>scan開始</small><b>{esc(meta.get('scan_started_at'))}</b></div><div><small>mode / ports</small><b>{esc(meta.get('scan_mode'))} / {esc(meta.get('port_spec'))}</b></div><div><small>rate / retry</small><b>{esc(meta.get('rate'))} / {esc(meta.get('tcp_retries'))}</b></div><div><small>source SHA-256</small><b title="{esc(data.source_sha256)}">{esc(data.source_sha256[:16])}…</b></div></div></header>
<main><section class="kpis"><div class="kpi"><small>Host records</small><strong>{len(data.hosts)}</strong></div><div class="kpi"><small>Open services</small><strong>{len(services)}</strong></div><div class="kpi"><small>Web surfaces</small><strong>{web_count}</strong></div><div class="kpi"><small>TLS-only</small><strong>{tls_count}</strong></div><div class="kpi warn"><small>Score ≥ 6 / hosts</small><strong>{review_count} / {review_hosts}</strong></div><div class="kpi alert"><small>Admin/Login</small><strong>{admin_count}</strong></div></section>
{warning_panel}
<section><h2>全体像</h2><div class="dashboard"><div class="panel"><h3>Protocol composition</h3><div class="donut-wrap"><svg class="donut" viewBox="0 0 140 140" role="img" aria-label="protocol distribution"><circle class="base" cx="70" cy="70" r="54"/><circle class="web" cx="70" cy="70" r="54"/><circle class="tls" cx="70" cy="70" r="54"/><text x="70" y="70">{len(services)}</text></svg><div>{counter_rows(protocol_counts, len(services))}</div></div></div><div class="panel"><h3>Classification</h3>{counter_rows(classification_counts, len(services))}</div><div class="panel"><h3>確認指標</h3><p><b>最高score:</b> {max_score}</p><p><b>known C2 port:</b> {known_count}</p><p><b>未完了host:</b> {incomplete}</p><p><b>反復body hash:</b> {len(body_clusters)} clusters</p><p><b>反復certificate:</b> {len(cert_clusters)} clusters</p></div></div></section>
<section><h2>優先確認キュー — score 6以上</h2><div class="table-wrap"><table class="queue-table"><thead><tr><th>score</th><th>endpoint</th><th>classification</th><th>title</th><th>根拠</th></tr></thead><tbody>{queue_rows}</tbody></table></div></section>
<section><h2>反復観測cluster</h2><div class="tabs-grid"><div class="panel"><h3>Body SHA-256</h3><p>同一response bodyを返したendpoint。共通UI、既定error page、同一配布物のpivotに利用できます。</p>{render_cluster_table(body_clusters, 'body')}</div><div class="panel"><h3>Certificate SHA-256</h3><p>同一証明書を提示したendpoint。証明書再利用のpivotですが、共有hosting等の可能性も確認してください。</p>{render_cluster_table(cert_clusters, 'certificate')}</div></div></section>
<section><h2>Host / service explorer</h2><div class="toolbar"><input id="search" type="search" placeholder="IP、port、title、Server、hash、証明書CNを検索"><select id="minScore"><option value="0">score: すべて</option><option value="3">score ≥ 3</option><option value="6">score ≥ 6</option><option value="8">score ≥ 8</option></select><select id="protocol"><option value="">protocol: すべて</option>{host_options}</select><select id="classification"><option value="">classification: すべて</option>{class_options}</select><label class="check"><input id="webOnly" type="checkbox">Webのみ</label><label class="check"><input id="incompleteOnly" type="checkbox">未完了のみ</label></div><div id="resultCount" class="result-count"></div><div id="hosts">{host_markup}</div></section></main>
<footer>生成日時 {esc(data.generated_at)} · source {esc(data.source_name)} · report generatorは外部通信を行いません。</footer>
<script>
const q=id=>document.getElementById(id); const controls=['search','minScore','protocol','classification','webOnly','incompleteOnly'].map(q);
function applyFilters(){{const term=q('search').value.trim().toLowerCase(),min=Number(q('minScore').value),proto=q('protocol').value,cls=q('classification').value,web=q('webOnly').checked,incomplete=q('incompleteOnly').checked;let shown=0;document.querySelectorAll('.host-card').forEach(host=>{{let visible=Number(host.dataset.score)>=min&&(!term||host.dataset.search.includes(term))&&(!proto||host.dataset.protocols.split(' ').includes(proto))&&(!cls||host.dataset.classifications.split(' ').includes(cls))&&(!web||Number(host.dataset.web)>0)&&(!incomplete||host.dataset.incomplete==='true');host.classList.toggle('hidden',!visible);if(visible)shown++;}});q('resultCount').textContent=`${{shown}} / ${{document.querySelectorAll('.host-card').length}} host records`;}}
controls.forEach(control=>control.addEventListener(control.type==='search'?'input':'change',applyFilters));
document.querySelectorAll('.copy').forEach(button=>button.addEventListener('click',async event=>{{event.preventDefault();event.stopPropagation();try{{if(!navigator.clipboard)throw new Error('clipboard unavailable');await navigator.clipboard.writeText(button.dataset.copy);}}catch(_error){{const area=document.createElement('textarea');area.value=button.dataset.copy;area.style.position='fixed';area.style.opacity='0';document.body.appendChild(area);area.select();document.execCommand('copy');area.remove();}}button.textContent='copied';setTimeout(()=>button.textContent='copy',900);}}));applyFilters();
</script></body></html>'''


def render_markdown(data: ReportData, title: str) -> str:
    services = data.services
    protocol_counts = collections.Counter(text(service.get("protocol"), "unknown") for _, service in services)
    class_counts = collections.Counter(text(service.get("classification"), "unclassified") for _, service in services)
    high_services = sorted(
        ((host, service) for host, service in services if int(service.get("suspicion_score") or 0) >= 6),
        key=lambda item: (-int(item[1].get("suspicion_score") or 0), str(item[0].get("ip")), int(item[1].get("port") or 0)),
    )
    meta = data.hosts[0].get("meta", {})
    complete = sum(bool(host.get("scan", {}).get("complete")) for host in data.hosts)
    review_hosts = sum(host_score(host) >= 6 for host in data.hosts)
    lines = [
        f"# {title}",
        "",
        "> suspicion scoreは悪性判定ではなく、確認順序を決めるtriage指標です。反復hashはpivot候補であり、単独で同一operatorを証明しません。",
        "",
        "## サマリー",
        "",
        "| 項目 | 値 |",
        "|---|---:|",
        f"| Host records | {len(data.hosts)} |",
        f"| 完了host | {complete} |",
        f"| Open services | {len(services)} |",
        f"| Web surfaces | {sum(service.get('protocol') in ('http', 'https') for _, service in services)} |",
        f"| TLS-only | {protocol_counts.get('tls', 0)} |",
        f"| Score 6以上のhost | {review_hosts} |",
        f"| Admin/Login | {sum(service.get('classification') in ('admin_panel', 'login_panel') for _, service in services)} |",
        "",
        "## Scan provenance",
        "",
        f"- Scan ID: `{md(meta.get('scan_id'))}`",
        f"- 開始: `{md(meta.get('scan_started_at'))}`",
        f"- Mode: `{md(meta.get('scan_mode'))}`",
        f"- Ports: `{md(meta.get('port_spec'))}`",
        f"- Rate / retries: `{md(meta.get('rate'))}` / `{md(meta.get('tcp_retries'))}`",
        f"- Source: `{md(data.source_name)}`",
        f"- Source SHA-256: `{data.source_sha256}`",
        "",
        "## Protocol / classification",
        "",
        "| 種別 | 件数 |",
        "|---|---:|",
    ]
    for name, count in protocol_counts.most_common():
        lines.append(f"| protocol: `{md(name)}` | {count} |")
    for name, count in class_counts.most_common():
        lines.append(f"| classification: `{md(name)}` | {count} |")

    if data.warnings:
        lines.extend(["", "## データ品質上の注意", ""] + [f"- {md(item)}" for item in data.warnings])

    lines.extend(
        [
            "",
            "## 優先確認キュー — score 6以上",
            "",
            "| Score | Endpoint | Classification | Title | 根拠 |",
            "|---:|---|---|---|---|",
        ]
    )
    if high_services:
        for host, service in high_services:
            lines.append(
                f"| {int(service.get('suspicion_score') or 0)} | `{md(endpoint(str(host.get('ip')), service))}` | "
                f"{md(service.get('classification'))} | {md(service.get('title'))} | "
                f"{md('; '.join(service.get('suspicion_reasons') or []))} |"
            )
    else:
        lines.append("| — | — | — | — | score 6以上なし |")

    lines.extend(["", "## Host triage", "", "| Max score | IP | Open | Web | TLS-only | Review endpoints |", "|---:|---|---:|---:|---:|---|"])
    for host in sorted(data.hosts, key=lambda item: (-host_score(item), str(item.get("ip")))):
        host_services = host.get("services", [])
        review = [f"{item.get('port')}/{item.get('protocol')} ({item.get('suspicion_score', 0)})" for item in host_services if int(item.get("suspicion_score") or 0) >= 3]
        lines.append(
            f"| {host_score(host)} | `{md(host.get('ip'))}` | {len(host_services)} | "
            f"{sum(item.get('protocol') in ('http', 'https') for item in host_services)} | "
            f"{sum(item.get('protocol') == 'tls' for item in host_services)} | {md(', '.join(review))} |"
        )

    for heading, field in (("Body SHA-256 clusters", "body_sha256"), ("Certificate SHA-256 clusters", "certificate_sha256")):
        lines.extend(["", f"## {heading}", "", "| 件数 | Hash | Endpoints |", "|---:|---|---|"])
        items = clusters(services, field)
        if not items:
            lines.append("| 0 | — | 反復clusterなし |")
        for value, endpoints in items:
            lines.append(f"| {len(endpoints)} | `{value}` | {md(', '.join(endpoints))} |")

    lines.extend(["", f"_Generated at {data.generated_at}_", ""])
    return "\n".join(lines)


def default_output(input_path: Path, suffix: str) -> Path:
    name = input_path.name
    if name.endswith(".jsonl"):
        name = name[:-6]
    return input_path.with_name(f"{name}.report.{suffix}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render scanner host JSONL as a standalone interactive HTML report and Markdown summary."
    )
    parser.add_argument("input", type=Path, help="host-centric JSONL produced by surface-scan")
    parser.add_argument("--html", type=Path, help="HTML output path (default: <input>.report.html)")
    parser.add_argument("--markdown", type=Path, help="Markdown output path (default: <input>.report.md)")
    parser.add_argument("--title", help="report title")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        data = load_jsonl(args.input)
        title = args.title or f"Operator Surface Report — {args.input.stem}"
        html_path = args.html or default_output(args.input, "html")
        markdown_path = args.markdown or default_output(args.input, "md")
        html_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(render_html(data, title), encoding="utf-8", newline="\n")
        markdown_path.write_text(render_markdown(data, title), encoding="utf-8", newline="\n")
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"HTML: {html_path}")
    print(f"Markdown: {markdown_path}")
    print(f"Hosts: {len(data.hosts)}, services: {len(data.services)}, warnings: {len(data.warnings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
