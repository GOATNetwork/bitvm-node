#!/usr/bin/env python3
"""RPC health monitor for goat-node.

Collects and summarizes:
1) graph status counts
2) instance status counts (bridge-in) and swap escrow status counts (bridge-out)
3) node online or offline status
4) overall service health verdict
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class EndpointCheck:
    name: str
    path: str
    ok: bool
    latency_ms: int
    detail: str


@dataclass
class ProofLagConfig:
    header_chain_height_url: str
    state_chain_rpc_url: str
    header_chain_lag_alert_blocks: int
    state_chain_lag_alert_blocks: int


SEVERITY = {"HEALTHY": 0, "DEGRADED": 1, "UNHEALTHY": 2}
DEFAULT_HEADER_CHAIN_HEIGHT_URL = "https://mempool.space/testnet4"
DEFAULT_STATE_CHAIN_RPC_URL = "https://rpc.testnet3.goat.network"
DEFAULT_HEADER_CHAIN_LAG_ALERT_BLOCKS = 30
DEFAULT_STATE_CHAIN_LAG_ALERT_BLOCKS = 200


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_url(base_url: str, path: str, params: Optional[Dict[str, Any]] = None) -> str:
    base = base_url.rstrip("/")
    rel = path if path.startswith("/") else "/" + path
    # If caller already uses a /v1 base URL, avoid producing /v1/v1/... paths.
    if rel.startswith("/v1") and base.endswith("/v1"):
        rel = rel[3:] or "/"
    url = f"{base}{rel}"
    if params:
        clean = {k: v for k, v in params.items() if v is not None}
        if clean:
            url = f"{url}?{urllib.parse.urlencode(clean)}"
    return url


def http_get(base_url: str, path: str, timeout: int, params: Optional[Dict[str, Any]] = None) -> Tuple[int, str, int]:
    url = build_url(base_url, path, params)
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    start = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body, int((time.monotonic() - start) * 1000)
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", errors="replace")
        return err.code, body, int((time.monotonic() - start) * 1000)


def get_json(
    base_url: str,
    path: str,
    timeout: int,
    params: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], EndpointCheck]:
    status, body, latency = http_get(base_url, path, timeout, params=params)
    if status < 200 or status >= 300:
        raise RuntimeError(f"HTTP {status}: {body[:300]}")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as err:
        raise RuntimeError(f"invalid json: {err}") from err
    check = EndpointCheck(name=path, path=build_url(base_url, path, params), ok=True, latency_ms=latency, detail="ok")
    return payload, check


def get_text_check(base_url: str, path: str, timeout: int) -> EndpointCheck:
    try:
        status, body, latency = http_get(base_url, path, timeout)
        if status < 200 or status >= 300:
            return EndpointCheck(
                name=path,
                path=build_url(base_url, path),
                ok=False,
                latency_ms=latency,
                detail=f"HTTP {status}: {body[:160]}",
            )
        return EndpointCheck(
            name=path,
            path=build_url(base_url, path),
            ok=True,
            latency_ms=latency,
            detail="ok",
        )
    except Exception as err:  # pylint: disable=broad-except
        return EndpointCheck(
            name=path,
            path=build_url(base_url, path),
            ok=False,
            latency_ms=0,
            detail=str(err),
        )


def fetch_pages(
    base_url: str,
    path: str,
    item_key: str,
    timeout: int,
    page_size: int,
    fixed_params: Optional[Dict[str, Any]] = None,
    max_pages: int = 1000,
) -> Tuple[List[Dict[str, Any]], int, List[EndpointCheck]]:
    all_items: List[Dict[str, Any]] = []
    checks: List[EndpointCheck] = []
    total = 0
    offset = 0
    params = dict(fixed_params or {})

    for _ in range(max_pages):
        page_params = dict(params)
        page_params["offset"] = offset
        page_params["limit"] = page_size
        payload, check = get_json(base_url, path, timeout, page_params)
        checks.append(check)

        if not isinstance(payload, dict):
            raise RuntimeError(f"{path}: payload is not object")

        page_items = payload.get(item_key, [])
        if not isinstance(page_items, list):
            raise RuntimeError(f"{path}: {item_key} is not list")

        if total == 0:
            try:
                total = int(payload.get("total", 0))
            except (TypeError, ValueError) as err:
                raise RuntimeError(f"{path}: invalid total field") from err

        all_items.extend(page_items)
        if len(page_items) < page_size:
            break
        offset += page_size
    else:
        raise RuntimeError(f"{path}: pagination exceeded max_pages={max_pages}")

    return all_items, total, checks


def count_by(items: List[Dict[str, Any]], extractor: Callable[[Dict[str, Any]], str]) -> Dict[str, int]:
    counter: Counter[str] = Counter()
    for item in items:
        status = extractor(item)
        counter[status or "UNKNOWN"] += 1
    return dict(sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])))


def percentile(values: List[float], q: float) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(values)
    index = int(round((len(sorted_values) - 1) * q))
    index = max(0, min(index, len(sorted_values) - 1))
    return float(sorted_values[index])


def summarize_numeric(values: List[float]) -> Dict[str, float]:
    if not values:
        return {"count": 0.0, "min": 0.0, "max": 0.0, "avg": 0.0, "p50": 0.0, "p95": 0.0}
    count = float(len(values))
    total = float(sum(values))
    return {
        "count": count,
        "min": float(min(values)),
        "max": float(max(values)),
        "avg": total / count,
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
    }


def latest_proof_height(proof_desc: Dict[str, Any]) -> Optional[int]:
    block_start = int(proof_desc.get("block_start", 0))
    block_end = int(proof_desc.get("block_end", 0))

    # Some backends use u32::MAX as a sentinel and this should not be used as height.
    if block_end >= 4_000_000_000:
        return None
    if block_end > block_start:
        return block_end - 1
    if block_end > 0:
        return block_end
    return None


def fetch_header_chain_tip_height(timeout: int, header_chain_height_url: str) -> int:
    status, body, _latency = http_get(header_chain_height_url, "/api/blocks/tip/height", timeout)
    if status < 200 or status >= 300:
        raise RuntimeError(f"header chain rpc HTTP {status}: {body[:200]}")
    return int(body.strip())


def fetch_state_chain_tip_height(timeout: int, state_chain_rpc_url: str) -> int:
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_blockNumber",
            "params": [],
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        state_chain_rpc_url,
        data=payload,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")
    data = json.loads(body)
    result = data.get("result")
    if not isinstance(result, str):
        raise RuntimeError(f"state chain rpc invalid response: {body[:200]}")
    return int(result, 16)


def summarize_chain_lag(
    details: Dict[str, Dict[str, Any]],
    timeout: int,
    lag_config: ProofLagConfig,
) -> Tuple[Dict[str, Any], List[str]]:
    issues: List[str] = []
    summary: Dict[str, Any] = {
        "alert": False,
        "header_chain": {
            "proof_height": None,
            "chain_height": None,
            "lag_blocks": None,
            "threshold_blocks": lag_config.header_chain_lag_alert_blocks,
            "alert": False,
            "error": None,
        },
        "state_chain": {
            "proof_height": None,
            "chain_height": None,
            "lag_blocks": None,
            "threshold_blocks": lag_config.state_chain_lag_alert_blocks,
            "alert": False,
            "error": None,
        },
    }

    header_proof = details.get("header_chain", {})
    header_proof_height = latest_proof_height(header_proof) if header_proof.get("available") else None
    summary["header_chain"]["proof_height"] = header_proof_height
    try:
        header_chain_height = fetch_header_chain_tip_height(
            timeout,
            lag_config.header_chain_height_url,
        )
        summary["header_chain"]["chain_height"] = header_chain_height
        if header_proof_height is None:
            summary["header_chain"]["error"] = "header_chain proof height unavailable"
            issues.append("header_chain proof height unavailable")
        else:
            lag_blocks = max(0, header_chain_height - header_proof_height)
            summary["header_chain"]["lag_blocks"] = lag_blocks
            summary["header_chain"]["alert"] = (
                lag_blocks > lag_config.header_chain_lag_alert_blocks
            )
    except Exception as err:  # pylint: disable=broad-except
        summary["header_chain"]["error"] = str(err)
        issues.append(f"header_chain height fetch failed: {err}")

    state_proof = details.get("state_chain", {})
    state_proof_height = latest_proof_height(state_proof) if state_proof.get("available") else None
    summary["state_chain"]["proof_height"] = state_proof_height
    try:
        state_chain_height = fetch_state_chain_tip_height(
            timeout,
            lag_config.state_chain_rpc_url,
        )
        summary["state_chain"]["chain_height"] = state_chain_height
        if state_proof_height is None:
            summary["state_chain"]["error"] = "state_chain proof height unavailable"
            issues.append("state_chain proof height unavailable")
        else:
            lag_blocks = max(0, state_chain_height - state_proof_height)
            summary["state_chain"]["lag_blocks"] = lag_blocks
            summary["state_chain"]["alert"] = (
                lag_blocks > lag_config.state_chain_lag_alert_blocks
            )
    except Exception as err:  # pylint: disable=broad-except
        summary["state_chain"]["error"] = str(err)
        issues.append(f"state_chain height fetch failed: {err}")

    summary["alert"] = bool(
        summary["header_chain"].get("alert") or summary["state_chain"].get("alert")
    )
    return summary, issues


def fetch_chain_proof_desc(
    base_url: str,
    timeout: int,
    proof_type: str,
) -> Tuple[Optional[Dict[str, Any]], EndpointCheck, Optional[str]]:
    payload, check = get_json(
        base_url,
        "/v1/proofs/chain_proofs_desc",
        timeout,
        params={"proof_type": proof_type},
    )
    if not isinstance(payload, dict):
        return None, check, "payload is not object"
    if payload.get("error"):
        return None, check, str(payload.get("error"))
    proof_desc = payload.get("proof_desc")
    if not isinstance(proof_desc, dict):
        return None, check, "proof_desc missing"
    return proof_desc, check, None


def collect_proof_latency_stats(
    base_url: str,
    timeout: int,
    lag_config: ProofLagConfig,
) -> Tuple[Dict[str, Any], List[EndpointCheck], List[str]]:
    checks: List[EndpointCheck] = []
    issues: List[str] = []
    now_ts = int(time.time())

    details: Dict[str, Dict[str, Any]] = {}
    proving_times: List[float] = []
    total_times: List[float] = []
    updated_delay_secs: List[float] = []

    for proof_type in ["header_chain", "commit_chain", "state_chain"]:
        try:
            proof_desc, check, error = fetch_chain_proof_desc(base_url, timeout, proof_type)
            checks.append(check)
            if error:
                details[proof_type] = {
                    "available": False,
                    "error": error,
                }
                issues.append(f"proof {proof_type} unavailable: {error}")
                continue

            proving_time = float(proof_desc.get("proving_time", 0))
            total_time_to_proof = float(proof_desc.get("total_time_to_proof", 0))
            updated_at = int(proof_desc.get("updated_at", 0))
            delay = float(max(0, now_ts - updated_at)) if updated_at > 0 else 0.0

            proving_times.append(proving_time)
            total_times.append(total_time_to_proof)
            if delay > 0:
                updated_delay_secs.append(delay)

            details[proof_type] = {
                "available": True,
                "state": proof_desc.get("state", ""),
                "block_start": int(proof_desc.get("block_start", 0)),
                "block_end": int(proof_desc.get("block_end", 0)),
                "proving_time": proving_time,
                "total_time_to_proof": total_time_to_proof,
                "updated_at": updated_at,
                "updated_delay_secs": delay,
            }
        except Exception as err:  # pylint: disable=broad-except
            issues.append(f"proof {proof_type} failed: {err}")
            details[proof_type] = {
                "available": False,
                "error": str(err),
            }

    available_count = sum(1 for v in details.values() if v.get("available"))
    if available_count == 0:
        issues.append("proof latency stats unavailable for all chain proof types")

    chain_lag, chain_lag_issues = summarize_chain_lag(details, timeout, lag_config)
    issues.extend(chain_lag_issues)

    stats = {
        "details": details,
        "summary": {
            "available_count": available_count,
            "proving_time": summarize_numeric(proving_times),
            "total_time_to_proof": summarize_numeric(total_times),
            "updated_delay_secs": summarize_numeric(updated_delay_secs),
            "chain_lag": chain_lag,
        },
    }
    return stats, checks, issues


def summarize_once(
    base_url: str,
    timeout: int,
    page_size: int,
    lag_config: ProofLagConfig,
) -> Dict[str, Any]:
    # Public RPCs often cap limit at 100.
    page_size = max(1, min(page_size, 100))

    checks: List[EndpointCheck] = []
    optional_checks: List[EndpointCheck] = []
    hard_issues: List[str] = []
    soft_issues: List[str] = []

    root_check = get_text_check(base_url, "/", timeout)
    optional_checks.append(root_check)

    metrics_check = get_text_check(base_url, "/metrics", timeout)
    optional_checks.append(metrics_check)

    # Use a core API route for liveness probing. Some deployments return 404 on '/'.
    rpc_probe = get_text_check(base_url, "/v1/nodes/overview", timeout)

    try:
        instances_overview, overview_check = get_json(base_url, "/v1/instances/overview", timeout)
        checks.append(overview_check)
    except Exception as err:  # pylint: disable=broad-except
        instances_overview = {}
        hard_issues.append(f"instances_overview failed: {err}")

    try:
        nodes_overview_resp, nodes_overview_check = get_json(base_url, "/v1/nodes/overview", timeout)
        checks.append(nodes_overview_check)
        nodes_overview = nodes_overview_resp.get("nodes_overview", {})
        if not isinstance(nodes_overview, dict):
            nodes_overview = {}
            hard_issues.append("nodes_overview payload invalid")
    except Exception as err:  # pylint: disable=broad-except
        nodes_overview = {}
        hard_issues.append(f"nodes_overview failed: {err}")

    graph_items: List[Dict[str, Any]] = []
    graph_total = 0
    try:
        graph_items, graph_total, graph_checks = fetch_pages(
            base_url,
            "/v1/graphs",
            "graphs",
            timeout,
            page_size,
            fixed_params={},
        )
        checks.extend(graph_checks)
    except Exception as err:  # pylint: disable=broad-except
        hard_issues.append(f"graph list failed: {err}")

    instance_in_items: List[Dict[str, Any]] = []
    instance_in_total = 0
    try:
        instance_in_items, instance_in_total, in_checks = fetch_pages(
            base_url,
            "/v1/instances",
            "instance_wraps",
            timeout,
            page_size,
            fixed_params={},
        )
        checks.extend(in_checks)
    except Exception as err:  # pylint: disable=broad-except
        hard_issues.append(f"bridge-in instance list failed: {err}")

    instance_out_items: List[Dict[str, Any]] = []
    instance_out_total = 0
    try:
        instance_out_items, instance_out_total, out_checks = fetch_pages(
            base_url,
            "/v1/swaps",
            "swaps",
            timeout,
            page_size,
            fixed_params={},
        )
        checks.extend(out_checks)
    except Exception as err:  # pylint: disable=broad-except
        hard_issues.append(f"bridge-out instance list failed: {err}")

    node_items: List[Dict[str, Any]] = []
    node_total = 0
    try:
        node_items, node_total, node_checks = fetch_pages(
            base_url,
            "/v1/nodes",
            "nodes",
            timeout,
            page_size,
            fixed_params={},
        )
        checks.extend(node_checks)
    except Exception as err:  # pylint: disable=broad-except
        hard_issues.append(f"node list failed: {err}")

    proof_latency_stats, proof_checks, proof_issues = collect_proof_latency_stats(
        base_url,
        timeout,
        lag_config,
    )
    checks.extend(proof_checks)
    soft_issues.extend(proof_issues)

    chain_lag = proof_latency_stats.get("summary", {}).get("chain_lag", {})
    header_lag = chain_lag.get("header_chain", {})
    state_lag = chain_lag.get("state_chain", {})
    if header_lag.get("alert"):
        hard_issues.append(
            "header_chain proof lag alert: "
            f"lag_blocks={header_lag.get('lag_blocks')}, "
            f"threshold={header_lag.get('threshold_blocks')}"
        )
    if state_lag.get("alert"):
        hard_issues.append(
            "state_chain proof lag alert: "
            f"lag_blocks={state_lag.get('lag_blocks')}, "
            f"threshold={state_lag.get('threshold_blocks')}"
        )

    graph_status_counts = count_by(
        graph_items,
        lambda x: (
            (x.get("graph") or {}).get("status")
            if isinstance(x, dict) and isinstance(x.get("graph"), dict)
            else "MISSING_GRAPH"
        ),
    )

    instance_in_status_counts = count_by(
        instance_in_items,
        lambda x: (
            (x.get("instance") or {}).get("status")
            if isinstance(x, dict) and isinstance(x.get("instance"), dict)
            else "MISSING_INSTANCE"
        ),
    )
    instance_out_status_counts = count_by(
        instance_out_items,
        lambda x: (
            (x.get("swap") or {}).get("status")
            if isinstance(x, dict) and isinstance(x.get("swap"), dict)
            else "MISSING_INSTANCE"
        ),
    )
    node_status_counts = count_by(
        node_items,
        lambda x: x.get("status") if isinstance(x, dict) else "UNKNOWN",
    )

    if graph_total and graph_total != len(graph_items):
        soft_issues.append(f"graph total mismatch: expected {graph_total}, got {len(graph_items)}")
    if instance_in_total and instance_in_total != len(instance_in_items):
        soft_issues.append(
            f"bridge-in total mismatch: expected {instance_in_total}, got {len(instance_in_items)}"
        )
    if instance_out_total and instance_out_total != len(instance_out_items):
        soft_issues.append(
            f"bridge-out total mismatch: expected {instance_out_total}, got {len(instance_out_items)}"
        )
    if node_total and node_total != len(node_items):
        soft_issues.append(f"node total mismatch: expected {node_total}, got {len(node_items)}")

    online_nodes = int(node_status_counts.get("Online", 0) + node_status_counts.get("online", 0))
    if node_total > 0 and online_nodes == 0:
        hard_issues.append("all nodes are offline")

    # Direct RPC alert when liveness probe fails and no core endpoint returned successfully.
    rpc_available = rpc_probe.ok or len(checks) > 0
    if not rpc_available:
        hard_issues.append(f"rpc unavailable: {rpc_probe.detail}")

    # Committee/operator liveness checks are required operational guards.
    online_operators = int(nodes_overview.get("online_operators", 0)) if nodes_overview else 0
    offline_committees = int(nodes_overview.get("offline_committees", 0)) if nodes_overview else 0
    if online_operators <= 0:
        hard_issues.append("no online operator")
    if offline_committees > 0:
        hard_issues.append(f"offline committees detected: {offline_committees}")

    issues = hard_issues + soft_issues

    verdict = "HEALTHY"
    if hard_issues:
        verdict = "UNHEALTHY"
    elif soft_issues:
        verdict = "DEGRADED"

    return {
        "generated_at": utc_now(),
        "base_url": base_url,
        "verdict": verdict,
        "issues": issues,
        "hard_issues": hard_issues,
        "soft_issues": soft_issues,
        "graph": {
            "total": len(graph_items),
            "status_counts": graph_status_counts,
        },
        "instance": {
            "bridge_in_total": len(instance_in_items),
            "bridge_in_status_counts": instance_in_status_counts,
            "bridge_out_total": len(instance_out_items),
            "bridge_out_status_counts": instance_out_status_counts,
        },
        "node": {
            "total": len(node_items),
            "status_counts": node_status_counts,
            "nodes_overview": nodes_overview,
        },
        "rpc_liveness": {
            "available": rpc_available,
            "probe": rpc_probe.__dict__,
        },
        "liveness": {
            "online_operators": online_operators,
            "offline_committees": offline_committees,
            "operator_ok": online_operators > 0,
            "committee_ok": offline_committees == 0,
        },
        "proof_builder_latency": proof_latency_stats,
        "instances_overview": instances_overview,
        "endpoint_checks": [c.__dict__ for c in checks],
        "optional_checks": [c.__dict__ for c in optional_checks],
    }


def print_checks(title: str, checks: List[Dict[str, Any]], show_all: bool) -> None:
    if not checks:
        print(f"\n{title}: none")
        return

    failed = [c for c in checks if not c.get("ok", False)]
    passed = len(checks) - len(failed)
    print(f"\n{title}: {passed}/{len(checks)} passed")

    if show_all:
        for c in checks:
            mark = "OK" if c.get("ok", False) else "FAIL"
            print(f"  [{mark}] {c['path']} ({c['latency_ms']} ms) {c['detail']}")
        return

    if failed:
        print("  failed endpoints:")
        for c in failed:
            print(f"  [FAIL] {c['path']} ({c['latency_ms']} ms) {c['detail']}")


def print_human(snapshot: Dict[str, Any], show_all_checks: bool = False) -> None:
    print(f"[{snapshot['generated_at']}] RPC health snapshot for {snapshot['base_url']}")
    print(f"VERDICT: {snapshot['verdict']}")

    rpc_liveness = snapshot.get("rpc_liveness", {})
    if rpc_liveness:
        probe = rpc_liveness.get("probe", {})
        print(
            "RPC liveness: available={} probe={} ({} ms) {}".format(
                rpc_liveness.get("available"),
                probe.get("path", ""),
                probe.get("latency_ms", 0),
                probe.get("detail", ""),
            )
        )

    print("\nGraph status counts:")
    print(f"total={snapshot['graph']['total']}")
    for key, value in snapshot["graph"]["status_counts"].items():
        print(f"  {key}: {value}")

    print("\nInstance status counts (bridge-in):")
    print(f"total={snapshot['instance']['bridge_in_total']}")
    for key, value in snapshot["instance"]["bridge_in_status_counts"].items():
        print(f"  {key}: {value}")

    print("\nInstance status counts (bridge-out):")
    print(f"total={snapshot['instance']['bridge_out_total']}")
    for key, value in snapshot["instance"]["bridge_out_status_counts"].items():
        print(f"  {key}: {value}")

    print("\nNode status counts:")
    print(f"total={snapshot['node']['total']}")
    for key, value in snapshot["node"]["status_counts"].items():
        print(f"  {key}: {value}")

    nodes_overview = snapshot["node"].get("nodes_overview", {})
    if nodes_overview:
        print("\nNode overview:")
        for key, value in nodes_overview.items():
            print(f"  {key}: {value}")

    liveness = snapshot.get("liveness", {})
    if liveness:
        print("\nOperator/Committee liveness:")
        print(
            "  operator_ok={} (online_operators={})".format(
                liveness.get("operator_ok"),
                liveness.get("online_operators"),
            )
        )
        print(
            "  committee_ok={} (offline_committees={})".format(
                liveness.get("committee_ok"),
                liveness.get("offline_committees"),
            )
        )

    proof_stats = snapshot.get("proof_builder_latency", {})
    if proof_stats:
        print("\nProof-builder latency stats:")
        summary = proof_stats.get("summary", {})
        proving_time = summary.get("proving_time", {})
        total_time = summary.get("total_time_to_proof", {})
        delay = summary.get("updated_delay_secs", {})
        chain_lag = summary.get("chain_lag", {})

        print(
            "  samples={} proving_time(avg/p50/p95/max)={:.2f}/{:.2f}/{:.2f}/{:.2f}".format(
                int(proving_time.get("count", 0.0)),
                proving_time.get("avg", 0.0),
                proving_time.get("p50", 0.0),
                proving_time.get("p95", 0.0),
                proving_time.get("max", 0.0),
            )
        )
        print(
            "  total_time_to_proof(avg/p50/p95/max)={:.2f}/{:.2f}/{:.2f}/{:.2f}".format(
                total_time.get("avg", 0.0),
                total_time.get("p50", 0.0),
                total_time.get("p95", 0.0),
                total_time.get("max", 0.0),
            )
        )
        print(
            "  updated_delay_secs(avg/p50/p95/max)={:.2f}/{:.2f}/{:.2f}/{:.2f}".format(
                delay.get("avg", 0.0),
                delay.get("p50", 0.0),
                delay.get("p95", 0.0),
                delay.get("max", 0.0),
            )
        )
        print(
            "  chain_lag_alert={} (header>{} blocks, state>{} blocks)".format(
                chain_lag.get("alert", False),
                chain_lag.get("header_chain", {}).get("threshold_blocks", "?"),
                chain_lag.get("state_chain", {}).get("threshold_blocks", "?"),
            )
        )
        for proof_type in ["header_chain", "state_chain"]:
            item = chain_lag.get(proof_type, {})
            if item.get("error"):
                print(f"  {proof_type} lag: unavailable ({item.get('error')})")
            else:
                print(
                    "  {} lag_blocks={} (proof_height={}, chain_height={}, threshold={}) alert={}".format(
                        proof_type,
                        item.get("lag_blocks"),
                        item.get("proof_height"),
                        item.get("chain_height"),
                        item.get("threshold_blocks"),
                        item.get("alert", False),
                    )
                )

        details = proof_stats.get("details", {})
        for proof_type in ["header_chain", "commit_chain", "state_chain"]:
            item = details.get(proof_type, {})
            if item.get("available"):
                print(
                    "  {}: state={} block=[{}, {}) proving_time={} total_time_to_proof={} delay={}s".format(
                        proof_type,
                        item.get("state", ""),
                        item.get("block_start", 0),
                        item.get("block_end", 0),
                        item.get("proving_time", 0.0),
                        item.get("total_time_to_proof", 0.0),
                        item.get("updated_delay_secs", 0.0),
                    )
                )
            else:
                print(f"  {proof_type}: unavailable ({item.get('error', 'unknown')})")

    print_checks("Core endpoint checks", snapshot["endpoint_checks"], show_all_checks)
    print_checks("Optional endpoint checks", snapshot.get("optional_checks", []), show_all_checks)

    hard_issues = snapshot.get("hard_issues", [])
    if hard_issues:
        print("\nHard issues:")
        for issue in hard_issues:
            print(f"  - {issue}")

    soft_issues = snapshot.get("soft_issues", [])
    if soft_issues:
        print("\nSoft issues:")
        for issue in soft_issues:
            print(f"  - {issue}")


def should_fail(verdict: str, fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = "UNHEALTHY" if fail_on == "unhealthy" else "DEGRADED"
    return SEVERITY[verdict] >= SEVERITY[threshold]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Monitor goat-node RPC health and status distributions")
    parser.add_argument("--base-url", default="http://127.0.0.1:8011", help="RPC base url")
    parser.add_argument("--interval", type=int, default=30, help="poll interval seconds")
    parser.add_argument("--timeout", type=int, default=8, help="single request timeout seconds")
    parser.add_argument("--page-size", type=int, default=100, help="pagination page size (1-100)")
    parser.add_argument("--once", action="store_true", help="run one snapshot and exit")
    parser.add_argument("--json", action="store_true", help="output JSON")
    parser.add_argument(
        "--show-all-checks",
        action="store_true",
        help="show every endpoint check line in human output",
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "degraded", "unhealthy"],
        default="unhealthy",
        help="when to return non-zero exit code in --once mode",
    )
    parser.add_argument(
        "--header-chain-height-url",
        default=DEFAULT_HEADER_CHAIN_HEIGHT_URL,
        help="header chain RPC base URL for tip height",
    )
    parser.add_argument(
        "--state-chain-rpc-url",
        default=DEFAULT_STATE_CHAIN_RPC_URL,
        help="state chain JSON-RPC URL for eth_blockNumber",
    )
    parser.add_argument(
        "--header-chain-lag-alert-blocks",
        type=int,
        default=DEFAULT_HEADER_CHAIN_LAG_ALERT_BLOCKS,
        help="alert threshold for header-chain lag blocks",
    )
    parser.add_argument(
        "--state-chain-lag-alert-blocks",
        type=int,
        default=DEFAULT_STATE_CHAIN_LAG_ALERT_BLOCKS,
        help="alert threshold for state-chain lag blocks",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    lag_config = ProofLagConfig(
        header_chain_height_url=args.header_chain_height_url,
        state_chain_rpc_url=args.state_chain_rpc_url,
        header_chain_lag_alert_blocks=max(1, args.header_chain_lag_alert_blocks),
        state_chain_lag_alert_blocks=max(1, args.state_chain_lag_alert_blocks),
    )

    def run_snapshot() -> int:
        try:
            snapshot = summarize_once(args.base_url, args.timeout, args.page_size, lag_config)
        except Exception as err:  # pylint: disable=broad-except
            print(f"fatal monitor error: {err}", file=sys.stderr)
            return 2

        if args.json:
            print(json.dumps(snapshot, ensure_ascii=True, separators=(",", ":")))
        else:
            print_human(snapshot, args.show_all_checks)

        if args.once and should_fail(snapshot["verdict"], args.fail_on):
            return 1
        return 0

    if args.once:
        return run_snapshot()

    while True:
        code = run_snapshot()
        if code != 0:
            print(f"monitor warning: snapshot exit code={code}", file=sys.stderr)
        print("")
        time.sleep(max(1, args.interval))


if __name__ == "__main__":
    sys.exit(main())
