from __future__ import annotations

import argparse
import asyncio
import statistics
import time

import httpx


async def one(
    client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore
) -> tuple[float, bool]:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/docs/report.txt"}},
    }
    headers = {
        "MCP-Protocol-Version": "2026-07-28",
        "X-Agent-ID": "research-agent",
    }
    async with semaphore:
        started = time.perf_counter()
        try:
            response = await client.post(url, json=payload, headers=headers)
            ok = response.status_code == 200 and "result" in response.json()
        except Exception:
            ok = False
        return (time.perf_counter() - started) * 1000, ok


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(len(ordered) * quantile))
    return ordered[index]


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8080/mcp/filesystem")
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--concurrency", type=int, default=20)
    args = parser.parse_args()
    semaphore = asyncio.Semaphore(args.concurrency)
    started = time.perf_counter()
    async with httpx.AsyncClient(timeout=30) as client:
        results = await asyncio.gather(
            *(one(client, args.url, semaphore) for _ in range(args.requests))
        )
    elapsed = time.perf_counter() - started
    latencies = [latency for latency, _ in results]
    passed = sum(ok for _, ok in results)
    print(f"requests={args.requests} concurrency={args.concurrency} elapsed_s={elapsed:.3f}")
    print(f"success={passed} failure={args.requests - passed} rps={args.requests / elapsed:.2f}")
    print(
        "latency_ms "
        f"mean={statistics.mean(latencies):.2f} "
        f"p50={percentile(latencies, 0.50):.2f} "
        f"p95={percentile(latencies, 0.95):.2f} "
        f"p99={percentile(latencies, 0.99):.2f}"
    )


if __name__ == "__main__":
    asyncio.run(main())
