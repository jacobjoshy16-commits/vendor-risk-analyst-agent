"""Bounded worker pool with per-item failure isolation.

At ~20 vendors a sequential poll wastes the interval and a single 401
must not abort the other 19. Workers are capped so we do not stampede
rate-limited admin APIs.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, TypeVar

from .config import DEFAULT_WORKERS, RunConfig

T = TypeVar("T")
R = TypeVar("R")


def worker_count(cfg: RunConfig | None = None) -> int:
    raw = os.environ.get("VRA_WORKERS")
    if raw:
        try:
            n = int(raw)
        except ValueError:
            n = DEFAULT_WORKERS
    elif cfg is not None:
        n = int(getattr(cfg, "workers", DEFAULT_WORKERS) or DEFAULT_WORKERS)
    else:
        n = DEFAULT_WORKERS
    return max(1, min(n, 8))


def map_isolated(
    fn: Callable[[T], R],
    items: Iterable[T],
    *,
    workers: int = 4,
    on_error: Callable[[T, BaseException], R] | None = None,
) -> list[R]:
    """Run ``fn`` on each item. Exceptions become ``on_error`` results.

    Order of ``items`` is preserved. ``workers=1`` is sequential (tests,
    tiny portfolios).
    """
    rows = list(items)
    if not rows:
        return []
    n = max(1, min(int(workers), 8, len(rows)))

    def _run(item: T) -> R:
        try:
            return fn(item)
        except BaseException as exc:
            if on_error is None:
                raise
            return on_error(item, exc)

    if n == 1:
        return [_run(item) for item in rows]

    out: list[R | None] = [None] * len(rows)
    with ThreadPoolExecutor(max_workers=n, thread_name_prefix="vra-poll") as pool:
        futures = {pool.submit(_run, item): idx for idx, item in enumerate(rows)}
        for fut in as_completed(futures):
            out[futures[fut]] = fut.result()
    return list(out)  # type: ignore[return-value]
