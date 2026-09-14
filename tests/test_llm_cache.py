"""The prompt cache must never serve a stale answer.

Reusing a narrative is only safe if a hit is impossible whenever the next call
would have sent different bytes. So the key is a hash of the exact
backend/model/task/system/prompt, and these tests pin both halves: that
identical prompts hit, and that every input which reaches a prompt misses.
"""

from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import unittest
import unittest.mock
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra import llm  # noqa: E402
from vra.config import RunConfig  # noqa: E402
from vra.llm import PromptCache  # noqa: E402


class _CountingBackend(llm.Backend):
    name = "ollama"

    def __init__(self, payload=None):
        self.calls = 0
        self.payload = payload or {"narrative": "generated once"}

    def generate(self, system, prompt, cfg):
        self.calls += 1
        return json.dumps(self.payload), None


def _ok(_parsed):
    return None


class _CacheTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cache = llm.reset_cache(Path(self.tmp.name) / "llm_cache.json")
        self.addCleanup(llm.reset_cache)
        # Keep the audit log out of the repo's data/ directory.
        self._audit = Path(self.tmp.name) / "audit.jsonl"
        patch = unittest.mock.patch.object(llm, "LLM_AUDIT_LOG", self._audit)
        patch.start()
        self.addCleanup(patch.stop)

    def call(self, backend, *, system="SYS", prompt="PROMPT", task="finding_narrative",
             cfg=None):
        cfg = cfg or RunConfig(offline=False)
        return llm.call_json(
            system=system, prompt=prompt, cfg=cfg,
            schema_check=_ok, task=task, backend=backend,
        )


class TestCacheHitsAndMisses(_CacheTestCase):
    def test_identical_prompt_is_served_from_cache(self):
        backend = _CountingBackend()
        first = self.call(backend)
        second = self.call(backend)

        self.assertEqual(backend.calls, 1, "the model must be asked only once")
        self.assertTrue(first.ok and second.ok)
        self.assertEqual(first.data, second.data)
        self.assertEqual(self.cache.stats["hits"], 1)

    def test_a_hit_returns_a_copy_not_the_stored_dict(self):
        """A caller mutating a result must not poison the cache."""
        backend = _CountingBackend()
        first = self.call(backend)
        first.data["narrative"] = "mutated by the caller"
        second = self.call(backend)
        self.assertEqual(second.data["narrative"], "generated once")

    def test_different_prompt_misses(self):
        backend = _CountingBackend()
        self.call(backend, prompt="PROMPT A")
        self.call(backend, prompt="PROMPT B")
        self.assertEqual(backend.calls, 2)

    def test_different_system_prompt_misses(self):
        backend = _CountingBackend()
        self.call(backend, system="SYS A")
        self.call(backend, system="SYS B")
        self.assertEqual(backend.calls, 2)

    def test_different_task_misses(self):
        backend = _CountingBackend()
        self.call(backend, task="finding_narrative")
        self.call(backend, task="vendor_outreach")
        self.assertEqual(backend.calls, 2)

    def test_different_model_misses(self):
        """Swapping the model must not reuse the previous model's words."""
        backend = _CountingBackend()
        cfg_a = RunConfig(offline=False)
        cfg_a.model = "qwen2.5:7b-instruct"
        cfg_b = RunConfig(offline=False)
        cfg_b.model = "llama3.1:8b"
        self.call(backend, cfg=cfg_a)
        self.call(backend, cfg=cfg_b)
        self.assertEqual(backend.calls, 2)

    def test_different_backend_misses(self):
        one = _CountingBackend()
        other = _CountingBackend()
        other.name = "some-other-backend"
        self.call(one)
        self.call(other)
        self.assertEqual(one.calls, 1)
        self.assertEqual(other.calls, 1)

    def test_cache_can_be_disabled(self):
        backend = _CountingBackend()
        cfg = RunConfig(offline=False)
        cfg.llm_cache = False
        self.call(backend, cfg=cfg)
        self.call(backend, cfg=cfg)
        self.assertEqual(backend.calls, 2)


class TestFailuresAreNotCached(_CacheTestCase):
    def test_a_rejected_response_is_never_stored(self):
        class Bad(llm.Backend):
            name = "ollama"

            def __init__(self):
                self.calls = 0

            def generate(self, system, prompt, cfg):
                self.calls += 1
                return "not json at all", None

        backend = Bad()
        first = llm.call_json(system="S", prompt="P", cfg=RunConfig(offline=False),
                              schema_check=_ok, task="t", backend=backend, max_attempts=1)
        self.assertFalse(first.ok)
        self.assertEqual(self.cache.entries, {}, "a failure must not be cached")

        llm.call_json(system="S", prompt="P", cfg=RunConfig(offline=False),
                      schema_check=_ok, task="t", backend=backend, max_attempts=1)
        self.assertEqual(backend.calls, 2, "the model is asked again after a failure")


class TestCacheFile(_CacheTestCase):
    def test_survives_a_new_process(self):
        backend = _CountingBackend()
        self.call(backend)
        self.cache.save(RunConfig())

        # A fresh cache object over the same file is what the next `--once` sees.
        reloaded = llm.reset_cache(self.cache.path)
        self.addCleanup(llm.reset_cache)
        again = self.call(backend)
        self.assertEqual(backend.calls, 1, "a restart must not re-ask the model")
        self.assertTrue(again.ok)
        self.assertEqual(reloaded.stats["hits"], 1)

    def test_prompt_text_is_never_written_to_disk(self):
        backend = _CountingBackend()
        secret_ish = "VENDOR-CONFIDENTIAL-PROMPT-BODY"
        self.call(backend, prompt=secret_ish)
        self.cache.save(RunConfig())
        blob = self.cache.path.read_text(encoding="utf-8")
        self.assertNotIn(secret_ish, blob, "only the hash is stored, never the prompt")

    def test_dry_run_writes_nothing(self):
        backend = _CountingBackend()
        self.call(backend)
        self.cache.save(RunConfig(dry_run=True))
        self.assertFalse(self.cache.path.exists())

    def test_entries_are_capped_evicting_least_recently_used(self):
        cache = PromptCache(Path(self.tmp.name) / "capped.json", max_entries=3)
        for i in range(6):
            cache.put(f"key-{i}", data={"n": i}, call_id="c", task="t")
            cache.entries[f"key-{i}"]["last_used"] = f"2026-01-0{i + 1}T00:00:00"
        cache.save(RunConfig())
        kept = set(json.loads(cache.path.read_text(encoding="utf-8"))["entries"])
        self.assertEqual(len(kept), 3)
        self.assertEqual(kept, {"key-3", "key-4", "key-5"}, "oldest evicted first")

    def test_a_format_change_invalidates_the_file(self):
        path = Path(self.tmp.name) / "stale.json"
        path.write_text(json.dumps({"version": 0, "entries": {"k": {"data": {}}}}),
                        encoding="utf-8")
        cache = PromptCache(path)
        cache.load()
        self.assertEqual(cache.entries, {})

    def test_a_corrupt_file_is_survivable(self):
        path = Path(self.tmp.name) / "corrupt.json"
        path.write_text("{not json", encoding="utf-8")
        cache = PromptCache(path)
        cache.load()
        self.assertEqual(cache.entries, {})


class TestAuditTrailRecordsHits(_CacheTestCase):
    def test_a_hit_is_logged_and_points_at_the_original_call(self):
        backend = _CountingBackend()
        self.call(backend)
        self.call(backend)

        rows = [json.loads(line) for line in
                self._audit.read_text(encoding="utf-8").splitlines() if line.strip()]
        miss = next(r for r in rows if r.get("cache") == "miss")
        hit = next(r for r in rows if r.get("cache") == "hit")
        self.assertEqual(hit["source_call_id"], miss["call_id"],
                         "a hit must name the call whose text it reused")
        self.assertTrue(hit["parsed_ok"])
        self.assertNotIn("prompt", hit, "a hit has no prompt to log — none was sent")

    def test_a_repeated_hit_is_not_logged_again(self):
        """The monitor re-serves the same hit every cycle; one row says it all."""
        backend = _CountingBackend()
        for _ in range(5):
            self.call(backend)
        rows = [json.loads(line) for line in
                self._audit.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(len([r for r in rows if r.get("cache") == "hit"]), 1)
        self.assertEqual(len([r for r in rows if r.get("cache") == "miss"]), 1)

    def test_dry_run_writes_no_audit_log(self):
        """--dry-run says it persists nothing; the log is on disk like the rest."""
        self.call(_CountingBackend(), cfg=RunConfig(dry_run=True))
        self.assertFalse(self._audit.exists())


class TestAssessReusesAcrossCycles(unittest.TestCase):
    """The whole point: an unchanged finding costs no model calls next cycle."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for name in ("data", "out", "pending_review"):
            shutil.rmtree(REPO / name, ignore_errors=True)
        self.addCleanup(lambda: [shutil.rmtree(REPO / n, ignore_errors=True)
                                 for n in ("data", "out", "pending_review")])
        llm.reset_cache()
        self.addCleanup(llm.reset_cache)

    def _cycle(self):
        from vra.cli import assess

        # dry_run so a test cannot rewrite vendors/*.yaml (assess persists a
        # `state:` block into the human-authored register). The cache still
        # demonstrates reuse: it lives in memory for the process, and the file
        # round-trip is covered by TestCacheFile.test_survives_a_new_process.
        cfg = RunConfig(offline=True, snapshot_version="v2", dry_run=True)
        with redirect_stdout(io.StringIO()):
            return assess(cfg)

    def test_second_cycle_sends_nothing(self):
        first = self._cycle()
        self.assertGreater(first.llm_calls_sent, 0)
        self.assertEqual(first.llm_calls_cached, 0)

        second = self._cycle()
        self.assertEqual(second.llm_calls_sent, 0,
                         "an unchanged portfolio must not re-ask the model")
        self.assertEqual(second.llm_calls_cached, first.llm_calls_sent)

    def test_counters_are_per_run_not_cumulative(self):
        """The monitor runs many cycles in one process."""
        self._cycle()
        second = self._cycle()
        third = self._cycle()
        self.assertEqual(second.llm_calls_cached, third.llm_calls_cached)


if __name__ == "__main__":
    unittest.main()
