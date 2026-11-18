"""Native intake routing and partial process outcomes are offline and recoverable."""

from __future__ import annotations

import pytest

from hyperresearch.web.base import WebResult, get_provider
from hyperresearch.web.opencli_provider import NativeSourceError, XDispatchProvider


class ArticleProvider:
    name = "article"

    def fetch(self, url):
        return WebResult(url=url, title="article", content="ordinary article " * 30)

    def search(self, query, max_results=5):
        return []


def test_native_refusal_never_calls_generic_reader(tmp_vault, monkeypatch):
    generic_calls = []

    def generic():
        generic_calls.append(True)
        return ArticleProvider()

    routed = XDispatchProvider(tmp_vault, "article", generic)
    with pytest.raises(NativeSourceError, match="disabled|configured|plan"):
        routed.fetch("https://x.com/user/status/123")
    assert generic_calls == []


def test_ordinary_article_keeps_synchronous_provider_behavior(tmp_vault):
    routed = XDispatchProvider(tmp_vault, "article", ArticleProvider)
    result = routed.fetch("https://example.org/article")
    assert isinstance(result, WebResult)
    assert result.title == "article"
    assert result.looks_like_junk() is None


def test_valid_native_media_only_post_bypasses_article_length_and_login_heuristics():
    from hyperresearch.web.base import native_capture_is_valid

    result = WebResult(url="https://x.com/u/status/123", title="X post 123", content="",
                       metadata={"x_capture": {"post_id": "123", "url": "https://x.com/u/status/123", "text": "", "schema_version": 1}})
    assert not native_capture_is_valid(result), "a marker without governed schema is not proof"
    assert result.looks_like_junk() is not None


def test_policy_refusal_is_not_duplicate_url(tmp_vault, monkeypatch):
    from hyperresearch.core.fetcher import DuplicateURL, fetch_and_save

    monkeypatch.setattr("hyperresearch.web.base.get_provider", lambda *args, **kwargs: XDispatchProvider(tmp_vault, "builtin", ArticleProvider))
    with pytest.raises(NativeSourceError) as refused:
        fetch_and_save(tmp_vault, "https://x.com/u/status/123")
    assert not isinstance(refused.value, DuplicateURL)


def test_capabilities_probe_is_nonstarting_and_distinct_from_content(tmp_vault, monkeypatch):
    from hyperresearch.web.opencli_provider import OpenCLIProvider

    calls = []
    class Completed:
        returncode = 1
        stdout = b"{}"
    monkeypatch.setattr("hyperresearch.web.opencli_provider.subprocess.run", lambda argv, **kwargs: calls.append(argv) or Completed())
    provider = OpenCLIProvider(tmp_vault)
    with pytest.raises(NativeSourceError):
        provider.capabilities()
    assert calls == [["opencli", "research-capabilities", "--json"]]


def test_redirected_native_result_cannot_be_saved_as_reader_provenance(tmp_vault):
    class RedirectingArticle(ArticleProvider):
        def fetch(self, url):
            return WebResult(url="https://x.com/u/status/123", title="reader snippet", content="reader snippet " * 40)

    routed = XDispatchProvider(tmp_vault, "article", RedirectingArticle)
    with pytest.raises(NativeSourceError):
        routed.fetch("https://example.org/redirect")


@pytest.mark.parametrize("text", ["", "Hi", "Log in is the quoted post text"])
def test_governed_public_posts_ignore_article_length_heuristics(tmp_vault, text):
    import json
    from hyperresearch.models.x_evidence import canonical_bytes
    from hyperresearch.web.opencli_provider import OpenCLIProvider
    from tests.test_core.test_x_operations import operation_fixture, write_json

    store = OpenCLIProvider(tmp_vault).store
    operation, capture_ref = operation_fixture(store)
    capture_path = operation / capture_ref["path"]
    capture = json.loads(capture_path.read_bytes())
    capture["text"] = text
    revised = write_json(capture_path, capture)
    revised["path"] = capture_ref["path"]
    page_path = operation / "pages/000000/receipt.json"
    page = json.loads(page_path.read_bytes())
    page["page"]["capture_refs"] = [revised]
    page["artifacts"] = [page["page"]["raw_ref"], revised]
    page_path.write_bytes(canonical_bytes(page))
    imported = store.import_operation(operation)
    provider = OpenCLIProvider(tmp_vault)
    result = provider._results(imported)[0]
    assert result.content == text
    assert result.looks_like_junk() is None
    assert not result.looks_like_login_wall(result.url)


def test_credentialed_native_host_never_enters_article_reader(tmp_vault):
    calls = []
    routed = XDispatchProvider(tmp_vault, "article", lambda: calls.append("reader") or ArticleProvider())
    with pytest.raises(NativeSourceError):
        routed.fetch("https://user:password@x.com/u/status/123")
    assert calls == []


def test_stop_signals_only_owned_native_child_once_and_retains_partial_final(tmp_vault, monkeypatch):
    import signal
    import subprocess
    import threading
    from dataclasses import replace
    from datetime import datetime
    import hyperresearch.web.opencli_provider as native
    from tests.test_core.test_x_operations import TIMESTAMP, operation_fixture, scope

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.fromisoformat(TIMESTAMP.replace("Z", "+00:00"))

    monkeypatch.setattr(native, "datetime", Clock)
    tmp_vault.config.x = replace(tmp_vault.config.x, enabled=True)
    provider = native.OpenCLIProvider(tmp_vault, source_authorizer=lambda request: request)
    monkeypatch.setattr(provider, "capabilities", lambda: {})
    cancelled = threading.Event()
    signals, pages = [], []

    class NativeChild:
        pid = 12345
        waits = 0

        def __init__(self, argv, **kwargs):
            self.argv = argv
            operation_fixture(provider.store)

        def send_signal(self, value):
            signals.append(value)
            operation_fixture(provider.store, final=True)

        def poll(self):
            return None if self.waits < 2 else 1

        def wait(self, timeout):
            self.waits += 1
            if self.waits == 1:
                cancelled.set()
                raise subprocess.TimeoutExpired(self.argv, timeout)
            return 1

    monkeypatch.setattr(native.subprocess, "Popen", NativeChild)
    outcome = provider.execute_scope(scope(), on_page=pages.append, cancel_event=cancelled)
    assert signals == [signal.SIGINT]
    assert pages[0]["final_receipt_ref"] is None
    assert outcome["returncode"] == 1
    assert outcome["final_receipt_ref"] is not None
    assert len(outcome["capture_refs"]) == 1
    assert provider.store.get_record(outcome["final_receipt_ref"])["coverage"]["state"] == "partial"


def test_generic_provider_without_vault_cannot_acquire_native_posts(monkeypatch):
    provider = get_provider("builtin")
    def reader_is_forbidden(url):
        raise AssertionError("Native URL entered an article acquisition")
    monkeypatch.setattr(provider, "_get", reader_is_forbidden)
    with pytest.raises(NativeSourceError):
        provider.fetch("https://x.com/u/status/123")


def test_schema_refusal_has_explicit_native_outcome(tmp_vault):
    from hyperresearch.web.opencli_provider import OpenCLIProvider

    with pytest.raises(NativeSourceError) as caught:
        OpenCLIProvider(tmp_vault).execute_scope({"operation_id": "invalid"})
    assert caught.value.code == "X_SOURCE_SCHEMA"
    assert caught.value.code != "DUPLICATE_URL"


def test_missing_native_command_is_capability_refusal(tmp_vault, monkeypatch):
    from hyperresearch.web.opencli_provider import OpenCLIProvider
    import hyperresearch.web.opencli_provider as native

    def missing(*args, **kwargs):
        raise FileNotFoundError("missing offline binary")

    monkeypatch.setattr(native.subprocess, "run", missing)
    with pytest.raises(NativeSourceError) as caught:
        OpenCLIProvider(tmp_vault).capabilities()
    assert caught.value.code == "X_SOURCE_CAPABILITIES"
