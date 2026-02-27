"""Tests for trusted_mcp.drift.hash_store.HashStore."""
from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from trusted_mcp.drift.hash_store import HashStore


class TestHashStoreInitialisation:
    def test_default_path_is_home_trusted_mcp(self, tmp_path: Path) -> None:
        store = HashStore(store_path=tmp_path / "hashes.json")
        assert store._store_path == tmp_path / "hashes.json"

    def test_empty_store_has_no_approved_tools(self, tmp_path: Path) -> None:
        store = HashStore(store_path=tmp_path / "hashes.json")
        assert store.list_approved() == []

    def test_nonexistent_file_loads_as_empty(self, tmp_path: Path) -> None:
        store = HashStore(store_path=tmp_path / "does_not_exist.json")
        assert store.load("anything") is None

    def test_malformed_json_loads_as_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("NOT VALID JSON", encoding="utf-8")
        store = HashStore(store_path=path)
        assert store.list_approved() == []

    def test_non_dict_json_loads_as_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        store = HashStore(store_path=path)
        assert store.list_approved() == []


class TestHashStoreSave:
    def test_save_creates_file(self, tmp_path: Path) -> None:
        store = HashStore(store_path=tmp_path / "hashes.json")
        store.save("srv:tool", "abc123")
        assert (tmp_path / "hashes.json").exists()

    def test_save_creates_parent_directory(self, tmp_path: Path) -> None:
        nested_path = tmp_path / "subdir" / "hashes.json"
        store = HashStore(store_path=nested_path)
        store.save("srv:tool", "abc123")
        assert nested_path.exists()

    def test_save_and_load_roundtrip(self, tmp_path: Path) -> None:
        store = HashStore(store_path=tmp_path / "hashes.json")
        store.save("my_server:my_tool", "deadbeef" * 8)
        assert store.load("my_server:my_tool") == "deadbeef" * 8

    def test_save_overwrites_existing_hash(self, tmp_path: Path) -> None:
        store = HashStore(store_path=tmp_path / "hashes.json")
        store.save("srv:tool", "first_hash")
        store.save("srv:tool", "second_hash")
        assert store.load("srv:tool") == "second_hash"

    def test_multiple_tools_persist_independently(self, tmp_path: Path) -> None:
        store = HashStore(store_path=tmp_path / "hashes.json")
        store.save("srv:tool_a", "hash_a")
        store.save("srv:tool_b", "hash_b")
        assert store.load("srv:tool_a") == "hash_a"
        assert store.load("srv:tool_b") == "hash_b"

    def test_save_persists_to_disk(self, tmp_path: Path) -> None:
        path = tmp_path / "hashes.json"
        store = HashStore(store_path=path)
        store.save("srv:tool", "myhash")

        # Load from a new store instance to verify disk persistence
        store2 = HashStore(store_path=path)
        assert store2.load("srv:tool") == "myhash"


class TestHashStoreLoad:
    def test_load_nonexistent_tool_returns_none(self, tmp_path: Path) -> None:
        store = HashStore(store_path=tmp_path / "hashes.json")
        assert store.load("nonexistent:tool") is None

    def test_load_returns_correct_hash(self, tmp_path: Path) -> None:
        store = HashStore(store_path=tmp_path / "hashes.json")
        expected = "a" * 64
        store.save("srv:tool", expected)
        assert store.load("srv:tool") == expected


class TestHashStoreDelete:
    def test_delete_existing_tool_returns_true(self, tmp_path: Path) -> None:
        store = HashStore(store_path=tmp_path / "hashes.json")
        store.save("srv:tool", "myhash")
        assert store.delete("srv:tool") is True

    def test_delete_removes_tool_from_store(self, tmp_path: Path) -> None:
        store = HashStore(store_path=tmp_path / "hashes.json")
        store.save("srv:tool", "myhash")
        store.delete("srv:tool")
        assert store.load("srv:tool") is None

    def test_delete_nonexistent_tool_returns_false(self, tmp_path: Path) -> None:
        store = HashStore(store_path=tmp_path / "hashes.json")
        assert store.delete("never:saved") is False

    def test_delete_persists_to_disk(self, tmp_path: Path) -> None:
        path = tmp_path / "hashes.json"
        store = HashStore(store_path=path)
        store.save("srv:tool", "myhash")
        store.delete("srv:tool")

        store2 = HashStore(store_path=path)
        assert store2.load("srv:tool") is None


class TestHashStoreListApproved:
    def test_list_approved_returns_sorted_keys(self, tmp_path: Path) -> None:
        store = HashStore(store_path=tmp_path / "hashes.json")
        store.save("b_server:tool", "hash1")
        store.save("a_server:tool", "hash2")
        assert store.list_approved() == ["a_server:tool", "b_server:tool"]

    def test_list_approved_empty_when_none_saved(self, tmp_path: Path) -> None:
        store = HashStore(store_path=tmp_path / "hashes.json")
        assert store.list_approved() == []


class TestHashStoreClear:
    def test_clear_removes_all_entries(self, tmp_path: Path) -> None:
        store = HashStore(store_path=tmp_path / "hashes.json")
        store.save("srv:tool_a", "hash_a")
        store.save("srv:tool_b", "hash_b")
        store.clear()
        assert store.list_approved() == []

    def test_clear_persists_to_disk(self, tmp_path: Path) -> None:
        path = tmp_path / "hashes.json"
        store = HashStore(store_path=path)
        store.save("srv:tool", "myhash")
        store.clear()

        store2 = HashStore(store_path=path)
        assert store2.list_approved() == []


class TestHashStoreThreadSafety:
    def test_concurrent_saves_do_not_corrupt_store(self, tmp_path: Path) -> None:
        store = HashStore(store_path=tmp_path / "hashes.json")
        errors: list[Exception] = []

        def save_hash(index: int) -> None:
            try:
                store.save(f"srv:tool_{index}", f"hash_{index}")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=save_hash, args=(i,)) for i in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert not errors
        approved = store.list_approved()
        assert len(approved) == 20
