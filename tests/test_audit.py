from pathlib import Path

from src.store.audit import AuditLog


def test_append_and_verify(tmp_path: Path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("run.start", {"a": 1})
    log.append("recon.done", {"files": 3})
    ok, broken = log.verify()
    assert ok and broken is None


def test_tamper_detected(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("e1", {"x": 1})
    log.append("e2", {"x": 2})
    lines = path.read_text().splitlines()
    # Corrupt the first entry's payload without fixing the hash chain.
    lines[0] = lines[0].replace('"x": 1', '"x": 999')
    path.write_text("\n".join(lines) + "\n")
    ok, broken = log.verify()
    assert not ok
    assert broken == 1


def test_chain_survives_line_larger_than_4kb(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("small", {"x": 1})
    log.append("huge", {"blob": "z" * 20000})  # a single line > old 4096 window
    # New entry must chain off the huge line's hash, not GENESIS.
    log.append("after", {"x": 2})
    ok, broken = log.verify()
    assert ok and broken is None
