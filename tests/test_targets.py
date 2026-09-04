from src.store.targets import TargetsStore


def test_add_and_lookup(tmp_path):
    store = TargetsStore(tmp_path / "db.sqlite")
    store.add(name="acme", repo="https://github.com/a/acme.git", ref="main",
              category="attested", notes="n", attested_by="op")
    assert store.get_by_repo("https://github.com/a/acme.git")["name"] == "acme"
    assert store.get_by_name("acme")["repo"] == "https://github.com/a/acme.git"
    assert store.names() == {"acme"}
    assert len(store.list()) == 1
    store.close()


def test_upsert_is_idempotent(tmp_path):
    store = TargetsStore(tmp_path / "db.sqlite")
    for _ in range(3):
        store.add(name="x", repo="https://github.com/a/x.git", ref="main",
                  category="attested", notes="n", attested_by="op")
    assert len(store.list()) == 1
    store.close()
