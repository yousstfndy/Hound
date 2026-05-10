from pathlib import Path

from hound.scope import ScopeEngine


def test_scope_matching_and_exclusions(tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text(
        """
[in_scope]
*.target.com
target.com
https://target.com/app
93.184.216.0/24

[out_of_scope]
admin.target.com
target.com/logout
""",
        encoding="utf-8",
    )
    engine = ScopeEngine(scope_file, output_root=tmp_path / "out")

    assert engine.is_in_scope("api.target.com") == (True, "matched *.target.com")
    assert engine.is_in_scope("target.com") == (True, "matched target.com")
    assert engine.is_in_scope("admin.target.com") == (False, "excluded: admin.target.com")
    assert engine.is_in_scope("https://target.com/logout/confirm") == (False, "excluded: target.com/logout")
    assert engine.is_in_scope("other.example") == (False, "not in scope - ambiguous")


def test_protocol_scoped_url() -> None:
    engine = ScopeEngine.__new__(ScopeEngine)
    entry = ScopeEngine._entry(engine, "https://target.com")
    assert entry.scheme == "https"
    assert entry.host == "target.com"
