
import pytest
import tools


def test_read_file_rejects_file_larger_than_limit(tmp_path, monkeypatch):
    """A file exceeding the configured read limit must be rejected."""
    monkeypatch.setattr(tools, "WORKSPACE", tmp_path)

    oversized_file = tmp_path / "large.txt"
    oversized_file.write_bytes(b"A" * (tools.MAX_READ_BYTES + 1))

    with pytest.raises(ValueError):
        tools.read_file("large.txt")


def test_read_file_rejects_opened_file_outside_workspace(
    tmp_path, monkeypatch
):
    """The final path associated with the open handle must remain in the workspace."""
    monkeypatch.setattr(tools, "WORKSPACE", tmp_path)

    allowed_file = tmp_path / "notes.txt"
    allowed_file.write_text("Test content", encoding="utf-8")

    outside_file = tmp_path.parent / "outside.txt"

    monkeypatch.setattr(
        tools,
        "_get_open_file_final_path",
        lambda file_obj: str(outside_file.resolve()),
    )

    with pytest.raises(PermissionError):
        tools.read_file("notes.txt")


def test_read_file_rejects_sensitive_final_path(
    tmp_path, monkeypatch
):
    """The final path must not identify a sensitive file."""
    monkeypatch.setattr(tools, "WORKSPACE", tmp_path)

    allowed_file = tmp_path / "notes.txt"
    allowed_file.write_text("Test content", encoding="utf-8")

    sensitive_path = tmp_path / ".env"

    monkeypatch.setattr(
        tools,
        "_get_open_file_final_path",
        lambda file_obj: str(sensitive_path.resolve()),
    )

    with pytest.raises(PermissionError):
        tools.read_file("notes.txt")


def test_read_file_accepts_regular_file_inside_workspace(
    tmp_path, monkeypatch
):
    """A normal file inside the workspace remains readable."""
    monkeypatch.setattr(tools, "WORKSPACE", tmp_path)

    test_file = tmp_path / "notes.txt"
    test_file.write_text("AEGIS security test", encoding="utf-8")

    result = tools.read_file("notes.txt")

    assert result == "AEGIS security test"


def test_read_file_rejects_symlink_to_outside_workspace(
    tmp_path, monkeypatch
):
    """A symlink to a file outside the workspace must be rejected."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("outside secret", encoding="utf-8")

    link = workspace / "linked.txt"

    try:
        link.symlink_to(outside_file)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Symbolic links unavailable: {exc}")

    monkeypatch.setattr(tools, "WORKSPACE", workspace)

    with pytest.raises(PermissionError):
        tools.read_file("linked.txt")
