"""The .env loader: keys without shell history, and no loading a file other users can read."""
import os
import stat

import pytest

from shadowcrumbs import config


@pytest.fixture
def envfile(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    monkeypatch.setenv("SHADOWCRUMBS_ENV_FILE", str(path))
    for k in ("BRAVE_API_KEY", "GITHUB_TOKEN", "OTHER_THING", "HIBP_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    return path


def write(path, text, mode=0o600):
    path.write_text(text)
    path.chmod(mode)


def test_loads_names_and_never_returns_a_value(envfile):
    write(envfile, '# keys\nBRAVE_API_KEY=abc123\nexport GITHUB_TOKEN="ghp_x y"\nbad name=1\nEMPTY=\nlower=1\n')
    loaded, problem = config.load_env_file()
    assert loaded == ["BRAVE_API_KEY", "GITHUB_TOKEN"] and problem is None
    assert os.environ["BRAVE_API_KEY"] == "abc123" and os.environ["GITHUB_TOKEN"] == "ghp_x y"
    assert "abc123" not in repr((loaded, problem))


def test_an_existing_environment_variable_wins(envfile, monkeypatch):
    monkeypatch.setenv("BRAVE_API_KEY", "from-shell")
    write(envfile, "BRAVE_API_KEY=from-file\nGITHUB_TOKEN=t\n")
    assert config.load_env_file()[0] == ["GITHUB_TOKEN"]
    assert os.environ["BRAVE_API_KEY"] == "from-shell"


@pytest.mark.skipif(os.name != "posix", reason="permission bits")
@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604])
def test_a_file_other_users_can_read_is_not_loaded(envfile, mode):
    write(envfile, "BRAVE_API_KEY=abc123\n", mode)
    loaded, problem = config.load_env_file()
    assert loaded == [] and "chmod 600" in problem and "abc123" not in problem
    assert "BRAVE_API_KEY" not in os.environ
    assert stat.S_IMODE(envfile.stat().st_mode) == mode        # we only complain, we do not change it


def test_no_file_is_not_a_problem(envfile):
    assert config.load_env_file() == ([], None)


def test_the_real_env_file_can_never_be_committed():
    """Keys live in .env. If it ever stops being ignored, or gets tracked, this fails before a commit can carry it."""
    import subprocess
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    git = lambda *a: subprocess.run(["git", "-C", str(root), *a], capture_output=True, text=True)
    if git("rev-parse", "--git-dir").returncode != 0:
        pytest.skip("not a git checkout")
    assert git("check-ignore", "-q", ".env").returncode == 0, ".env must be in .gitignore"
    assert git("check-ignore", "-q", ".env.local").returncode == 0
    assert git("check-ignore", "-q", "env.example").returncode == 1, "the example file has to stay committable"
    tracked = git("ls-files").stdout.split()
    assert not [f for f in tracked if f.rsplit("/", 1)[-1].startswith(".env")], "a .env file is tracked"
