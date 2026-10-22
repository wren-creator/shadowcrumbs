"""Guards tools/searxng/settings.yml. Read as plain text on purpose, so the tests need no YAML library.

Why this exists: with keep_only, an engine that ships switched off or flips between versions stays off unless it is
named under engines with disabled: false. Four engines (bing, mojeek, qwant, yahoo) were silently off that way.
"""
import re
from pathlib import Path

SETTINGS = Path(__file__).resolve().parent.parent / "tools" / "searxng" / "settings.yml"


def _kept():
    text = SETTINGS.read_text()
    block = re.search(r"keep_only:\n((?:\s+- .+\n)+)", text).group(1)
    return [line.strip()[2:] for line in block.splitlines()]


def _switched_on():
    text = SETTINGS.read_text()
    section = text[text.index("\nengines:\n"):]
    return re.findall(r"- name: (.+)\n\s+disabled: false", section)


def test_every_kept_engine_is_switched_on_by_name():
    assert sorted(_kept()) == sorted(_switched_on())


def test_the_json_format_shadowcrumbs_reads_stays_on():
    assert re.search(r"formats:\n(?:\s+- .+\n)*?\s+- json", SETTINGS.read_text())


def test_the_search_engines_the_owner_asked_for_are_there():
    assert {"google", "yandex", "bing", "brave", "startpage", "duckduckgo", "mojeek", "qwant", "yahoo",
            "gitlab", "bitbucket", "codeberg", "national vulnerability database"} == set(_kept())
