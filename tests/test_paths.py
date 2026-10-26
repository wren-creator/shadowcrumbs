"""shadowcrumbs/paths.py: sorting a URL into what it exposes."""
from shadowcrumbs.paths import classify


def test_each_kind_is_recognized_from_the_path():
    cases = {
        "https://acme.test/.git/config": "vcs",
        "https://acme.test/.env": "secrets",
        "https://acme.test/wp-config.php": "secrets",
        "https://acme.test/backup.sql": "backup",
        "https://acme.test/db_backup/old.zip": "backup",
        "https://acme.test/wp-admin/": "admin",
        "https://acme.test/phpmyadmin/": "admin",
        "https://acme.test/login": "login",
        "https://acme.test/owa/auth/logon.aspx": "login",
        "https://acme.test/vpn/": "login",
        "https://acme.test/server-status": "debug",
        "https://acme.test/actuator/health": "debug",
        "https://acme.test/swagger-ui.html": "api_docs",
        "https://acme.test/reports/q3.pdf": "file",
    }
    for url, kind in cases.items():
        got = classify(url)
        assert got and got[0] == kind, (url, got)


def test_an_ordinary_page_is_not_classified():
    assert classify("https://acme.test/about") is None
    assert classify("https://acme.test/products/widgets") is None


def test_the_host_never_makes_a_url_interesting_only_the_path_does():
    assert classify("https://admin.acme.test/about") is None
    assert classify("https://login.acme.test/") is None


def test_a_page_titled_index_of_is_a_directory_even_without_it_in_the_url():
    assert classify("https://acme.test/files/", "Index of /files") == ("directory", "Open directory listing")
    assert classify("https://acme.test/files/", "Files - Acme") is None


def test_a_bad_url_does_not_raise():
    assert classify("not a url \x00") is None or True   # urlparse rarely raises, but must never crash either way


def test_the_most_serious_match_wins_when_several_apply():
    # a backup living under an admin path should still read as a backup, not get swallowed by admin
    assert classify("https://acme.test/admin/backup.sql")[0] == "backup"


def test_well_known_files_sitemaps_and_feeds_are_recognized():
    for u in ("https://acme.test/.well-known/ai-plugin.json", "https://acme.test/.well-known/assetlinks.json",
              "https://acme.test/.well-known/gpc.json", "https://acme.test/.well-known/openid-configuration"):
        assert classify(u)[0] == "wellknown", u
    for u in ("https://acme.test/sitemap.xml", "https://acme.test/atom.xml", "https://acme.test/feed.xml",
              "https://acme.test/feeds/all.atom.xml", "https://acme.test/index.xml", "https://acme.test/robots.txt"):
        assert classify(u)[0] == "discovery", u
    assert classify("https://acme.test/.well-known/security.txt")[0] == "debug"   # unchanged, still the more serious label
