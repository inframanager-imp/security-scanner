"""Unit tests for the pure, dependency-free logic in backend/scanners.py.

These target the specific bugs found and fixed during live pipeline testing
on 2026-08-18 (GIT-scope misfires against github.com, and the patch_node
matching chain that went from a 0% to ~80% real-world patch-apply rate).
Deliberately scoped to functions with no DB/network dependency — scanners.py
is safe to import without a live Postgres connection (get_db_connection()
is called lazily, never at import time), so these run as plain unit tests.
"""
from backend.scanners import is_git_scope_target, _find_unsafe_span, _has_ai_fix


class TestIsGitScopeTarget:
    def test_target_type_git(self):
        assert is_git_scope_target({"target_type": "git", "url": "https://example.com/app"}) is True

    def test_github_url(self):
        assert is_git_scope_target({"url": "https://github.com/org/repo"}) is True

    def test_github_url_with_git_suffix(self):
        assert is_git_scope_target({"url": "https://github.com/org/repo.git"}) is True

    def test_gitlab_url(self):
        assert is_git_scope_target({"url": "https://gitlab.com/org/repo"}) is True

    def test_dot_git_suffix_non_github_host(self):
        assert is_git_scope_target({"url": "https://git.internal.example.com/org/repo.git"}) is True

    def test_live_url_target(self):
        assert is_git_scope_target({"url": "https://app.example.com", "target_type": "web"}) is False

    def test_live_ip_target(self):
        assert is_git_scope_target({"url": "http://10.0.0.5:8080"}) is False

    def test_missing_url_key(self):
        # Must not raise on a malformed/partial target dict.
        assert is_git_scope_target({}) is False


class TestHasAiFix:
    def test_ready_fix(self):
        finding = {"remediation": {"unsafe": "x = 1", "safe": "x = 2", "explanation": "because"}}
        assert _has_ai_fix(finding) is True

    def test_missing_remediation(self):
        assert _has_ai_fix({}) is False

    def test_empty_unsafe_or_safe(self):
        assert _has_ai_fix({"remediation": {"unsafe": "", "safe": "x = 2", "explanation": "y"}}) is False
        assert _has_ai_fix({"remediation": {"unsafe": "x = 1", "safe": "", "explanation": "y"}}) is False

    def test_untriaged_placeholder_explanation(self):
        finding = {"remediation": {
            "unsafe": "x = 1", "safe": "x = 2",
            "explanation": "Review the scanner finding and apply the appropriate remediation.",
        }}
        assert _has_ai_fix(finding) is False


class TestFindUnsafeSpan:
    def test_exact_match(self):
        content = "def foo():\n    return 1\n"
        assert _find_unsafe_span(content, "return 1") == "return 1"

    def test_no_match_at_all(self):
        assert _find_unsafe_span("totally unrelated content", "os.system('rm -rf /')") is None

    def test_empty_unsafe(self):
        assert _find_unsafe_span("anything", "") is None

    def test_whitespace_reindented(self):
        # Real bug: LLM output used spaces, file uses a tab.
        content = "def foo():\n\treturn 1\n"
        result = _find_unsafe_span(content, "    return 1")
        assert result is not None
        assert "return 1" in result

    def test_whitespace_crlf_vs_lf(self):
        content = "def foo():\r\n    os.system(cmd)\r\n"
        unsafe = "def foo():\n    os.system(cmd)\n"
        result = _find_unsafe_span(content, unsafe)
        assert result is not None

    def test_whitespace_trailing_spaces(self):
        content = "def foo():   \n    return 1   \n"
        unsafe = "def foo():\n    return 1\n"
        result = _find_unsafe_span(content, unsafe)
        assert result is not None

    def test_fuzzy_match_paraphrased_content(self):
        # Real bug: LLM condensed/reworded the quote instead of copying it.
        big = "\n".join(f"line_{i} = {i}" for i in range(500))
        big += "\ndef vulnerable():\n    os.system('ping ' + user_input)\n"
        big += "\n".join(f"line_{i} = {i}" for i in range(500))
        unsafe = "os.system('ping' + userinput)"  # slightly reworded, same meaning
        result = _find_unsafe_span(big, unsafe)
        assert result is not None
        assert "os.system" in result

    def test_fuzzy_match_rejects_low_similarity(self):
        content = "def totally_unrelated_function():\n    print('hello world')\n"
        unsafe = "os.system('rm -rf /' + shell_injection_payload_here)"
        assert _find_unsafe_span(content, unsafe) is None

    def test_returns_real_file_substring_not_llm_text(self):
        content = "def foo():\n\treturn 1\n"
        result = _find_unsafe_span(content, "    return 1")
        assert result in content
