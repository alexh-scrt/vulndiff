"""Tests for vulndiff.rules.

Verifies that:
- Every rule in ALL_RULES has a correctly compiled pattern.
- All rule IDs are unique.
- Helper query functions return the expected subsets.
- Key rules match their documented example payloads.
- Key rules do NOT match safe counter-examples.
"""

from __future__ import annotations

import re
from typing import List

import pytest

from vulndiff.models import Category, Rule, Severity
from vulndiff.rules import (
    ALL_RULES,
    get_all_rules,
    get_rule_by_id,
    get_rule_ids,
    get_rules_at_or_above_severity,
    get_rules_by_category,
    get_rules_by_severity,
)


# ---------------------------------------------------------------------------
# Structural / metadata tests
# ---------------------------------------------------------------------------


class TestRuleStructure:
    """Tests verifying the structural integrity of the rule set."""

    def test_all_rules_non_empty(self) -> None:
        """ALL_RULES must contain at least one rule."""
        assert len(ALL_RULES) > 0

    def test_all_rule_ids_unique(self) -> None:
        """Every rule must have a unique rule_id."""
        ids = [r.rule_id for r in ALL_RULES]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs found"

    def test_all_patterns_are_compiled(self) -> None:
        """Every rule's pattern must be a compiled re.Pattern."""
        for rule in ALL_RULES:
            assert isinstance(rule.pattern, re.Pattern), (
                f"{rule.rule_id}: pattern is not a compiled re.Pattern"
            )

    def test_all_rules_have_non_empty_description(self) -> None:
        """Every rule must have a non-empty description."""
        for rule in ALL_RULES:
            assert rule.description.strip(), f"{rule.rule_id}: description is empty"

    def test_all_rules_have_non_empty_recommendation(self) -> None:
        """Every rule must have a non-empty recommendation."""
        for rule in ALL_RULES:
            assert rule.recommendation.strip(), (
                f"{rule.rule_id}: recommendation is empty"
            )

    def test_all_rules_have_valid_severity(self) -> None:
        """Every rule's severity must be a Severity enum member."""
        for rule in ALL_RULES:
            assert isinstance(rule.severity, Severity), (
                f"{rule.rule_id}: invalid severity type {type(rule.severity)}"
            )

    def test_all_rules_have_valid_category(self) -> None:
        """Every rule's category must be a Category enum member."""
        for rule in ALL_RULES:
            assert isinstance(rule.category, Category), (
                f"{rule.rule_id}: invalid category type {type(rule.category)}"
            )

    def test_rule_ids_start_with_vd(self) -> None:
        """Rule IDs should follow the VDxxx naming convention."""
        for rule in ALL_RULES:
            assert rule.rule_id.startswith("VD"), (
                f"{rule.rule_id}: does not start with 'VD'"
            )

    def test_rule_ids_are_numeric_after_prefix(self) -> None:
        """The characters after 'VD' in a rule ID should be numeric."""
        for rule in ALL_RULES:
            suffix = rule.rule_id[2:]
            assert suffix.isdigit(), (
                f"{rule.rule_id}: suffix '{suffix}' is not numeric"
            )

    def test_get_all_rules_returns_list(self) -> None:
        """get_all_rules() should return a list, not a tuple."""
        result = get_all_rules()
        assert isinstance(result, list)

    def test_get_all_rules_length_matches_all_rules(self) -> None:
        """get_all_rules() length should equal len(ALL_RULES)."""
        assert len(get_all_rules()) == len(ALL_RULES)

    def test_get_all_rules_is_independent_copy(self) -> None:
        """Modifying the list returned by get_all_rules() should not affect ALL_RULES."""
        result = get_all_rules()
        original_len = len(ALL_RULES)
        result.clear()
        assert len(ALL_RULES) == original_len

    def test_get_rule_ids_sorted(self) -> None:
        """get_rule_ids() should return IDs in sorted order."""
        ids = get_rule_ids()
        assert ids == sorted(ids)

    def test_get_rule_ids_returns_list_of_strings(self) -> None:
        """get_rule_ids() should return a list of strings."""
        ids = get_rule_ids()
        assert isinstance(ids, list)
        for rid in ids:
            assert isinstance(rid, str)

    def test_get_rule_by_id_found(self) -> None:
        """get_rule_by_id() should return the correct rule."""
        rule = get_rule_by_id("VD001")
        assert rule.rule_id == "VD001"

    def test_get_rule_by_id_not_found(self) -> None:
        """get_rule_by_id() should raise KeyError for unknown IDs."""
        with pytest.raises(KeyError):
            get_rule_by_id("VD99999")

    def test_get_rule_by_id_returns_rule_instance(self) -> None:
        """get_rule_by_id() should return a Rule instance."""
        rule = get_rule_by_id("VD001")
        assert isinstance(rule, Rule)

    def test_all_rules_have_non_empty_name(self) -> None:
        """Every rule must have a non-empty name."""
        for rule in ALL_RULES:
            assert rule.name.strip(), f"{rule.rule_id}: name is empty"

    def test_all_rules_have_non_empty_rule_id(self) -> None:
        """Every rule must have a non-empty rule_id."""
        for rule in ALL_RULES:
            assert rule.rule_id.strip(), "A rule has an empty rule_id"

    def test_get_all_rules_contains_same_rules_as_all_rules(self) -> None:
        """get_all_rules() should return the same rules as ALL_RULES."""
        result = get_all_rules()
        result_ids = {r.rule_id for r in result}
        all_ids = {r.rule_id for r in ALL_RULES}
        assert result_ids == all_ids

    def test_multiple_categories_covered(self) -> None:
        """The rule set should span more than one category."""
        categories = {r.category for r in ALL_RULES}
        assert len(categories) > 1

    def test_multiple_severity_levels_covered(self) -> None:
        """The rule set should include more than one severity level."""
        severities = {r.severity for r in ALL_RULES}
        assert len(severities) > 1


# ---------------------------------------------------------------------------
# Category and severity filter tests
# ---------------------------------------------------------------------------


class TestRuleFilters:
    """Tests for the rule query/filter helper functions."""

    def test_get_rules_by_category_sql_injection(self) -> None:
        """SQL injection rules should be returned for the SQL_INJECTION category."""
        rules = get_rules_by_category(Category.SQL_INJECTION)
        assert len(rules) >= 1
        for rule in rules:
            assert rule.category == Category.SQL_INJECTION

    def test_get_rules_by_category_command_injection(self) -> None:
        """Command injection rules should be returned."""
        rules = get_rules_by_category(Category.COMMAND_INJECTION)
        assert len(rules) >= 1
        for rule in rules:
            assert rule.category == Category.COMMAND_INJECTION

    def test_get_rules_by_category_hardcoded_secret(self) -> None:
        """Hardcoded secret rules should be returned."""
        rules = get_rules_by_category(Category.HARDCODED_SECRET)
        assert len(rules) >= 1
        for rule in rules:
            assert rule.category == Category.HARDCODED_SECRET

    def test_get_rules_by_category_ldap_injection(self) -> None:
        """LDAP injection rules should be returned."""
        rules = get_rules_by_category(Category.LDAP_INJECTION)
        assert len(rules) >= 1
        for rule in rules:
            assert rule.category == Category.LDAP_INJECTION

    def test_get_rules_by_category_path_traversal(self) -> None:
        """Path traversal rules should be returned."""
        rules = get_rules_by_category(Category.PATH_TRAVERSAL)
        assert len(rules) >= 1
        for rule in rules:
            assert rule.category == Category.PATH_TRAVERSAL

    def test_get_rules_by_category_unsafe_deserialization(self) -> None:
        """Unsafe deserialization rules should be returned."""
        rules = get_rules_by_category(Category.UNSAFE_DESERIALIZATION)
        assert len(rules) >= 1
        for rule in rules:
            assert rule.category == Category.UNSAFE_DESERIALIZATION

    def test_get_rules_by_category_xss(self) -> None:
        """XSS rules should be returned."""
        rules = get_rules_by_category(Category.XSS)
        assert len(rules) >= 1
        for rule in rules:
            assert rule.category == Category.XSS

    def test_get_rules_by_category_insecure_randomness(self) -> None:
        """Insecure randomness rules should be returned."""
        rules = get_rules_by_category(Category.INSECURE_RANDOMNESS)
        assert len(rules) >= 1
        for rule in rules:
            assert rule.category == Category.INSECURE_RANDOMNESS

    def test_get_rules_by_category_weak_cryptography(self) -> None:
        """Weak cryptography rules should be returned."""
        rules = get_rules_by_category(Category.WEAK_CRYPTOGRAPHY)
        assert len(rules) >= 1
        for rule in rules:
            assert rule.category == Category.WEAK_CRYPTOGRAPHY

    def test_get_rules_by_category_insecure_auth(self) -> None:
        """Insecure auth rules should be returned."""
        rules = get_rules_by_category(Category.INSECURE_AUTH)
        assert len(rules) >= 1
        for rule in rules:
            assert rule.category == Category.INSECURE_AUTH

    def test_get_rules_by_severity_critical(self) -> None:
        """At least one critical-severity rule should exist."""
        rules = get_rules_by_severity(Severity.CRITICAL)
        assert len(rules) >= 1
        for rule in rules:
            assert rule.severity == Severity.CRITICAL

    def test_get_rules_by_severity_high(self) -> None:
        """At least one high-severity rule should exist."""
        rules = get_rules_by_severity(Severity.HIGH)
        assert len(rules) >= 1
        for rule in rules:
            assert rule.severity == Severity.HIGH

    def test_get_rules_by_severity_medium(self) -> None:
        """At least one medium-severity rule should exist."""
        rules = get_rules_by_severity(Severity.MEDIUM)
        assert len(rules) >= 1
        for rule in rules:
            assert rule.severity == Severity.MEDIUM

    def test_get_rules_at_or_above_severity_critical(self) -> None:
        """At-or-above CRITICAL should equal get_rules_by_severity(CRITICAL)."""
        at_above = get_rules_at_or_above_severity(Severity.CRITICAL)
        exact = get_rules_by_severity(Severity.CRITICAL)
        assert set(r.rule_id for r in at_above) == set(r.rule_id for r in exact)

    def test_get_rules_at_or_above_severity_high_includes_critical(self) -> None:
        """At-or-above HIGH should include both HIGH and CRITICAL rules."""
        at_above = get_rules_at_or_above_severity(Severity.HIGH)
        high_rules = get_rules_by_severity(Severity.HIGH)
        crit_rules = get_rules_by_severity(Severity.CRITICAL)
        expected_ids = {r.rule_id for r in high_rules} | {r.rule_id for r in crit_rules}
        actual_ids = {r.rule_id for r in at_above}
        assert expected_ids == actual_ids

    def test_get_rules_at_or_above_severity_low_is_all_non_info(self) -> None:
        """At-or-above LOW should exclude only INFO-severity rules."""
        at_above = get_rules_at_or_above_severity(Severity.LOW)
        info_rules = get_rules_by_severity(Severity.INFO)
        info_ids = {r.rule_id for r in info_rules}
        for rule in at_above:
            assert rule.rule_id not in info_ids

    def test_get_rules_at_or_above_severity_info_is_all(self) -> None:
        """At-or-above INFO should return all rules."""
        at_above = get_rules_at_or_above_severity(Severity.INFO)
        assert len(at_above) == len(ALL_RULES)

    def test_get_rules_by_category_returns_list(self) -> None:
        """get_rules_by_category() should return a list."""
        result = get_rules_by_category(Category.SQL_INJECTION)
        assert isinstance(result, list)

    def test_get_rules_by_severity_returns_list(self) -> None:
        """get_rules_by_severity() should return a list."""
        result = get_rules_by_severity(Severity.HIGH)
        assert isinstance(result, list)

    def test_get_rules_at_or_above_severity_returns_list(self) -> None:
        """get_rules_at_or_above_severity() should return a list."""
        result = get_rules_at_or_above_severity(Severity.MEDIUM)
        assert isinstance(result, list)

    def test_categories_covered(self) -> None:
        """A broad range of vulnerability categories should be represented."""
        covered = {rule.category for rule in ALL_RULES}
        required = {
            Category.SQL_INJECTION,
            Category.COMMAND_INJECTION,
            Category.HARDCODED_SECRET,
            Category.INSECURE_AUTH,
            Category.UNSAFE_DESERIALIZATION,
            Category.XSS,
            Category.INSECURE_RANDOMNESS,
            Category.WEAK_CRYPTOGRAPHY,
            Category.PATH_TRAVERSAL,
        }
        missing = required - covered
        assert not missing, f"Missing coverage for categories: {missing}"

    def test_sum_of_severity_buckets_equals_total(self) -> None:
        """Sum of counts across all severity buckets should equal total rule count."""
        total = len(ALL_RULES)
        bucket_sum = sum(
            len(get_rules_by_severity(sev)) for sev in Severity
        )
        assert bucket_sum == total

    def test_at_or_above_medium_subset_of_all(self) -> None:
        """Rules at-or-above MEDIUM should be a subset of all rules."""
        at_above_ids = {r.rule_id for r in get_rules_at_or_above_severity(Severity.MEDIUM)}
        all_ids = {r.rule_id for r in ALL_RULES}
        assert at_above_ids.issubset(all_ids)

    def test_at_or_above_high_is_smaller_than_at_or_above_medium(self) -> None:
        """Rules at-or-above HIGH should be <= rules at-or-above MEDIUM."""
        high_count = len(get_rules_at_or_above_severity(Severity.HIGH))
        medium_count = len(get_rules_at_or_above_severity(Severity.MEDIUM))
        assert high_count <= medium_count


# ---------------------------------------------------------------------------
# Pattern match tests: each rule must match its example payload
# ---------------------------------------------------------------------------


class TestRulePatternMatches:
    """Tests verifying that rules match their documented attack payloads."""

    # --- SQL Injection ---

    def test_vd001_matches_fstring_execute(self) -> None:
        """VD001 should match cursor.execute with an f-string."""
        rule = get_rule_by_id("VD001")
        line = "    cursor.execute(f'SELECT * FROM users WHERE id={uid}')"
        assert rule.matches(line) is not None

    def test_vd001_matches_execute_fstring_double_quote(self) -> None:
        """VD001 should match cursor.execute with a double-quoted f-string."""
        rule = get_rule_by_id("VD001")
        line = '    cursor.execute(f"SELECT * FROM users WHERE name={name}")'
        assert rule.matches(line) is not None

    def test_vd001_matches_db_execute_fstring(self) -> None:
        """VD001 should match db.execute with an f-string."""
        rule = get_rule_by_id("VD001")
        line = "    db.execute(f'INSERT INTO logs VALUES ({val})')"
        assert rule.matches(line) is not None

    def test_vd002_matches_string_concat_select(self) -> None:
        """VD002 should match SELECT with string concatenation."""
        rule = get_rule_by_id("VD002")
        line = "    query = 'SELECT * FROM users WHERE id=' + user_id"
        assert rule.matches(line) is not None

    def test_vd002_matches_format_call(self) -> None:
        """VD002 should match DELETE with .format() call."""
        rule = get_rule_by_id("VD002")
        line = "    sql = 'DELETE FROM sessions WHERE token={}'.format(token)"
        assert rule.matches(line) is not None

    def test_vd002_matches_update_concat(self) -> None:
        """VD002 should match UPDATE with concatenation."""
        rule = get_rule_by_id("VD002")
        line = "    q = 'UPDATE users SET name=' + name + ' WHERE id=1'"
        assert rule.matches(line) is not None

    def test_vd003_matches_django_raw_fstring(self) -> None:
        """VD003 should match Django raw() with an f-string."""
        rule = get_rule_by_id("VD003")
        line = "    MyModel.objects.raw(f'SELECT * FROM t WHERE id={pk}')"
        assert rule.matches(line) is not None

    def test_vd003_matches_text_concat(self) -> None:
        """VD003 should match SQLAlchemy text() with concatenation."""
        rule = get_rule_by_id("VD003")
        line = "    stmt = text('SELECT * FROM t WHERE x=' + val)"
        assert rule.matches(line) is not None

    # --- Command Injection ---

    def test_vd010_matches_os_system_fstring(self) -> None:
        """VD010 should match os.system() with an f-string."""
        rule = get_rule_by_id("VD010")
        line = "    os.system(f'ls {directory}')"
        assert rule.matches(line) is not None

    def test_vd010_matches_os_system_concat(self) -> None:
        """VD010 should match os.system() with concatenation."""
        rule = get_rule_by_id("VD010")
        line = "    os.system('rm ' + filename)"
        assert rule.matches(line) is not None

    def test_vd011_matches_subprocess_shell_true(self) -> None:
        """VD011 should match subprocess.run with shell=True."""
        rule = get_rule_by_id("VD011")
        line = "    subprocess.run(cmd, shell=True)"
        assert rule.matches(line) is not None

    def test_vd011_matches_subprocess_check_output_shell_true(self) -> None:
        """VD011 should match subprocess.check_output with shell=True."""
        rule = get_rule_by_id("VD011")
        line = "    output = subprocess.check_output(cmd, shell=True)"
        assert rule.matches(line) is not None

    def test_vd011_matches_subprocess_call_shell_true(self) -> None:
        """VD011 should match subprocess.call with shell=True."""
        rule = get_rule_by_id("VD011")
        line = "    subprocess.call(command, shell=True)"
        assert rule.matches(line) is not None

    def test_vd012_matches_os_popen_fstring(self) -> None:
        """VD012 should match os.popen() with an f-string."""
        rule = get_rule_by_id("VD012")
        line = "    result = os.popen(f'cat {filename}')"
        assert rule.matches(line) is not None

    def test_vd012_matches_os_popen_concat(self) -> None:
        """VD012 should match os.popen() with concatenation."""
        rule = get_rule_by_id("VD012")
        line = "    fd = os.popen('cat ' + filepath)"
        assert rule.matches(line) is not None

    def test_vd013_matches_eval_variable(self) -> None:
        """VD013 should match eval() with a variable argument."""
        rule = get_rule_by_id("VD013")
        line = "    result = eval(user_code)"
        assert rule.matches(line) is not None

    def test_vd013_matches_eval_request_input(self) -> None:
        """VD013 should match eval() with request input."""
        rule = get_rule_by_id("VD013")
        line = "    val = eval(request.form.get('expr'))"
        assert rule.matches(line) is not None

    def test_vd014_matches_exec_variable(self) -> None:
        """VD014 should match exec() with a variable."""
        rule = get_rule_by_id("VD014")
        line = "    exec(request.data)"
        assert rule.matches(line) is not None

    def test_vd014_matches_exec_user_code(self) -> None:
        """VD014 should match exec() with user-supplied code variable."""
        rule = get_rule_by_id("VD014")
        line = "    exec(user_script)"
        assert rule.matches(line) is not None

    # --- LDAP Injection ---

    def test_vd020_matches_ldap_search(self) -> None:
        """VD020 should match LDAP search_s() with concatenation."""
        rule = get_rule_by_id("VD020")
        line = "    conn.search_s(base, '(uid=' + username + ')')  # noqa"
        assert rule.matches(line) is not None

    def test_vd020_matches_ldap_search_format(self) -> None:
        """VD020 should match LDAP search_s() with %s formatting."""
        rule = get_rule_by_id("VD020")
        line = "    conn.search_s(base, '(cn=%s)' % username)"
        assert rule.matches(line) is not None

    # --- Path Traversal ---

    def test_vd030_matches_open_fstring(self) -> None:
        """VD030 should match open() with an f-string path."""
        rule = get_rule_by_id("VD030")
        line = "    with open(f'/var/data/{filename}') as f:"
        assert rule.matches(line) is not None

    def test_vd031_matches_dotdot_literal(self) -> None:
        """VD031 should match a string literal containing '../'."""
        rule = get_rule_by_id("VD031")
        line = "    path = '../etc/passwd'"
        assert rule.matches(line) is not None

    def test_vd031_matches_dotdot_in_path(self) -> None:
        """VD031 should match '../' in a longer path string."""
        rule = get_rule_by_id("VD031")
        line = "    restricted_path = '../../secret/config.json'"
        assert rule.matches(line) is not None

    def test_vd032_matches_send_file_variable(self) -> None:
        """VD032 should match send_file() with an f-string."""
        rule = get_rule_by_id("VD032")
        line = "    return send_file(f'/uploads/{filename}')"
        assert rule.matches(line) is not None

    def test_vd032_matches_send_from_directory_variable(self) -> None:
        """VD032 should match send_from_directory() with a variable."""
        rule = get_rule_by_id("VD032")
        line = "    return send_from_directory(directory, filename)"
        assert rule.matches(line) is not None

    # --- Hardcoded Secrets ---

    def test_vd040_matches_hardcoded_password(self) -> None:
        """VD040 should match a hardcoded password assignment."""
        rule = get_rule_by_id("VD040")
        line = "    password = 'SuperSecret123'"
        assert rule.matches(line) is not None

    def test_vd040_matches_hardcoded_api_key(self) -> None:
        """VD040 should match a hardcoded api_key assignment."""
        rule = get_rule_by_id("VD040")
        line = "    api_key = 'abcdefghijklmnopqrst'"
        assert rule.matches(line) is not None

    def test_vd040_matches_hardcoded_secret_key(self) -> None:
        """VD040 should match a hardcoded secret_key assignment."""
        rule = get_rule_by_id("VD040")
        line = "    secret_key = 'my-secret-value'"
        assert rule.matches(line) is not None

    def test_vd041_matches_aws_access_key(self) -> None:
        """VD041 should match an AWS AKIA access key ID."""
        rule = get_rule_by_id("VD041")
        line = "    AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"
        assert rule.matches(line) is not None

    def test_vd041_matches_asia_key(self) -> None:
        """VD041 should match an AWS ASIA temporary key ID."""
        rule = get_rule_by_id("VD041")
        line = "key = 'ASIAIOSFODNN7EXAMPLE1'"
        assert rule.matches(line) is not None

    def test_vd041_matches_aroa_key(self) -> None:
        """VD041 should match an AWS AROA role key pattern."""
        rule = get_rule_by_id("VD041")
        line = "ROLE_ID = 'AROAIOSFODNN7EXAMPLEXX'"
        assert rule.matches(line) is not None

    def test_vd042_matches_generic_token(self) -> None:
        """VD042 should match a long alphanumeric token literal."""
        rule = get_rule_by_id("VD042")
        line = "    token = 'abcdefghijklmnopqrstuvwxyz12345678'"
        assert rule.matches(line) is not None

    def test_vd042_matches_api_key_assignment(self) -> None:
        """VD042 should match an api_key assignment with a long value."""
        rule = get_rule_by_id("VD042")
        line = "    api_key = 'sk-abcdefghijklmnopqrstuvwxyz123456'"
        assert rule.matches(line) is not None

    def test_vd043_matches_rsa_private_key_header(self) -> None:
        """VD043 should match a BEGIN RSA PRIVATE KEY header."""
        rule = get_rule_by_id("VD043")
        line = "-----BEGIN RSA PRIVATE KEY-----"
        assert rule.matches(line) is not None

    def test_vd043_matches_ec_private_key(self) -> None:
        """VD043 should match a BEGIN EC PRIVATE KEY header."""
        rule = get_rule_by_id("VD043")
        line = "-----BEGIN EC PRIVATE KEY-----"
        assert rule.matches(line) is not None

    def test_vd043_matches_plain_private_key(self) -> None:
        """VD043 should match a plain BEGIN PRIVATE KEY header."""
        rule = get_rule_by_id("VD043")
        line = "-----BEGIN PRIVATE KEY-----"
        assert rule.matches(line) is not None

    def test_vd043_matches_openssh_private_key(self) -> None:
        """VD043 should match a BEGIN OPENSSH PRIVATE KEY header."""
        rule = get_rule_by_id("VD043")
        line = "-----BEGIN OPENSSH PRIVATE KEY-----"
        assert rule.matches(line) is not None

    def test_vd044_matches_github_pat_ghp(self) -> None:
        """VD044 should match a GitHub PAT with ghp_ prefix."""
        rule = get_rule_by_id("VD044")
        line = "    token = 'ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH'"
        assert rule.matches(line) is not None

    def test_vd044_matches_github_token_ghs(self) -> None:
        """VD044 should match a GitHub server token with ghs_ prefix."""
        rule = get_rule_by_id("VD044")
        line = "    GH_TOKEN = 'ghs_abcdefghijklmnopqrstuvwxyz123456'"
        assert rule.matches(line) is not None

    # --- Insecure Auth / TLS ---

    def test_vd050_matches_requests_get_verify_false(self) -> None:
        """VD050 should match requests.get with verify=False."""
        rule = get_rule_by_id("VD050")
        line = "    resp = requests.get(url, verify=False)"
        assert rule.matches(line) is not None

    def test_vd050_matches_requests_post_verify_false(self) -> None:
        """VD050 should match requests.post with verify=False."""
        rule = get_rule_by_id("VD050")
        line = "    r = requests.post(endpoint, json=data, verify=False)"
        assert rule.matches(line) is not None

    def test_vd050_matches_requests_put_verify_false(self) -> None:
        """VD050 should match requests.put with verify=False."""
        rule = get_rule_by_id("VD050")
        line = "    resp = requests.put(url, data=payload, verify=False)"
        assert rule.matches(line) is not None

    def test_vd051_matches_check_hostname_false(self) -> None:
        """VD051 should match check_hostname = False."""
        rule = get_rule_by_id("VD051")
        line = "    ctx.check_hostname = False"
        assert rule.matches(line) is not None

    def test_vd051_matches_cert_none(self) -> None:
        """VD051 should match verify_mode = ssl.CERT_NONE."""
        rule = get_rule_by_id("VD051")
        line = "    ctx.verify_mode = ssl.CERT_NONE"
        assert rule.matches(line) is not None

    def test_vd052_matches_basic_auth_tuple(self) -> None:
        """VD052 should match a hardcoded HTTP Basic Auth tuple."""
        rule = get_rule_by_id("VD052")
        line = "    resp = requests.get(url, auth=('admin', 'password123'))"
        assert rule.matches(line) is not None

    def test_vd052_matches_basic_auth_tuple_no_space(self) -> None:
        """VD052 should match auth=('user','pass') with no spaces."""
        rule = get_rule_by_id("VD052")
        line = "    r = requests.get(url, auth=('user','pass'))"
        assert rule.matches(line) is not None

    def test_vd053_matches_jwt_none_algorithm(self) -> None:
        """VD053 should match JWT decode with algorithm='none'."""
        rule = get_rule_by_id("VD053")
        line = "    payload = jwt.decode(token, algorithms='none')"
        assert rule.matches(line) is not None

    def test_vd054_matches_app_run_debug_true(self) -> None:
        """VD054 should match app.run() with debug=True."""
        rule = get_rule_by_id("VD054")
        line = "    app.run(host='0.0.0.0', debug=True)"
        assert rule.matches(line) is not None

    def test_vd054_matches_django_debug_true(self) -> None:
        """VD054 should match Django's DEBUG = True setting."""
        rule = get_rule_by_id("VD054")
        line = "DEBUG = True"
        assert rule.matches(line) is not None

    # --- Unsafe Deserialization ---

    def test_vd060_matches_pickle_loads(self) -> None:
        """VD060 should match pickle.loads()."""
        rule = get_rule_by_id("VD060")
        line = "    obj = pickle.loads(data)"
        assert rule.matches(line) is not None

    def test_vd060_matches_pickle_load(self) -> None:
        """VD060 should match pickle.load()."""
        rule = get_rule_by_id("VD060")
        line = "    obj = pickle.load(file_handle)"
        assert rule.matches(line) is not None

    def test_vd060_matches_pickle_unpickler(self) -> None:
        """VD060 should match pickle.Unpickler()."""
        rule = get_rule_by_id("VD060")
        line = "    unpickler = pickle.Unpickler(file_obj)"
        assert rule.matches(line) is not None

    def test_vd061_matches_yaml_load_no_loader(self) -> None:
        """VD061 should match yaml.load() without a Loader argument."""
        rule = get_rule_by_id("VD061")
        line = "    data = yaml.load(stream)"
        assert rule.matches(line) is not None

    def test_vd061_matches_yaml_load_unsafe_loader(self) -> None:
        """VD061 should match yaml.load() with Loader=yaml.Loader."""
        rule = get_rule_by_id("VD061")
        line = "    data = yaml.load(stream, Loader=yaml.Loader)"
        assert rule.matches(line) is not None

    def test_vd062_matches_marshal_loads(self) -> None:
        """VD062 should match marshal.loads()."""
        rule = get_rule_by_id("VD062")
        line = "    obj = marshal.loads(data)"
        assert rule.matches(line) is not None

    def test_vd062_matches_marshal_load(self) -> None:
        """VD062 should match marshal.load()."""
        rule = get_rule_by_id("VD062")
        line = "    obj = marshal.load(file_handle)"
        assert rule.matches(line) is not None

    def test_vd063_matches_jsonpickle_decode(self) -> None:
        """VD063 should match jsonpickle.decode()."""
        rule = get_rule_by_id("VD063")
        line = "    obj = jsonpickle.decode(payload)"
        assert rule.matches(line) is not None

    # --- XSS ---

    def test_vd070_matches_inner_html(self) -> None:
        """VD070 should match .innerHTML = assignment."""
        rule = get_rule_by_id("VD070")
        line = "    element.innerHTML = userInput;"
        assert rule.matches(line) is not None

    def test_vd070_matches_outer_html(self) -> None:
        """VD070 should match .outerHTML = assignment."""
        rule = get_rule_by_id("VD070")
        line = "    div.outerHTML = value;"
        assert rule.matches(line) is not None

    def test_vd071_matches_dangerous_set_inner_html(self) -> None:
        """VD071 should match React dangerouslySetInnerHTML={{ __html usage."""
        rule = get_rule_by_id("VD071")
        line = "    return <div dangerouslySetInnerHTML={{ __html: markup }} />;"
        assert rule.matches(line) is not None

    def test_vd072_matches_document_write(self) -> None:
        """VD072 should match document.write()."""
        rule = get_rule_by_id("VD072")
        line = "    document.write(userContent);"
        assert rule.matches(line) is not None

    def test_vd073_matches_mark_safe_variable(self) -> None:
        """VD073 should match mark_safe() with a variable argument."""
        rule = get_rule_by_id("VD073")
        line = "    return mark_safe(user_html)"
        assert rule.matches(line) is not None

    def test_vd073_matches_markup_variable(self) -> None:
        """VD073 should match Markup() with a variable argument."""
        rule = get_rule_by_id("VD073")
        line = "    safe = Markup(user_content)"
        assert rule.matches(line) is not None

    # --- Insecure Randomness ---

    def test_vd080_matches_random_randint(self) -> None:
        """VD080 should match random.randint()."""
        rule = get_rule_by_id("VD080")
        line = "    token = random.randint(0, 999999)"
        assert rule.matches(line) is not None

    def test_vd080_matches_random_choice(self) -> None:
        """VD080 should match random.choice()."""
        rule = get_rule_by_id("VD080")
        line = "    session_id = random.choice(charset)"
        assert rule.matches(line) is not None

    def test_vd080_matches_random_random(self) -> None:
        """VD080 should match random.random()."""
        rule = get_rule_by_id("VD080")
        line = "    val = random.random()"
        assert rule.matches(line) is not None

    def test_vd080_matches_random_choices(self) -> None:
        """VD080 should match random.choices()."""
        rule = get_rule_by_id("VD080")
        line = "    password = ''.join(random.choices(chars, k=16))"
        assert rule.matches(line) is not None

    def test_vd081_matches_seed_integer(self) -> None:
        """VD081 should match random.seed() with an integer constant."""
        rule = get_rule_by_id("VD081")
        line = "    random.seed(42)"
        assert rule.matches(line) is not None

    def test_vd081_matches_seed_string(self) -> None:
        """VD081 should match random.seed() with a string literal."""
        rule = get_rule_by_id("VD081")
        line = "    random.seed('fixed')"
        assert rule.matches(line) is not None

    def test_vd081_matches_seed_zero(self) -> None:
        """VD081 should match random.seed(0)."""
        rule = get_rule_by_id("VD081")
        line = "    random.seed(0)"
        assert rule.matches(line) is not None

    # --- Weak Cryptography ---

    def test_vd090_matches_hashlib_md5(self) -> None:
        """VD090 should match hashlib.md5()."""
        rule = get_rule_by_id("VD090")
        line = "    h = hashlib.md5(data)"
        assert rule.matches(line) is not None

    def test_vd090_matches_md5_new(self) -> None:
        """VD090 should match MD5.new() from PyCryptodome."""
        rule = get_rule_by_id("VD090")
        line = "    h = MD5.new(data)"
        assert rule.matches(line) is not None

    def test_vd091_matches_hashlib_sha1(self) -> None:
        """VD091 should match hashlib.sha1()."""
        rule = get_rule_by_id("VD091")
        line = "    h = hashlib.sha1(data)"
        assert rule.matches(line) is not None

    def test_vd091_matches_sha1_new(self) -> None:
        """VD091 should match SHA1.new() from PyCryptodome."""
        rule = get_rule_by_id("VD091")
        line = "    h = SHA1.new(data)"
        assert rule.matches(line) is not None

    def test_vd092_matches_des_import(self) -> None:
        """VD092 should match 'from Crypto.Cipher import DES'."""
        rule = get_rule_by_id("VD092")
        line = "    from Crypto.Cipher import DES"
        assert rule.matches(line) is not None

    def test_vd092_matches_des3_new(self) -> None:
        """VD092 should match DES3.new()."""
        rule = get_rule_by_id("VD092")
        line = "    cipher = DES3.new(key, DES3.MODE_CBC, iv)"
        assert rule.matches(line) is not None

    def test_vd093_matches_arc4_import(self) -> None:
        """VD093 should match 'from Crypto.Cipher import ARC4'."""
        rule = get_rule_by_id("VD093")
        line = "    from Crypto.Cipher import ARC4"
        assert rule.matches(line) is not None

    def test_vd093_matches_arc4_new(self) -> None:
        """VD093 should match ARC4.new()."""
        rule = get_rule_by_id("VD093")
        line = "    cipher = ARC4.new(key)"
        assert rule.matches(line) is not None

    def test_vd094_matches_ecb_mode(self) -> None:
        """VD094 should match AES.MODE_ECB usage."""
        rule = get_rule_by_id("VD094")
        line = "    cipher = AES.new(key, AES.MODE_ECB)"
        assert rule.matches(line) is not None

    def test_vd095_matches_md5_password(self) -> None:
        """VD095 should match hashlib.md5() applied to a password variable."""
        rule = get_rule_by_id("VD095")
        line = "    h = hashlib.md5(password.encode()).hexdigest()"
        assert rule.matches(line) is not None

    def test_vd095_matches_sha1_passwd(self) -> None:
        """VD095 should match hashlib.sha1() applied to a passwd variable."""
        rule = get_rule_by_id("VD095")
        line = "    digest = hashlib.sha1(passwd).hexdigest()"
        assert rule.matches(line) is not None

    def test_vd095_matches_sha256_pwd(self) -> None:
        """VD095 should match hashlib.sha256() applied to a pwd variable."""
        rule = get_rule_by_id("VD095")
        line = "    h = hashlib.sha256(pwd).digest()"
        assert rule.matches(line) is not None

    # --- Sensitive Data Exposure ---

    def test_vd100_matches_logger_debug_password(self) -> None:
        """VD100 should match logger.debug() containing a password variable."""
        rule = get_rule_by_id("VD100")
        line = "    logger.debug(f'User password: {password}')"
        assert rule.matches(line) is not None

    def test_vd100_matches_print_secret(self) -> None:
        """VD100 should match print() containing a secret variable."""
        rule = get_rule_by_id("VD100")
        line = "    print('secret value:', secret)"
        assert rule.matches(line) is not None

    def test_vd100_matches_log_info_token(self) -> None:
        """VD100 should match log.info() containing a token variable."""
        rule = get_rule_by_id("VD100")
        line = "    log.info('Auth token: ' + token)"
        assert rule.matches(line) is not None

    # --- Insecure Configuration ---

    def test_vd110_matches_change_me_secret_key(self) -> None:
        """VD110 should match SECRET_KEY = 'change-me'."""
        rule = get_rule_by_id("VD110")
        line = "SECRET_KEY = 'change-me'"
        assert rule.matches(line) is not None

    def test_vd110_matches_insecure_secret_key(self) -> None:
        """VD110 should match SECRET_KEY = 'django-insecure-...'."""
        rule = get_rule_by_id("VD110")
        line = "SECRET_KEY = 'django-insecure-abc123'"
        assert rule.matches(line) is not None

    def test_vd110_matches_secret_value(self) -> None:
        """VD110 should match SECRET_KEY = 'secret'."""
        rule = get_rule_by_id("VD110")
        line = "SECRET_KEY = 'secret'"
        assert rule.matches(line) is not None

    def test_vd111_matches_allowed_hosts_wildcard(self) -> None:
        """VD111 should match ALLOWED_HOSTS = ['*']."""
        rule = get_rule_by_id("VD111")
        line = "ALLOWED_HOSTS = ['*']"
        assert rule.matches(line) is not None

    def test_vd112_matches_cors_allow_all_origins_true(self) -> None:
        """VD112 should match CORS_ALLOW_ALL_ORIGINS = True."""
        rule = get_rule_by_id("VD112")
        line = "CORS_ALLOW_ALL_ORIGINS = True"
        assert rule.matches(line) is not None

    # --- SSTI ---

    def test_vd120_matches_template_variable(self) -> None:
        """VD120 should match Template() with a variable argument."""
        rule = get_rule_by_id("VD120")
        line = "    t = Template(user_template)"
        assert rule.matches(line) is not None

    def test_vd120_matches_from_string_variable(self) -> None:
        """VD120 should match from_string() with a variable argument."""
        rule = get_rule_by_id("VD120")
        line = "    tmpl = env.from_string(user_input)"
        assert rule.matches(line) is not None

    def test_vd120_matches_render_template_string(self) -> None:
        """VD120 should match render_template_string() with a variable."""
        rule = get_rule_by_id("VD120")
        line = "    return render_template_string(user_template)"
        assert rule.matches(line) is not None

    # --- XXE ---

    def test_vd130_matches_etree_parse(self) -> None:
        """VD130 should match etree.parse()."""
        rule = get_rule_by_id("VD130")
        line = "    tree = etree.parse(xml_file)"
        assert rule.matches(line) is not None

    def test_vd130_matches_et_fromstring(self) -> None:
        """VD130 should match ET.fromstring()."""
        rule = get_rule_by_id("VD130")
        line = "    root = ET.fromstring(xml_data)"
        assert rule.matches(line) is not None

    def test_vd130_matches_minidom_parse(self) -> None:
        """VD130 should match minidom.parse()."""
        rule = get_rule_by_id("VD130")
        line = "    doc = minidom.parse(xml_file)"
        assert rule.matches(line) is not None

    def test_vd130_matches_et_parse(self) -> None:
        """VD130 should match ET.parse()."""
        rule = get_rule_by_id("VD130")
        line = "    tree = ET.parse(source)"
        assert rule.matches(line) is not None

    # --- ReDoS ---

    def test_vd140_matches_re_compile_variable(self) -> None:
        """VD140 should match re.compile() with a variable pattern."""
        rule = get_rule_by_id("VD140")
        line = "    pattern = re.compile(user_input)"
        assert rule.matches(line) is not None

    def test_vd140_matches_re_match_variable(self) -> None:
        """VD140 should match re.match() with a variable pattern."""
        rule = get_rule_by_id("VD140")
        line = "    m = re.match(user_pattern, text)"
        assert rule.matches(line) is not None

    def test_vd140_matches_re_search_variable(self) -> None:
        """VD140 should match re.search() with a variable pattern."""
        rule = get_rule_by_id("VD140")
        line = "    result = re.search(pattern_from_user, data)"
        assert rule.matches(line) is not None

    # --- SSRF ---

    def test_vd150_matches_requests_get_variable_url(self) -> None:
        """VD150 should match requests.get() with a variable URL."""
        rule = get_rule_by_id("VD150")
        line = "    resp = requests.get(url)"
        assert rule.matches(line) is not None

    def test_vd150_matches_requests_post_fstring_url(self) -> None:
        """VD150 should match requests.post() with an f-string URL."""
        rule = get_rule_by_id("VD150")
        line = "    resp = requests.post(f'http://api/{endpoint}', json=data)"
        assert rule.matches(line) is not None

    def test_vd150_matches_urllib_urlopen_variable(self) -> None:
        """VD150 should match urllib.request.urlopen() with a variable URL."""
        rule = get_rule_by_id("VD150")
        line = "    response = urllib.request.urlopen(url)"
        assert rule.matches(line) is not None

    # --- File Upload ---

    def test_vd160_matches_file_save_filename(self) -> None:
        """VD160 should match file.save() with a user-supplied filename."""
        rule = get_rule_by_id("VD160")
        line = "    file.save(os.path.join(upload_dir, file.filename))"
        assert rule.matches(line) is not None

    def test_vd160_matches_open_request_files(self) -> None:
        """VD160 should match open() with request.FILES in the path."""
        rule = get_rule_by_id("VD160")
        line = "    with open(request.FILES['upload'].name) as f:"
        assert rule.matches(line) is not None


# ---------------------------------------------------------------------------
# Pattern NON-match tests: safe patterns should NOT trigger rules
# ---------------------------------------------------------------------------


class TestRulePatternNonMatches:
    """Tests verifying that safe code patterns do not trigger rules."""

    def test_vd011_safe_subprocess_list_no_shell(self) -> None:
        """subprocess.run with a list and no shell=True should not match VD011."""
        rule = get_rule_by_id("VD011")
        line = "    subprocess.run(['ls', '-la'])"
        assert rule.matches(line) is None

    def test_vd011_safe_subprocess_shell_false(self) -> None:
        """subprocess.run with shell=False should not match VD011."""
        rule = get_rule_by_id("VD011")
        line = "    subprocess.run(cmd, shell=False)"
        assert rule.matches(line) is None

    def test_vd050_safe_verify_true(self) -> None:
        """requests.get with verify=True should not match VD050."""
        rule = get_rule_by_id("VD050")
        line = "    resp = requests.get(url, verify=True)"
        assert rule.matches(line) is None

    def test_vd050_safe_verify_path(self) -> None:
        """requests.get with verify='/path/to/ca.crt' should not match VD050."""
        rule = get_rule_by_id("VD050")
        line = "    resp = requests.get(url, verify='/etc/ssl/certs/ca-certificates.crt')"
        assert rule.matches(line) is None

    def test_vd054_debug_false_safe(self) -> None:
        """DEBUG = False should not trigger VD054."""
        rule = get_rule_by_id("VD054")
        line = "DEBUG = False"
        assert rule.matches(line) is None

    def test_vd061_safe_yaml_safe_load(self) -> None:
        """yaml.safe_load() should not match VD061."""
        rule = get_rule_by_id("VD061")
        line = "    data = yaml.safe_load(stream)"
        assert rule.matches(line) is None

    def test_vd080_safe_secrets_token(self) -> None:
        """secrets.token_hex() should not be flagged by VD080."""
        rule = get_rule_by_id("VD080")
        line = "    token = secrets.token_hex(32)"
        assert rule.matches(line) is None

    def test_vd080_safe_secrets_choice(self) -> None:
        """secrets.choice() should not be flagged by VD080."""
        rule = get_rule_by_id("VD080")
        line = "    c = secrets.choice(charset)"
        assert rule.matches(line) is None

    def test_vd090_safe_sha256(self) -> None:
        """hashlib.sha256 should not be flagged by the MD5 rule VD090."""
        rule = get_rule_by_id("VD090")
        line = "    h = hashlib.sha256(data).hexdigest()"
        assert rule.matches(line) is None

    def test_vd090_safe_sha512(self) -> None:
        """hashlib.sha512 should not be flagged by VD090."""
        rule = get_rule_by_id("VD090")
        line = "    h = hashlib.sha512(data).hexdigest()"
        assert rule.matches(line) is None

    def test_vd091_safe_sha256(self) -> None:
        """hashlib.sha256 should not match VD091 (SHA-1 rule)."""
        rule = get_rule_by_id("VD091")
        line = "    h = hashlib.sha256(data).hexdigest()"
        assert rule.matches(line) is None

    def test_vd094_safe_gcm_mode(self) -> None:
        """AES.MODE_GCM should not trigger the ECB mode rule VD094."""
        rule = get_rule_by_id("VD094")
        line = "    cipher = AES.new(key, AES.MODE_GCM)"
        assert rule.matches(line) is None

    def test_vd094_safe_cbc_mode(self) -> None:
        """AES.MODE_CBC should not trigger VD094."""
        rule = get_rule_by_id("VD094")
        line = "    cipher = AES.new(key, AES.MODE_CBC, iv)"
        assert rule.matches(line) is None

    def test_vd140_safe_literal_pattern(self) -> None:
        """re.compile with a string literal should not trigger VD140."""
        rule = get_rule_by_id("VD140")
        line = "    pat = re.compile(r'^[a-z]+$')"
        assert rule.matches(line) is None

    def test_vd111_safe_specific_hosts(self) -> None:
        """ALLOWED_HOSTS with specific domains should not match VD111."""
        rule = get_rule_by_id("VD111")
        line = "ALLOWED_HOSTS = ['example.com', 'www.example.com']"
        assert rule.matches(line) is None

    def test_vd053_safe_rs256_algorithm(self) -> None:
        """JWT decode with algorithms='RS256' should not match VD053."""
        rule = get_rule_by_id("VD053")
        line = "    payload = jwt.decode(token, key, algorithms=['RS256'])"
        assert rule.matches(line) is None

    def test_vd070_safe_text_content(self) -> None:
        """Assignment to .textContent should not match VD070 (innerHTML rule)."""
        rule = get_rule_by_id("VD070")
        line = "    element.textContent = userText;"
        assert rule.matches(line) is None


# ---------------------------------------------------------------------------
# Rule metadata integrity tests
# ---------------------------------------------------------------------------


class TestRuleMetadataIntegrity:
    """Tests checking that important rules carry required metadata."""

    @pytest.mark.parametrize("rule_id", [
        "VD001", "VD002", "VD010", "VD011", "VD013", "VD014",
        "VD030", "VD040", "VD041", "VD043", "VD050", "VD060",
        "VD061", "VD070", "VD071", "VD080", "VD090", "VD091",
    ])
    def test_critical_rules_have_cwe(self, rule_id: str) -> None:
        """High-importance rules should have a CWE ID assigned."""
        rule = get_rule_by_id(rule_id)
        assert rule.cwe_id is not None and rule.cwe_id.strip(), (
            f"{rule_id}: expected a CWE ID but got {rule.cwe_id!r}"
        )

    @pytest.mark.parametrize("rule_id", [
        "VD001", "VD002", "VD010", "VD011", "VD013", "VD050",
        "VD060", "VD070", "VD080", "VD090",
    ])
    def test_critical_rules_have_owasp_id(self, rule_id: str) -> None:
        """High-importance rules should have an OWASP identifier."""
        rule = get_rule_by_id(rule_id)
        assert rule.owasp_id is not None and rule.owasp_id.strip(), (
            f"{rule_id}: expected an OWASP ID but got {rule.owasp_id!r}"
        )

    @pytest.mark.parametrize("rule_id", [
        "VD001", "VD010", "VD050", "VD060", "VD070",
    ])
    def test_key_rules_have_references(self, rule_id: str) -> None:
        """Key rules should include at least one reference URL."""
        rule = get_rule_by_id(rule_id)
        assert len(rule.references) >= 1, (
            f"{rule_id}: expected at least one reference URL"
        )

    @pytest.mark.parametrize("rule_id", [
        "VD001", "VD010", "VD050", "VD060",
    ])
    def test_key_rules_have_tags(self, rule_id: str) -> None:
        """Key rules should have at least one tag."""
        rule = get_rule_by_id(rule_id)
        assert len(rule.tags) >= 1, (
            f"{rule_id}: expected at least one tag"
        )

    def test_vd001_is_critical(self) -> None:
        """SQL injection f-string rule should be CRITICAL severity."""
        rule = get_rule_by_id("VD001")
        assert rule.severity == Severity.CRITICAL

    def test_vd010_is_critical(self) -> None:
        """os.system() command injection rule should be CRITICAL."""
        rule = get_rule_by_id("VD010")
        assert rule.severity == Severity.CRITICAL

    def test_vd041_is_critical(self) -> None:
        """AWS Access Key hardcoded secret rule should be CRITICAL."""
        rule = get_rule_by_id("VD041")
        assert rule.severity == Severity.CRITICAL

    def test_vd043_is_critical(self) -> None:
        """Private key material rule should be CRITICAL."""
        rule = get_rule_by_id("VD043")
        assert rule.severity == Severity.CRITICAL

    def test_vd060_is_critical(self) -> None:
        """pickle.loads() unsafe deserialization rule should be CRITICAL."""
        rule = get_rule_by_id("VD060")
        assert rule.severity == Severity.CRITICAL

    def test_vd013_is_critical(self) -> None:
        """eval() code injection rule should be CRITICAL."""
        rule = get_rule_by_id("VD013")
        assert rule.severity == Severity.CRITICAL

    def test_vd044_is_critical(self) -> None:
        """GitHub PAT hardcoded secret rule should be CRITICAL."""
        rule = get_rule_by_id("VD044")
        assert rule.severity == Severity.CRITICAL

    def test_vd053_is_critical(self) -> None:
        """JWT none algorithm rule should be CRITICAL."""
        rule = get_rule_by_id("VD053")
        assert rule.severity == Severity.CRITICAL

    def test_vd011_is_high(self) -> None:
        """subprocess shell=True rule should be HIGH severity."""
        rule = get_rule_by_id("VD011")
        assert rule.severity == Severity.HIGH

    def test_vd050_is_high(self) -> None:
        """TLS verify=False rule should be HIGH severity."""
        rule = get_rule_by_id("VD050")
        assert rule.severity == Severity.HIGH

    def test_vd080_is_medium(self) -> None:
        """Insecure random() rule should be MEDIUM severity."""
        rule = get_rule_by_id("VD080")
        assert rule.severity == Severity.MEDIUM

    def test_vd090_is_medium(self) -> None:
        """MD5 weak hash rule should be MEDIUM severity."""
        rule = get_rule_by_id("VD090")
        assert rule.severity == Severity.MEDIUM

    def test_vd001_category_is_sql_injection(self) -> None:
        """VD001 should be in the SQL_INJECTION category."""
        rule = get_rule_by_id("VD001")
        assert rule.category == Category.SQL_INJECTION

    def test_vd010_category_is_command_injection(self) -> None:
        """VD010 should be in the COMMAND_INJECTION category."""
        rule = get_rule_by_id("VD010")
        assert rule.category == Category.COMMAND_INJECTION

    def test_vd011_category_is_command_injection(self) -> None:
        """VD011 should be in the COMMAND_INJECTION category."""
        rule = get_rule_by_id("VD011")
        assert rule.category == Category.COMMAND_INJECTION

    def test_vd041_category_is_hardcoded_secret(self) -> None:
        """VD041 should be in the HARDCODED_SECRET category."""
        rule = get_rule_by_id("VD041")
        assert rule.category == Category.HARDCODED_SECRET

    def test_vd060_category_is_unsafe_deserialization(self) -> None:
        """VD060 should be in the UNSAFE_DESERIALIZATION category."""
        rule = get_rule_by_id("VD060")
        assert rule.category == Category.UNSAFE_DESERIALIZATION

    def test_vd070_category_is_xss(self) -> None:
        """VD070 should be in the XSS category."""
        rule = get_rule_by_id("VD070")
        assert rule.category == Category.XSS

    def test_vd080_category_is_insecure_randomness(self) -> None:
        """VD080 should be in the INSECURE_RANDOMNESS category."""
        rule = get_rule_by_id("VD080")
        assert rule.category == Category.INSECURE_RANDOMNESS

    def test_vd090_category_is_weak_cryptography(self) -> None:
        """VD090 should be in the WEAK_CRYPTOGRAPHY category."""
        rule = get_rule_by_id("VD090")
        assert rule.category == Category.WEAK_CRYPTOGRAPHY

    def test_vd030_category_is_path_traversal(self) -> None:
        """VD030 should be in the PATH_TRAVERSAL category."""
        rule = get_rule_by_id("VD030")
        assert rule.category == Category.PATH_TRAVERSAL

    def test_vd050_category_is_insecure_auth(self) -> None:
        """VD050 should be in the INSECURE_AUTH category."""
        rule = get_rule_by_id("VD050")
        assert rule.category == Category.INSECURE_AUTH
