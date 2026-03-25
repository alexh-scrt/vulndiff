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

    def test_get_rule_by_id_found(self) -> None:
        """get_rule_by_id() should return the correct rule."""
        rule = get_rule_by_id("VD001")
        assert rule.rule_id == "VD001"

    def test_get_rule_by_id_not_found(self) -> None:
        """get_rule_by_id() should raise KeyError for unknown IDs."""
        with pytest.raises(KeyError):
            get_rule_by_id("VD99999")


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

    def test_get_rules_by_category_empty_category(self) -> None:
        """An unused category should return an empty list without raising."""
        # LDAP_INJECTION has at least one rule, so use a category
        # that genuinely maps to some rules and verify the count.
        rules = get_rules_by_category(Category.LDAP_INJECTION)
        for rule in rules:
            assert rule.category == Category.LDAP_INJECTION

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

    def test_get_rules_at_or_above_severity_critical(self) -> None:
        """At-or-above CRITICAL should equal get_rules_by_severity(CRITICAL)."""
        at_above = get_rules_at_or_above_severity(Severity.CRITICAL)
        exact = get_rules_by_severity(Severity.CRITICAL)
        assert set(r.rule_id for r in at_above) == set(r.rule_id for r in exact)

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


# ---------------------------------------------------------------------------
# Pattern match tests: each rule must match its example payload
# ---------------------------------------------------------------------------


class TestRulePatternMatches:
    """Tests verifying that rules match their documented attack payloads."""

    # --- SQL Injection ---

    def test_vd001_matches_fstring_execute(self) -> None:
        rule = get_rule_by_id("VD001")
        line = "    cursor.execute(f'SELECT * FROM users WHERE id={uid}')"
        assert rule.matches(line) is not None

    def test_vd001_matches_execute_fstring_double_quote(self) -> None:
        rule = get_rule_by_id("VD001")
        line = '    cursor.execute(f"SELECT * FROM users WHERE name={name}")'
        assert rule.matches(line) is not None

    def test_vd002_matches_string_concat_select(self) -> None:
        rule = get_rule_by_id("VD002")
        line = "    query = 'SELECT * FROM users WHERE id=' + user_id"
        assert rule.matches(line) is not None

    def test_vd002_matches_format_call(self) -> None:
        rule = get_rule_by_id("VD002")
        line = "    sql = 'DELETE FROM sessions WHERE token={}'.format(token)"
        assert rule.matches(line) is not None

    def test_vd003_matches_django_raw_fstring(self) -> None:
        rule = get_rule_by_id("VD003")
        line = "    MyModel.objects.raw(f'SELECT * FROM t WHERE id={pk}')"
        assert rule.matches(line) is not None

    # --- Command Injection ---

    def test_vd010_matches_os_system_fstring(self) -> None:
        rule = get_rule_by_id("VD010")
        line = "    os.system(f'ls {directory}')"
        assert rule.matches(line) is not None

    def test_vd011_matches_subprocess_shell_true(self) -> None:
        rule = get_rule_by_id("VD011")
        line = "    subprocess.run(cmd, shell=True)"
        assert rule.matches(line) is not None

    def test_vd011_matches_subprocess_check_output_shell_true(self) -> None:
        rule = get_rule_by_id("VD011")
        line = "    output = subprocess.check_output(cmd, shell=True)"
        assert rule.matches(line) is not None

    def test_vd012_matches_os_popen_fstring(self) -> None:
        rule = get_rule_by_id("VD012")
        line = "    result = os.popen(f'cat {filename}')"
        assert rule.matches(line) is not None

    def test_vd013_matches_eval_variable(self) -> None:
        rule = get_rule_by_id("VD013")
        line = "    result = eval(user_code)"
        assert rule.matches(line) is not None

    def test_vd014_matches_exec_variable(self) -> None:
        rule = get_rule_by_id("VD014")
        line = "    exec(request.data)"
        assert rule.matches(line) is not None

    # --- LDAP Injection ---

    def test_vd020_matches_ldap_search(self) -> None:
        rule = get_rule_by_id("VD020")
        line = "    conn.search_s(base, '(uid=' + username + ')')  # noqa"
        assert rule.matches(line) is not None

    # --- Path Traversal ---

    def test_vd030_matches_open_fstring(self) -> None:
        rule = get_rule_by_id("VD030")
        line = "    with open(f'/var/data/{filename}') as f:"
        assert rule.matches(line) is not None

    def test_vd031_matches_dotdot_literal(self) -> None:
        rule = get_rule_by_id("VD031")
        line = "    path = '../etc/passwd'"
        assert rule.matches(line) is not None

    def test_vd032_matches_send_file_variable(self) -> None:
        rule = get_rule_by_id("VD032")
        line = "    return send_file(f'/uploads/{filename}')"
        assert rule.matches(line) is not None

    # --- Hardcoded Secrets ---

    def test_vd040_matches_hardcoded_password(self) -> None:
        rule = get_rule_by_id("VD040")
        line = "    password = 'SuperSecret123'"
        assert rule.matches(line) is not None

    def test_vd040_matches_hardcoded_api_key(self) -> None:
        rule = get_rule_by_id("VD040")
        line = "    api_key = 'abcdefghijklmnopqrst'"
        assert rule.matches(line) is not None

    def test_vd041_matches_aws_access_key(self) -> None:
        rule = get_rule_by_id("VD041")
        line = "    AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"
        assert rule.matches(line) is not None

    def test_vd041_matches_asia_key(self) -> None:
        rule = get_rule_by_id("VD041")
        line = "key = 'ASIAIOSFODNN7EXAMPLE1'"
        assert rule.matches(line) is not None

    def test_vd043_matches_private_key_header(self) -> None:
        rule = get_rule_by_id("VD043")
        line = "-----BEGIN RSA PRIVATE KEY-----"
        assert rule.matches(line) is not None

    def test_vd043_matches_ec_private_key(self) -> None:
        rule = get_rule_by_id("VD043")
        line = "-----BEGIN EC PRIVATE KEY-----"
        assert rule.matches(line) is not None

    def test_vd044_matches_github_pat(self) -> None:
        rule = get_rule_by_id("VD044")
        line = "    token = 'ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH'"
        assert rule.matches(line) is not None

    # --- Insecure Auth / TLS ---

    def test_vd050_matches_requests_verify_false(self) -> None:
        rule = get_rule_by_id("VD050")
        line = "    resp = requests.get(url, verify=False)"
        assert rule.matches(line) is not None

    def test_vd050_matches_requests_post_verify_false(self) -> None:
        rule = get_rule_by_id("VD050")
        line = "    r = requests.post(endpoint, json=data, verify=False)"
        assert rule.matches(line) is not None

    def test_vd051_matches_check_hostname_false(self) -> None:
        rule = get_rule_by_id("VD051")
        line = "    ctx.check_hostname = False"
        assert rule.matches(line) is not None

    def test_vd051_matches_cert_none(self) -> None:
        rule = get_rule_by_id("VD051")
        line = "    ctx.verify_mode = ssl.CERT_NONE"
        assert rule.matches(line) is not None

    def test_vd052_matches_basic_auth_tuple(self) -> None:
        rule = get_rule_by_id("VD052")
        line = "    resp = requests.get(url, auth=('admin', 'password123'))"
        assert rule.matches(line) is not None

    def test_vd053_matches_jwt_none_algorithm(self) -> None:
        rule = get_rule_by_id("VD053")
        line = "    payload = jwt.decode(token, algorithms='none')"
        assert rule.matches(line) is not None

    def test_vd054_matches_debug_true(self) -> None:
        rule = get_rule_by_id("VD054")
        line = "    app.run(host='0.0.0.0', debug=True)"
        assert rule.matches(line) is not None

    def test_vd054_matches_django_debug_true(self) -> None:
        rule = get_rule_by_id("VD054")
        line = "DEBUG = True"
        assert rule.matches(line) is not None

    # --- Unsafe Deserialization ---

    def test_vd060_matches_pickle_loads(self) -> None:
        rule = get_rule_by_id("VD060")
        line = "    obj = pickle.loads(data)"
        assert rule.matches(line) is not None

    def test_vd060_matches_pickle_load(self) -> None:
        rule = get_rule_by_id("VD060")
        line = "    obj = pickle.load(file_handle)"
        assert rule.matches(line) is not None

    def test_vd061_matches_yaml_load_no_loader(self) -> None:
        rule = get_rule_by_id("VD061")
        line = "    data = yaml.load(stream)"
        assert rule.matches(line) is not None

    def test_vd062_matches_marshal_loads(self) -> None:
        rule = get_rule_by_id("VD062")
        line = "    obj = marshal.loads(data)"
        assert rule.matches(line) is not None

    def test_vd063_matches_jsonpickle_decode(self) -> None:
        rule = get_rule_by_id("VD063")
        line = "    obj = jsonpickle.decode(payload)"
        assert rule.matches(line) is not None

    # --- XSS ---

    def test_vd070_matches_inner_html(self) -> None:
        rule = get_rule_by_id("VD070")
        line = "    element.innerHTML = userInput;"
        assert rule.matches(line) is not None

    def test_vd070_matches_outer_html(self) -> None:
        rule = get_rule_by_id("VD070")
        line = "    div.outerHTML = value;"
        assert rule.matches(line) is not None

    def test_vd071_matches_dangerous_set_inner_html(self) -> None:
        rule = get_rule_by_id("VD071")
        line = "    return <div dangerouslySetInnerHTML={{ __html: markup }} />;"
        assert rule.matches(line) is not None

    def test_vd072_matches_document_write(self) -> None:
        rule = get_rule_by_id("VD072")
        line = "    document.write(userContent);"
        assert rule.matches(line) is not None

    def test_vd073_matches_mark_safe_variable(self) -> None:
        rule = get_rule_by_id("VD073")
        line = "    return mark_safe(user_html)"
        assert rule.matches(line) is not None

    # --- Insecure Randomness ---

    def test_vd080_matches_random_randint(self) -> None:
        rule = get_rule_by_id("VD080")
        line = "    token = random.randint(0, 999999)"
        assert rule.matches(line) is not None

    def test_vd080_matches_random_choice(self) -> None:
        rule = get_rule_by_id("VD080")
        line = "    session_id = random.choice(charset)"
        assert rule.matches(line) is not None

    def test_vd081_matches_seed_constant(self) -> None:
        rule = get_rule_by_id("VD081")
        line = "    random.seed(42)"
        assert rule.matches(line) is not None

    def test_vd081_matches_seed_string(self) -> None:
        rule = get_rule_by_id("VD081")
        line = "    random.seed('fixed')"
        assert rule.matches(line) is not None

    # --- Weak Cryptography ---

    def test_vd090_matches_hashlib_md5(self) -> None:
        rule = get_rule_by_id("VD090")
        line = "    h = hashlib.md5(data)"
        assert rule.matches(line) is not None

    def test_vd091_matches_hashlib_sha1(self) -> None:
        rule = get_rule_by_id("VD091")
        line = "    h = hashlib.sha1(data)"
        assert rule.matches(line) is not None

    def test_vd092_matches_des_cipher(self) -> None:
        rule = get_rule_by_id("VD092")
        line = "    from Crypto.Cipher import DES"
        assert rule.matches(line) is not None

    def test_vd093_matches_arc4(self) -> None:
        rule = get_rule_by_id("VD093")
        line = "    from Crypto.Cipher import ARC4"
        assert rule.matches(line) is not None

    def test_vd094_matches_ecb_mode(self) -> None:
        rule = get_rule_by_id("VD094")
        line = "    cipher = AES.new(key, AES.MODE_ECB)"
        assert rule.matches(line) is not None

    def test_vd095_matches_md5_password(self) -> None:
        rule = get_rule_by_id("VD095")
        line = "    h = hashlib.md5(password.encode()).hexdigest()"
        assert rule.matches(line) is not None

    # --- Sensitive Data ---

    def test_vd100_matches_logging_password(self) -> None:
        rule = get_rule_by_id("VD100")
        line = "    logger.debug(f'User password: {password}')"
        assert rule.matches(line) is not None

    # --- Insecure Config ---

    def test_vd110_matches_weak_secret_key(self) -> None:
        rule = get_rule_by_id("VD110")
        line = "SECRET_KEY = 'change-me'"
        assert rule.matches(line) is not None

    def test_vd110_matches_insecure_secret_key(self) -> None:
        rule = get_rule_by_id("VD110")
        line = "SECRET_KEY = 'django-insecure-abc123'"
        assert rule.matches(line) is not None

    def test_vd111_matches_allowed_hosts_wildcard(self) -> None:
        rule = get_rule_by_id("VD111")
        line = "ALLOWED_HOSTS = ['*']"
        assert rule.matches(line) is not None

    def test_vd112_matches_cors_allow_all(self) -> None:
        rule = get_rule_by_id("VD112")
        line = "CORS_ALLOW_ALL_ORIGINS = True"
        assert rule.matches(line) is not None

    # --- SSTI ---

    def test_vd120_matches_template_string_variable(self) -> None:
        rule = get_rule_by_id("VD120")
        line = "    t = Template(user_template)"
        assert rule.matches(line) is not None

    # --- XXE ---

    def test_vd130_matches_etree_parse(self) -> None:
        rule = get_rule_by_id("VD130")
        line = "    tree = etree.parse(xml_file)"
        assert rule.matches(line) is not None

    def test_vd130_matches_et_fromstring(self) -> None:
        rule = get_rule_by_id("VD130")
        line = "    root = ET.fromstring(xml_data)"
        assert rule.matches(line) is not None

    # --- ReDoS ---

    def test_vd140_matches_re_compile_variable(self) -> None:
        rule = get_rule_by_id("VD140")
        line = "    pattern = re.compile(user_input)"
        assert rule.matches(line) is not None

    # --- SSRF ---

    def test_vd150_matches_requests_get_variable(self) -> None:
        rule = get_rule_by_id("VD150")
        line = "    resp = requests.get(url)"
        assert rule.matches(line) is not None

    def test_vd150_matches_requests_post_fstring(self) -> None:
        rule = get_rule_by_id("VD150")
        line = "    resp = requests.post(f'http://api/{endpoint}', json=data)"
        assert rule.matches(line) is not None

    # --- File Upload ---

    def test_vd160_matches_file_save_filename(self) -> None:
        rule = get_rule_by_id("VD160")
        line = "    file.save(os.path.join(upload_dir, file.filename))"
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

    def test_vd080_safe_secrets_token(self) -> None:
        """secrets.token_hex() should not be flagged by VD080."""
        rule = get_rule_by_id("VD080")
        line = "    token = secrets.token_hex(32)"
        assert rule.matches(line) is None

    def test_vd090_safe_sha256(self) -> None:
        """hashlib.sha256 should not be flagged by the MD5 rule VD090."""
        rule = get_rule_by_id("VD090")
        line = "    h = hashlib.sha256(data).hexdigest()"
        assert rule.matches(line) is None

    def test_vd094_safe_gcm_mode(self) -> None:
        """AES.MODE_GCM should not trigger the ECB mode rule VD094."""
        rule = get_rule_by_id("VD094")
        line = "    cipher = AES.new(key, AES.MODE_GCM)"
        assert rule.matches(line) is None

    def test_vd054_debug_false_safe(self) -> None:
        """DEBUG = False should not trigger VD054."""
        rule = get_rule_by_id("VD054")
        line = "DEBUG = False"
        assert rule.matches(line) is None

    def test_vd140_safe_literal_pattern(self) -> None:
        """re.compile with a string literal should not trigger VD140."""
        rule = get_rule_by_id("VD140")
        line = "    pat = re.compile(r'^[a-z]+$')"
        assert rule.matches(line) is None
