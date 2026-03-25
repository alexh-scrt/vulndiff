"""Vulnerability rule definitions for vulndiff.

This module provides the complete curated rule set used by the vulndiff scanner.
Rules cover OWASP Top 10 categories, common injection flaws, hardcoded secrets,
authentication issues, path traversal, and unsafe deserialization.

Each rule is a :class:`~vulndiff.models.Rule` instance with a compiled regex
pattern, severity, category, and remediation guidance.

Usage::

    from vulndiff.rules import get_all_rules, get_rules_by_category
    from vulndiff.models import Category

    rules = get_all_rules()
    injection_rules = get_rules_by_category(Category.SQL_INJECTION)

The module-level constant :data:`ALL_RULES` is a tuple of all rules in
definition order.  Use :func:`get_all_rules` to get a fresh list copy.
"""

from __future__ import annotations

import re
from typing import List

from vulndiff.models import Category, Rule, Severity

# ---------------------------------------------------------------------------
# SQL Injection rules
# ---------------------------------------------------------------------------

_SQL_INJECTION_FSTRING = Rule(
    rule_id="VD001",
    name="SQL Injection via f-string or % formatting",
    description=(
        "A SQL query is constructed by embedding variables directly into the query "
        "string using an f-string or %-formatting. This allows an attacker to "
        "manipulate the query structure and execute arbitrary SQL commands."
    ),
    category=Category.SQL_INJECTION,
    severity=Severity.CRITICAL,
    pattern=re.compile(
        r"(?i)"
        r"(?:execute|executemany|cursor\.execute|db\.execute|conn\.execute|engine\.execute)"
        r"\s*\("
        r"\s*(?:f['\"]|['\"].*%[^)]*%|f\"\"\"|f'')",
        re.IGNORECASE,
    ),
    recommendation=(
        "Use parameterised queries or prepared statements instead. Pass user input "
        "as parameters, e.g.: cursor.execute('SELECT * FROM t WHERE id=%s', (uid,))"
    ),
    cwe_id="CWE-89",
    owasp_id="A03:2021",
    references=[
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    ],
    tags=["sql", "injection", "owasp-a03"],
)

_SQL_INJECTION_CONCAT = Rule(
    rule_id="VD002",
    name="SQL Injection via string concatenation",
    description=(
        "A SQL query string is assembled by concatenating variables with the + "
        "operator or .format() calls. This pattern is a classic vector for "
        "SQL injection when any part of the query is user-controlled."
    ),
    category=Category.SQL_INJECTION,
    severity=Severity.CRITICAL,
    pattern=re.compile(
        r"(?i)"
        r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|REPLACE|UNION)"
        r".{0,120}"
        r"(?:\+\s*(?:str\()?[a-zA-Z_][a-zA-Z0-9_.]*|['\"]\s*\+|format\s*\()",
        re.IGNORECASE,
    ),
    recommendation=(
        "Never construct SQL strings by concatenation. Use parameterised queries "
        "or an ORM (e.g. SQLAlchemy) that handles escaping automatically."
    ),
    cwe_id="CWE-89",
    owasp_id="A03:2021",
    references=[
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    ],
    tags=["sql", "injection", "owasp-a03"],
)

_SQL_INJECTION_RAW_QUERY = Rule(
    rule_id="VD003",
    name="Django/SQLAlchemy raw SQL with variable interpolation",
    description=(
        "A call to a raw-SQL helper (raw(), text(), RawSQL()) includes an f-string "
        "or string concatenation, bypassing ORM parameterisation protections."
    ),
    category=Category.SQL_INJECTION,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"(?:raw|text|RawSQL|execute_sql|raw_query)\s*\("
        r"\s*(?:f['\"]|['\"].*\+|\".*\\{)",
        re.IGNORECASE,
    ),
    recommendation=(
        "Pass user input through the ORM parameter mechanism rather than "
        "interpolating it into the raw SQL string."
    ),
    cwe_id="CWE-89",
    owasp_id="A03:2021",
    references=[
        "https://docs.djangoproject.com/en/stable/ref/models/expressions/#raw-sql-expressions",
    ],
    tags=["sql", "injection", "django", "sqlalchemy", "owasp-a03"],
)

# ---------------------------------------------------------------------------
# Command Injection rules
# ---------------------------------------------------------------------------

_CMD_INJECTION_OS_SYSTEM = Rule(
    rule_id="VD010",
    name="Command Injection via os.system()",
    description=(
        "os.system() is called with a value that appears to include a variable "
        "(f-string, concatenation, or format call). Passing unsanitised user input "
        "to os.system() allows arbitrary OS command execution."
    ),
    category=Category.COMMAND_INJECTION,
    severity=Severity.CRITICAL,
    pattern=re.compile(
        r"os\.system\s*\("
        r"\s*(?:f['\"]|[^)]*\+|[^)]*\.format\s*\()",
        re.IGNORECASE,
    ),
    recommendation=(
        "Use subprocess.run() with a list argument (not shell=True) and never "
        "pass user-controlled data directly to a shell command."
    ),
    cwe_id="CWE-78",
    owasp_id="A03:2021",
    references=[
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://docs.python.org/3/library/subprocess.html#security-considerations",
    ],
    tags=["command-injection", "os", "owasp-a03"],
)

_CMD_INJECTION_SUBPROCESS_SHELL = Rule(
    rule_id="VD011",
    name="Command Injection via subprocess with shell=True",
    description=(
        "A subprocess call uses shell=True, which causes the command to be "
        "executed through the system shell. Combined with any variable input this "
        "enables shell injection attacks."
    ),
    category=Category.COMMAND_INJECTION,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"(?:subprocess\.(?:run|call|check_output|check_call|Popen)|popen)\s*\("
        r"[^)]*shell\s*=\s*True",
        re.IGNORECASE,
    ),
    recommendation=(
        "Pass the command as a list of arguments and set shell=False (the default). "
        "If shell=True is unavoidable, use shlex.quote() on all user-supplied values."
    ),
    cwe_id="CWE-78",
    owasp_id="A03:2021",
    references=[
        "https://docs.python.org/3/library/subprocess.html#security-considerations",
    ],
    tags=["command-injection", "subprocess", "owasp-a03"],
)

_CMD_INJECTION_POPEN = Rule(
    rule_id="VD012",
    name="Command Injection via os.popen()",
    description=(
        "os.popen() opens a pipe to a shell command. If the command string "
        "contains variables, this may allow arbitrary command execution."
    ),
    category=Category.COMMAND_INJECTION,
    severity=Severity.CRITICAL,
    pattern=re.compile(
        r"os\.popen\s*\("
        r"\s*(?:f['\"]|[^)]*\+|[^)]*\.format\s*\()",
        re.IGNORECASE,
    ),
    recommendation=(
        "Replace os.popen() with subprocess.run() and pass the command as a list "
        "without shell=True."
    ),
    cwe_id="CWE-78",
    owasp_id="A03:2021",
    references=[
        "https://docs.python.org/3/library/os.html#os.popen",
    ],
    tags=["command-injection", "os", "owasp-a03"],
)

_CMD_INJECTION_EVAL = Rule(
    rule_id="VD013",
    name="Code Injection via eval()",
    description=(
        "eval() executes arbitrary Python expressions. Calling it with any "
        "non-literal argument (variable, f-string, user input) is a critical "
        "code-injection vulnerability."
    ),
    category=Category.CODE_INJECTION,
    severity=Severity.CRITICAL,
    pattern=re.compile(
        r"\beval\s*\(\s*(?!(?:['\"].*['\"]|b['\"].*['\"]|rb['\"].*['\"])\s*\))",
        re.IGNORECASE,
    ),
    recommendation=(
        "Never call eval() with user-controlled input. Use ast.literal_eval() for "
        "safe parsing of Python literals, or redesign to avoid dynamic evaluation."
    ),
    cwe_id="CWE-94",
    owasp_id="A03:2021",
    references=[
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://docs.python.org/3/library/functions.html#eval",
    ],
    tags=["code-injection", "eval", "owasp-a03"],
)

_CMD_INJECTION_EXEC = Rule(
    rule_id="VD014",
    name="Code Injection via exec()",
    description=(
        "exec() executes arbitrary Python code. Using it with any variable "
        "or user-supplied string constitutes a critical code injection risk."
    ),
    category=Category.CODE_INJECTION,
    severity=Severity.CRITICAL,
    pattern=re.compile(
        r"\bexec\s*\(\s*(?!(?:['\"].*['\"]|b['\"].*['\"])\s*\))",
        re.IGNORECASE,
    ),
    recommendation=(
        "Avoid exec() with any external or user-controlled data. "
        "Refactor the logic to not require dynamic code execution."
    ),
    cwe_id="CWE-94",
    owasp_id="A03:2021",
    references=[
        "https://owasp.org/Top10/A03_2021-Injection/",
    ],
    tags=["code-injection", "exec", "owasp-a03"],
)

# ---------------------------------------------------------------------------
# LDAP Injection rules
# ---------------------------------------------------------------------------

_LDAP_INJECTION = Rule(
    rule_id="VD020",
    name="LDAP Injection via unsanitised filter construction",
    description=(
        "An LDAP search filter string is assembled by embedding variables directly. "
        "Special LDAP characters in user input can alter the filter logic and allow "
        "unauthorised data access or authentication bypass."
    ),
    category=Category.LDAP_INJECTION,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"(?:search_s|search|search_ext_s)\s*\("
        r"[^)]*(?:f['\"]|\+|%s|format\s*\().*?\)",
        re.IGNORECASE | re.DOTALL,
    ),
    recommendation=(
        "Escape all user-supplied values using a proper LDAP escaping function "
        "(e.g. ldap3's escape_filter_chars) before inserting them into filter strings."
    ),
    cwe_id="CWE-90",
    owasp_id="A03:2021",
    references=[
        "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
    ],
    tags=["ldap", "injection", "owasp-a03"],
)

# ---------------------------------------------------------------------------
# Path Traversal rules
# ---------------------------------------------------------------------------

_PATH_TRAVERSAL_OPEN = Rule(
    rule_id="VD030",
    name="Path Traversal via open() with variable path",
    description=(
        "open() is called with a path that appears to contain a variable. "
        "Without validation, user-supplied paths can traverse outside the "
        "intended directory using sequences like '../'."
    ),
    category=Category.PATH_TRAVERSAL,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"\bopen\s*\("
        r"\s*(?:f['\"]|[a-zA-Z_][a-zA-Z0-9_.]*\s*[+,]|os\.path\.join\s*\([^)]*(?:request|input|param|arg|user))",
        re.IGNORECASE,
    ),
    recommendation=(
        "Validate and sanitise file paths before use. Use os.path.realpath() "
        "to resolve the canonical path and confirm it starts with the intended "
        "base directory. Consider using pathlib for safer path manipulation."
    ),
    cwe_id="CWE-22",
    owasp_id="A01:2021",
    references=[
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
    ],
    tags=["path-traversal", "owasp-a01"],
)

_PATH_TRAVERSAL_DOTDOT = Rule(
    rule_id="VD031",
    name="Path Traversal pattern '../' in string literal",
    description=(
        "A string literal contains a '../' sequence, which may indicate "
        "a hard-coded directory traversal attempt or insufficient sanitisation "
        "of user-supplied path components."
    ),
    category=Category.PATH_TRAVERSAL,
    severity=Severity.MEDIUM,
    pattern=re.compile(
        r"['\"].*\.\./.*['\"|]",
        re.IGNORECASE,
    ),
    recommendation=(
        "Reject or strip '../' sequences from any user-supplied path. "
        "Use os.path.realpath() and check the resolved path is within the "
        "allowed base directory."
    ),
    cwe_id="CWE-22",
    owasp_id="A01:2021",
    references=[
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    ],
    tags=["path-traversal", "owasp-a01"],
)

_PATH_TRAVERSAL_SEND_FILE = Rule(
    rule_id="VD032",
    name="Path Traversal via send_file / send_from_directory with variable",
    description=(
        "Flask's send_file() or send_from_directory() is called with a variable "
        "that may be user-supplied. This can expose arbitrary files on the server."
    ),
    category=Category.PATH_TRAVERSAL,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"(?:send_file|send_from_directory)\s*\("
        r"\s*(?:f['\"]|[a-zA-Z_][a-zA-Z0-9_.]*(?:\s*[+,]))",
        re.IGNORECASE,
    ),
    recommendation=(
        "Always use send_from_directory() with a fixed, trusted directory argument "
        "and validate the filename against an allowlist."
    ),
    cwe_id="CWE-22",
    owasp_id="A01:2021",
    references=[
        "https://flask.palletsprojects.com/en/latest/api/#flask.send_file",
    ],
    tags=["path-traversal", "flask", "owasp-a01"],
)

# ---------------------------------------------------------------------------
# Hardcoded Secrets rules
# ---------------------------------------------------------------------------

_SECRET_HARDCODED_PASSWORD = Rule(
    rule_id="VD040",
    name="Hardcoded password or secret in assignment",
    description=(
        "A variable whose name suggests it holds a password, secret, or key is "
        "assigned a non-empty string literal. Hardcoded credentials can be "
        "extracted from source code and version control history."
    ),
    category=Category.HARDCODED_SECRET,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"(?i)"
        r"(?:password|passwd|secret|api_key|apikey|auth_token|authtoken"
        r"|access_token|private_key|client_secret|db_pass|database_password"
        r"|secret_key|app_secret)\s*=\s*['\"][^'\"\s]{4,}['\"])",
        re.IGNORECASE,
    ),
    recommendation=(
        "Load secrets from environment variables, a secrets manager (e.g. AWS "
        "Secrets Manager, HashiCorp Vault), or a .env file that is excluded from "
        "version control. Never commit plaintext credentials."
    ),
    cwe_id="CWE-798",
    owasp_id="A07:2021",
    references=[
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
    ],
    tags=["hardcoded-secret", "credentials", "owasp-a07"],
)

_SECRET_AWS_KEY = Rule(
    rule_id="VD041",
    name="Hardcoded AWS Access Key ID",
    description=(
        "An AWS Access Key ID pattern (AKIA… or ASIA…) is present in the code. "
        "AWS credentials committed to source control can be harvested by automated "
        "scanners and used to compromise cloud infrastructure."
    ),
    category=Category.HARDCODED_SECRET,
    severity=Severity.CRITICAL,
    pattern=re.compile(
        r"(?:AKIA|ASIA|AROA|AIDA|ANPA|ANVA|APKA)[A-Z0-9]{16}",
    ),
    recommendation=(
        "Rotate the exposed key immediately. Use IAM roles or environment variables "
        "for AWS credentials. Add a pre-commit hook to prevent future commits."
    ),
    cwe_id="CWE-798",
    owasp_id="A07:2021",
    references=[
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
    ],
    tags=["hardcoded-secret", "aws", "cloud", "owasp-a07"],
)

_SECRET_GENERIC_TOKEN = Rule(
    rule_id="VD042",
    name="Hardcoded API token or bearer token",
    description=(
        "A variable or argument whose name contains 'token', 'bearer', or 'api_key' "
        "is assigned a long alphanumeric literal that resembles a real secret token."
    ),
    category=Category.HARDCODED_SECRET,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"(?i)(?:token|bearer|api[_-]?key|auth[_-]?key)\s*[=:]\s*['\"][A-Za-z0-9\-_\.]{20,}['\"])",
        re.IGNORECASE,
    ),
    recommendation=(
        "Store tokens in environment variables or a secrets manager. "
        "Rotate any exposed tokens immediately."
    ),
    cwe_id="CWE-798",
    owasp_id="A07:2021",
    references=[
        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
    ],
    tags=["hardcoded-secret", "token", "owasp-a07"],
)

_SECRET_PRIVATE_KEY_HEADER = Rule(
    rule_id="VD043",
    name="Private key material in source code",
    description=(
        "A PEM private key header ('BEGIN PRIVATE KEY', 'BEGIN RSA PRIVATE KEY', "
        "etc.) is present in the code. Including private key material in source "
        "files exposes it to anyone with repository access."
    ),
    category=Category.HARDCODED_SECRET,
    severity=Severity.CRITICAL,
    pattern=re.compile(
        r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|ENCRYPTED\s+)?PRIVATE KEY-----",
    ),
    recommendation=(
        "Remove the private key from the repository immediately and rotate it. "
        "Store private keys in a secure vault or as environment variables, never "
        "in source code."
    ),
    cwe_id="CWE-321",
    owasp_id="A02:2021",
    references=[
        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    ],
    tags=["hardcoded-secret", "private-key", "pem", "owasp-a02"],
)

_SECRET_GITHUB_TOKEN = Rule(
    rule_id="VD044",
    name="Hardcoded GitHub personal access token",
    description=(
        "A GitHub personal access token (ghp_, gho_, ghu_, ghs_, or ghr_ prefix) "
        "is present in the code. These tokens grant access to GitHub repositories "
        "and should never be stored in source code."
    ),
    category=Category.HARDCODED_SECRET,
    severity=Severity.CRITICAL,
    pattern=re.compile(
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b",
    ),
    recommendation=(
        "Revoke the token immediately on GitHub. Use environment variables or a "
        "secrets manager to supply tokens at runtime."
    ),
    cwe_id="CWE-798",
    owasp_id="A07:2021",
    references=[
        "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
    ],
    tags=["hardcoded-secret", "github", "token", "owasp-a07"],
)

# ---------------------------------------------------------------------------
# Insecure Authentication / TLS rules
# ---------------------------------------------------------------------------

_AUTH_SSL_VERIFY_FALSE = Rule(
    rule_id="VD050",
    name="TLS certificate verification disabled (verify=False)",
    description=(
        "An HTTP request is made with verify=False, which disables TLS certificate "
        "validation. This makes the connection vulnerable to man-in-the-middle attacks "
        "because the server's identity is not verified."
    ),
    category=Category.INSECURE_AUTH,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"(?:requests\.(?:get|post|put|patch|delete|head|options|request)|session\.(?:get|post|put|patch|delete|head|options|request))\s*\("
        r"[^)]*verify\s*=\s*False",
        re.IGNORECASE | re.DOTALL,
    ),
    recommendation=(
        "Remove verify=False. If you need a custom CA bundle, pass the path to "
        "the CA file as verify='/path/to/ca-bundle.crt'. Never disable certificate "
        "verification in production code."
    ),
    cwe_id="CWE-295",
    owasp_id="A02:2021",
    references=[
        "https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification",
        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    ],
    tags=["insecure-auth", "tls", "ssl", "owasp-a02"],
)

_AUTH_SSL_CONTEXT_NO_VERIFY = Rule(
    rule_id="VD051",
    name="SSL context with certificate verification disabled",
    description=(
        "An ssl.SSLContext is created and check_hostname or verify_mode is set "
        "to disable certificate verification, removing protection against "
        "man-in-the-middle attacks."
    ),
    category=Category.INSECURE_AUTH,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"(?:check_hostname\s*=\s*False|verify_mode\s*=\s*ssl\.CERT_NONE)",
        re.IGNORECASE,
    ),
    recommendation=(
        "Use the default SSL context created by ssl.create_default_context() which "
        "has certificate verification enabled. Never disable check_hostname or "
        "set verify_mode to CERT_NONE in production."
    ),
    cwe_id="CWE-295",
    owasp_id="A02:2021",
    references=[
        "https://docs.python.org/3/library/ssl.html",
    ],
    tags=["insecure-auth", "tls", "ssl", "owasp-a02"],
)

_AUTH_HARDCODED_BASIC_AUTH = Rule(
    rule_id="VD052",
    name="Hardcoded HTTP Basic Auth credentials",
    description=(
        "HTTP Basic Auth credentials are passed as a literal tuple or string. "
        "Committing usernames and passwords in source code exposes them to anyone "
        "with repository access."
    ),
    category=Category.INSECURE_AUTH,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"auth\s*=\s*\(\s*['\"][^'\"]+['\"]\s*,\s*['\"][^'\"]+['\"]\s*\)",
        re.IGNORECASE,
    ),
    recommendation=(
        "Load credentials from environment variables or a secrets manager. "
        "Use os.environ.get('USERNAME') and os.environ.get('PASSWORD')."
    ),
    cwe_id="CWE-798",
    owasp_id="A07:2021",
    references=[
        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
    ],
    tags=["hardcoded-secret", "basic-auth", "owasp-a07"],
)

_AUTH_JWT_NONE_ALG = Rule(
    rule_id="VD053",
    name="JWT algorithm set to 'none'",
    description=(
        "A JWT is decoded or verified with algorithm='none', which disables "
        "signature verification entirely and allows forged tokens to be accepted."
    ),
    category=Category.INSECURE_AUTH,
    severity=Severity.CRITICAL,
    pattern=re.compile(
        r"(?:decode|verify)\s*\([^)]*algorithms?\s*=\s*['\"]none['\"])",
        re.IGNORECASE,
    ),
    recommendation=(
        "Always specify a strong algorithm such as HS256 or RS256. "
        "Never accept 'none' as a valid JWT algorithm."
    ),
    cwe_id="CWE-347",
    owasp_id="A02:2021",
    references=[
        "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
    ],
    tags=["insecure-auth", "jwt", "owasp-a02"],
)

_AUTH_DEBUG_TRUE = Rule(
    rule_id="VD054",
    name="Debug mode enabled in production framework",
    description=(
        "A web framework (Django, Flask) is started with DEBUG=True or debug=True. "
        "Debug mode exposes stack traces, environment variables, and interactive "
        "debuggers to anyone who triggers an error."
    ),
    category=Category.INSECURE_CONFIGURATION,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"(?:DEBUG\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True)",
        re.IGNORECASE,
    ),
    recommendation=(
        "Set DEBUG=False in production. Control the debug flag via an environment "
        "variable: DEBUG = os.environ.get('DEBUG', 'False') == 'True'"
    ),
    cwe_id="CWE-215",
    owasp_id="A05:2021",
    references=[
        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "https://docs.djangoproject.com/en/stable/ref/settings/#debug",
    ],
    tags=["insecure-config", "debug", "flask", "django", "owasp-a05"],
)

# ---------------------------------------------------------------------------
# Unsafe Deserialization rules
# ---------------------------------------------------------------------------

_DESER_PICKLE_LOADS = Rule(
    rule_id="VD060",
    name="Unsafe deserialization via pickle.loads()",
    description=(
        "pickle.loads() deserialises Python objects from a byte string. "
        "Deserialising data from an untrusted source allows an attacker to "
        "execute arbitrary code during the deserialization process."
    ),
    category=Category.UNSAFE_DESERIALIZATION,
    severity=Severity.CRITICAL,
    pattern=re.compile(
        r"\bpickle\.(?:loads|load|Unpickler)\s*\(",
        re.IGNORECASE,
    ),
    recommendation=(
        "Never deserialise pickle data from untrusted sources. Use a safer "
        "format such as JSON. If pickle is necessary, sign and verify the data "
        "with HMAC before deserialising."
    ),
    cwe_id="CWE-502",
    owasp_id="A08:2021",
    references=[
        "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        "https://docs.python.org/3/library/pickle.html#restricting-globals",
    ],
    tags=["deserialization", "pickle", "owasp-a08"],
)

_DESER_YAML_LOAD = Rule(
    rule_id="VD061",
    name="Unsafe YAML deserialization via yaml.load() without safe Loader",
    description=(
        "yaml.load() without an explicit Loader argument (or with "
        "Loader=yaml.Loader / Loader=yaml.UnsafeLoader) can execute arbitrary "
        "Python code present in the YAML document."
    ),
    category=Category.UNSAFE_DESERIALIZATION,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"yaml\.load\s*\("
        r"(?!\s*[^,)]+,\s*Loader\s*=\s*yaml\.(?:SafeLoader|CSafeLoader))",
        re.IGNORECASE,
    ),
    recommendation=(
        "Use yaml.safe_load() instead of yaml.load(), or explicitly pass "
        "Loader=yaml.SafeLoader: yaml.load(data, Loader=yaml.SafeLoader)."
    ),
    cwe_id="CWE-502",
    owasp_id="A08:2021",
    references=[
        "https://pyyaml.org/wiki/PyYAMLDocumentation",
        "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    ],
    tags=["deserialization", "yaml", "owasp-a08"],
)

_DESER_MARSHAL = Rule(
    rule_id="VD062",
    name="Unsafe deserialization via marshal module",
    description=(
        "The marshal module deserialises Python code objects and can execute "
        "arbitrary code when fed untrusted input. Its use for anything other "
        "than trusted internal Python bytecode is dangerous."
    ),
    category=Category.UNSAFE_DESERIALIZATION,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"\bmarshal\.(?:loads|load)\s*\(",
        re.IGNORECASE,
    ),
    recommendation=(
        "Replace marshal with a safe serialisation format such as JSON. "
        "Never deserialise marshal data from untrusted sources."
    ),
    cwe_id="CWE-502",
    owasp_id="A08:2021",
    references=[
        "https://docs.python.org/3/library/marshal.html",
    ],
    tags=["deserialization", "marshal", "owasp-a08"],
)

_DESER_JSONPICKLE = Rule(
    rule_id="VD063",
    name="Unsafe deserialization via jsonpickle.decode()",
    description=(
        "jsonpickle.decode() can deserialise arbitrary Python objects and execute "
        "code embedded in the JSON payload. It should not be used with untrusted input."
    ),
    category=Category.UNSAFE_DESERIALIZATION,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"\bjsonpickle\.decode\s*\(",
        re.IGNORECASE,
    ),
    recommendation=(
        "Use the standard json module for deserialising untrusted data. "
        "If jsonpickle is required, set classes=None and validate the input schema "
        "before decoding."
    ),
    cwe_id="CWE-502",
    owasp_id="A08:2021",
    references=[
        "https://jsonpickle.github.io/",
    ],
    tags=["deserialization", "jsonpickle", "owasp-a08"],
)

# ---------------------------------------------------------------------------
# XSS rules
# ---------------------------------------------------------------------------

_XSS_INNER_HTML = Rule(
    rule_id="VD070",
    name="XSS via innerHTML assignment",
    description=(
        "A value is assigned to element.innerHTML or outerHTML. If the value "
        "contains user-controlled data, this can inject malicious HTML/JavaScript "
        "into the page, resulting in Cross-Site Scripting (XSS)."
    ),
    category=Category.XSS,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"\.(?:innerHTML|outerHTML)\s*=",
        re.IGNORECASE,
    ),
    recommendation=(
        "Use textContent or innerText to set plain text, or use a sanitisation "
        "library (e.g. DOMPurify) before assigning to innerHTML. Never insert "
        "raw user input into innerHTML."
    ),
    cwe_id="CWE-79",
    owasp_id="A03:2021",
    references=[
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ],
    tags=["xss", "javascript", "owasp-a03"],
)

_XSS_DANGEROUS_SET_HTML = Rule(
    rule_id="VD071",
    name="XSS via dangerouslySetInnerHTML (React)",
    description=(
        "React's dangerouslySetInnerHTML prop is used, which bypasses React's "
        "automatic escaping. If the __html value contains user input, this leads "
        "to XSS."
    ),
    category=Category.XSS,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html",
        re.IGNORECASE,
    ),
    recommendation=(
        "Sanitise HTML with DOMPurify before passing it to dangerouslySetInnerHTML. "
        "Prefer rendering plain text via React's standard data binding whenever possible."
    ),
    cwe_id="CWE-79",
    owasp_id="A03:2021",
    references=[
        "https://react.dev/reference/react-dom/components/common#dangerouslysetinnerhtml",
    ],
    tags=["xss", "react", "javascript", "owasp-a03"],
)

_XSS_DOCUMENT_WRITE = Rule(
    rule_id="VD072",
    name="XSS via document.write()",
    description=(
        "document.write() inserts raw HTML into the page. When the argument "
        "contains user-supplied data this creates a Cross-Site Scripting vector."
    ),
    category=Category.XSS,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"document\.write\s*\(",
        re.IGNORECASE,
    ),
    recommendation=(
        "Avoid document.write(). Use DOM manipulation methods such as "
        "document.createElement() combined with textContent, or use a templating "
        "library that auto-escapes output."
    ),
    cwe_id="CWE-79",
    owasp_id="A03:2021",
    references=[
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ],
    tags=["xss", "javascript", "owasp-a03"],
)

_XSS_PYTHON_MARK_SAFE = Rule(
    rule_id="VD073",
    name="XSS via Django mark_safe() or Markup() with variable",
    description=(
        "Django's mark_safe() or Jinja2/MarkupSafe's Markup() is called with a "
        "variable argument. These functions tell the template engine to trust the "
        "value as safe HTML, bypassing auto-escaping. If the value contains "
        "user input, XSS results."
    ),
    category=Category.XSS,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"(?:mark_safe|Markup)\s*\(\s*(?!(?:['\"].*['\"])\s*\))",
        re.IGNORECASE,
    ),
    recommendation=(
        "Only pass string literals to mark_safe()/Markup(). "
        "Escape user-supplied values with django.utils.html.escape() or "
        "markupsafe.escape() before marking them safe."
    ),
    cwe_id="CWE-79",
    owasp_id="A03:2021",
    references=[
        "https://docs.djangoproject.com/en/stable/ref/utils/#django.utils.safestring.mark_safe",
    ],
    tags=["xss", "django", "jinja2", "python", "owasp-a03"],
)

# ---------------------------------------------------------------------------
# Insecure Randomness rules
# ---------------------------------------------------------------------------

_RANDOM_INSECURE = Rule(
    rule_id="VD080",
    name="Insecure random number generation for security-sensitive use",
    description=(
        "The random module (random.random(), random.randint(), random.choice(), etc.) "
        "uses a Mersenne Twister PRNG that is not cryptographically secure. "
        "Using it for passwords, tokens, session IDs, or other security-sensitive "
        "values makes them predictable."
    ),
    category=Category.INSECURE_RANDOMNESS,
    severity=Severity.MEDIUM,
    pattern=re.compile(
        r"\brandom\.(?:random|randint|randrange|choice|choices|shuffle|sample|uniform)\s*\(",
        re.IGNORECASE,
    ),
    recommendation=(
        "Use the secrets module for security-sensitive random values: "
        "secrets.token_hex(), secrets.token_urlsafe(), secrets.choice(). "
        "Or use os.urandom() for raw bytes."
    ),
    cwe_id="CWE-338",
    owasp_id="A02:2021",
    references=[
        "https://docs.python.org/3/library/secrets.html",
        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    ],
    tags=["insecure-randomness", "crypto", "owasp-a02"],
)

_RANDOM_SEED = Rule(
    rule_id="VD081",
    name="Predictable random seed",
    description=(
        "random.seed() is called with a constant or predictable value. "
        "A predictable seed makes all subsequent random values reproducible "
        "by an attacker who knows or guesses the seed."
    ),
    category=Category.INSECURE_RANDOMNESS,
    severity=Severity.MEDIUM,
    pattern=re.compile(
        r"\brandom\.seed\s*\(\s*(?:\d+|['\"][^'\"]*['\"])\s*\)",
        re.IGNORECASE,
    ),
    recommendation=(
        "If you need reproducible sequences for testing, use a clearly marked "
        "test-only path. For production, never seed with a constant. "
        "Use the secrets module for security-sensitive randomness."
    ),
    cwe_id="CWE-335",
    owasp_id="A02:2021",
    references=[
        "https://docs.python.org/3/library/random.html#random.seed",
    ],
    tags=["insecure-randomness", "crypto", "owasp-a02"],
)

# ---------------------------------------------------------------------------
# Weak Cryptography rules
# ---------------------------------------------------------------------------

_CRYPTO_MD5 = Rule(
    rule_id="VD090",
    name="Weak hash function: MD5",
    description=(
        "MD5 is a cryptographically broken hash function. It is vulnerable to "
        "collision attacks and should not be used for password hashing, "
        "digital signatures, or any security-sensitive purpose."
    ),
    category=Category.WEAK_CRYPTOGRAPHY,
    severity=Severity.MEDIUM,
    pattern=re.compile(
        r"(?:hashlib\.md5|MD5\.new|md5\s*\()",
        re.IGNORECASE,
    ),
    recommendation=(
        "Use SHA-256 or SHA-3 via hashlib for general hashing. "
        "For password hashing specifically, use bcrypt, scrypt, or Argon2 "
        "via the passlib or argon2-cffi libraries."
    ),
    cwe_id="CWE-327",
    owasp_id="A02:2021",
    references=[
        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
    ],
    tags=["weak-crypto", "md5", "hash", "owasp-a02"],
)

_CRYPTO_SHA1 = Rule(
    rule_id="VD091",
    name="Weak hash function: SHA-1",
    description=(
        "SHA-1 is considered cryptographically weak following demonstrated "
        "collision attacks (SHAttered). It must not be used for digital "
        "signatures, certificate fingerprints, or password hashing."
    ),
    category=Category.WEAK_CRYPTOGRAPHY,
    severity=Severity.MEDIUM,
    pattern=re.compile(
        r"(?:hashlib\.sha1|SHA\.new|SHA1\.new|sha1\s*\()",
        re.IGNORECASE,
    ),
    recommendation=(
        "Use SHA-256 or SHA-3 for integrity checks and digital signatures. "
        "For password hashing, use bcrypt, scrypt, or Argon2."
    ),
    cwe_id="CWE-327",
    owasp_id="A02:2021",
    references=[
        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "https://shattered.io/",
    ],
    tags=["weak-crypto", "sha1", "hash", "owasp-a02"],
)

_CRYPTO_DES = Rule(
    rule_id="VD092",
    name="Weak encryption algorithm: DES or 3DES",
    description=(
        "DES uses a 56-bit key and is trivially brute-forceable. "
        "3DES (Triple DES) is deprecated and vulnerable to Sweet32 birthday attacks. "
        "Neither should be used for new applications."
    ),
    category=Category.WEAK_CRYPTOGRAPHY,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"(?:Crypto\.Cipher\.DES|from Crypto\.Cipher import DES|DES3?\s*\.new|DES\.MODE_|ARC2\.new)",
        re.IGNORECASE,
    ),
    recommendation=(
        "Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption. "
        "The cryptography library provides these as authenticated encryption primitives."
    ),
    cwe_id="CWE-326",
    owasp_id="A02:2021",
    references=[
        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "https://sweet32.info/",
    ],
    tags=["weak-crypto", "des", "cipher", "owasp-a02"],
)

_CRYPTO_RC4 = Rule(
    rule_id="VD093",
    name="Weak encryption algorithm: RC4",
    description=(
        "RC4 is a broken stream cipher with known statistical biases that make "
        "it unsuitable for any security purpose, including TLS."
    ),
    category=Category.WEAK_CRYPTOGRAPHY,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"(?:ARC4|RC4)\s*\.new|from\s+Crypto\.Cipher\s+import\s+ARC4",
        re.IGNORECASE,
    ),
    recommendation=(
        "Replace RC4 with AES-256-GCM or ChaCha20-Poly1305 for symmetric "
        "encryption. Do not use RC4 in any new code."
    ),
    cwe_id="CWE-327",
    owasp_id="A02:2021",
    references=[
        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    ],
    tags=["weak-crypto", "rc4", "cipher", "owasp-a02"],
)

_CRYPTO_ECB_MODE = Rule(
    rule_id="VD094",
    name="Insecure cipher mode: ECB",
    description=(
        "AES or another block cipher is used in ECB (Electronic Codebook) mode. "
        "ECB is deterministic and leaks patterns in the plaintext because identical "
        "plaintext blocks produce identical ciphertext blocks."
    ),
    category=Category.WEAK_CRYPTOGRAPHY,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"MODE_ECB",
        re.IGNORECASE,
    ),
    recommendation=(
        "Use an authenticated encryption mode such as AES-GCM (MODE_GCM) or "
        "AES-CCM. Avoid ECB mode for any security-sensitive data."
    ),
    cwe_id="CWE-327",
    owasp_id="A02:2021",
    references=[
        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    ],
    tags=["weak-crypto", "ecb", "aes", "cipher", "owasp-a02"],
)

_CRYPTO_PLAIN_PASSWORD_HASH = Rule(
    rule_id="VD095",
    name="Plain MD5/SHA hash used for password storage",
    description=(
        "A password is hashed with a generic cryptographic hash function "
        "(MD5, SHA-1, SHA-256) without a salt or key-stretching. Generic "
        "hashes are fast, making them vulnerable to brute-force and rainbow table attacks."
    ),
    category=Category.WEAK_CRYPTOGRAPHY,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"(?:hashlib\.(?:md5|sha1|sha256|sha512))\s*\("
        r"[^)]*(?:password|passwd|pass|pwd|secret)[^)]*\)",
        re.IGNORECASE,
    ),
    recommendation=(
        "Use a password hashing algorithm specifically designed for this purpose: "
        "bcrypt (bcrypt library), scrypt (hashlib.scrypt), or Argon2 (argon2-cffi). "
        "These include built-in salting and are deliberately slow."
    ),
    cwe_id="CWE-916",
    owasp_id="A02:2021",
    references=[
        "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
    ],
    tags=["weak-crypto", "password-hashing", "owasp-a02"],
)

# ---------------------------------------------------------------------------
# Sensitive Data Exposure rules
# ---------------------------------------------------------------------------

_SENSITIVE_LOGGING = Rule(
    rule_id="VD100",
    name="Sensitive data written to logs",
    description=(
        "A logging call appears to include a value whose variable name suggests "
        "it contains a password, token, secret, or other sensitive data. "
        "Logging secrets can expose them in log aggregation systems."
    ),
    category=Category.SENSITIVE_DATA_EXPOSURE,
    severity=Severity.MEDIUM,
    pattern=re.compile(
        r"(?:log(?:ger)?\.(?:debug|info|warning|error|critical|exception)|print)\s*\("
        r"[^)]*(?:password|passwd|secret|token|api_key|auth|private_key)[^)]*\)",
        re.IGNORECASE,
    ),
    recommendation=(
        "Mask or redact sensitive values before logging. Use a log filter or "
        "a custom formatter that scrubs known sensitive field names."
    ),
    cwe_id="CWE-532",
    owasp_id="A09:2021",
    references=[
        "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    ],
    tags=["sensitive-data", "logging", "owasp-a09"],
)

_SENSITIVE_EXCEPTION_INFO = Rule(
    rule_id="VD101",
    name="Detailed exception information returned to client",
    description=(
        "A full exception traceback or error detail is included in an HTTP response. "
        "This leaks internal implementation details, file paths, and potentially "
        "sensitive data to an attacker."
    ),
    category=Category.SENSITIVE_DATA_EXPOSURE,
    severity=Severity.MEDIUM,
    pattern=re.compile(
        r"(?:traceback\.format_exc|str\s*\(\s*e\s*\)|str\s*\(\s*err\s*\))"
        r"[^;\n]*(?:return|jsonify|Response|HttpResponse|render|send)",
        re.IGNORECASE,
    ),
    recommendation=(
        "Return generic error messages to clients. Log the full exception "
        "server-side and return only an error code or reference to the user."
    ),
    cwe_id="CWE-209",
    owasp_id="A05:2021",
    references=[
        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    ],
    tags=["sensitive-data", "error-handling", "owasp-a05"],
)

# ---------------------------------------------------------------------------
# Insecure Configuration rules
# ---------------------------------------------------------------------------

_CONFIG_SECRET_KEY_WEAK = Rule(
    rule_id="VD110",
    name="Weak or hardcoded Django/Flask SECRET_KEY",
    description=(
        "The SECRET_KEY setting is assigned a short, predictable, or obviously "
        "placeholder value. The secret key is used for session signing, CSRF "
        "tokens, and password reset links; a weak key undermines all of these."
    ),
    category=Category.INSECURE_CONFIGURATION,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"SECRET_KEY\s*=\s*['\"](?:secret|change.?me|insecure|dev|development|test|django-insecure-|your-?secret|changethis)[^'\"]*['\"])",
        re.IGNORECASE,
    ),
    recommendation=(
        "Generate a strong random SECRET_KEY using: "
        "python -c \"import secrets; print(secrets.token_hex(50))\". "
        "Store it as an environment variable and never commit it to version control."
    ),
    cwe_id="CWE-1392",
    owasp_id="A05:2021",
    references=[
        "https://docs.djangoproject.com/en/stable/ref/settings/#secret-key",
    ],
    tags=["insecure-config", "secret-key", "django", "flask", "owasp-a05"],
)

_CONFIG_ALLOWED_HOSTS_WILDCARD = Rule(
    rule_id="VD111",
    name="Django ALLOWED_HOSTS set to wildcard '*'",
    description=(
        "ALLOWED_HOSTS = ['*'] disables Django's Host header validation, "
        "leaving the application open to Host header injection attacks."
    ),
    category=Category.INSECURE_CONFIGURATION,
    severity=Severity.MEDIUM,
    pattern=re.compile(
        r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]\s*\]",
        re.IGNORECASE,
    ),
    recommendation=(
        "Set ALLOWED_HOSTS to the specific domain names your application serves. "
        "Only use '*' in local development and never in production."
    ),
    cwe_id="CWE-116",
    owasp_id="A05:2021",
    references=[
        "https://docs.djangoproject.com/en/stable/ref/settings/#allowed-hosts",
    ],
    tags=["insecure-config", "django", "owasp-a05"],
)

_CONFIG_CORS_ALL_ORIGINS = Rule(
    rule_id="VD112",
    name="CORS configured to allow all origins",
    description=(
        "CORS is configured with a wildcard ('*') allowed origin or "
        "CORS_ALLOW_ALL_ORIGINS=True, permitting any website to make "
        "credentialed cross-origin requests to this API."
    ),
    category=Category.INSECURE_CONFIGURATION,
    severity=Severity.MEDIUM,
    pattern=re.compile(
        r"(?:CORS_ALLOW_ALL_ORIGINS\s*=\s*True"
        r"|Access-Control-Allow-Origin['"]\s*:\s*['\"]\*['\"])",
        re.IGNORECASE,
    ),
    recommendation=(
        "Restrict CORS_ALLOWED_ORIGINS to the specific origins that should access "
        "the API. Never use '*' in combination with allow_credentials=True."
    ),
    cwe_id="CWE-942",
    owasp_id="A05:2021",
    references=[
        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
    ],
    tags=["insecure-config", "cors", "owasp-a05"],
)

# ---------------------------------------------------------------------------
# Template Injection
# ---------------------------------------------------------------------------

_TEMPLATE_INJECTION_JINJA2 = Rule(
    rule_id="VD120",
    name="Server-Side Template Injection via Jinja2/Mako render",
    description=(
        "A template is rendered from a user-supplied string (e.g. via "
        "Template(user_input).render() or environment.from_string(user_input)). "
        "This allows Server-Side Template Injection, which can lead to remote "
        "code execution."
    ),
    category=Category.CODE_INJECTION,
    severity=Severity.CRITICAL,
    pattern=re.compile(
        r"(?:Template|from_string|render_template_string)\s*\("
        r"\s*(?!(?:['\"].*['\"])\s*[,)])",
        re.IGNORECASE,
    ),
    recommendation=(
        "Never render templates from user-supplied strings. Load templates only "
        "from a trusted template directory using Environment.get_template(). "
        "Validate and sanitise all user input passed as template variables."
    ),
    cwe_id="CWE-94",
    owasp_id="A03:2021",
    references=[
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://portswigger.net/web-security/server-side-template-injection",
    ],
    tags=["ssti", "template-injection", "jinja2", "mako", "owasp-a03"],
)

# ---------------------------------------------------------------------------
# XML / XXE rules
# ---------------------------------------------------------------------------

_XXE_ETREE_PARSE = Rule(
    rule_id="VD130",
    name="XML External Entity (XXE) via ElementTree / lxml",
    description=(
        "XML is parsed without disabling external entity processing. "
        "Malicious XML documents can use XXE to read arbitrary files from the "
        "server, perform SSRF, or cause denial of service via entity expansion."
    ),
    category=Category.CODE_INJECTION,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"(?:etree\.parse|etree\.fromstring|ET\.parse|ET\.fromstring"
        r"|lxml\.etree\.parse|minidom\.parse|xml\.dom\.minidom\.parseString"
        r"|expatbuilder\.parseString|pulldom\.parseString)\s*\(",
        re.IGNORECASE,
    ),
    recommendation=(
        "Use defusedxml instead of the standard xml library for parsing untrusted "
        "XML. If using lxml, set resolve_entities=False in the parser options."
    ),
    cwe_id="CWE-611",
    owasp_id="A05:2021",
    references=[
        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "https://pypi.org/project/defusedxml/",
    ],
    tags=["xxe", "xml", "owasp-a05"],
)

# ---------------------------------------------------------------------------
# Regex DoS (ReDoS)
# ---------------------------------------------------------------------------

_REDOS = Rule(
    rule_id="VD140",
    name="Potential ReDoS via user-supplied regex pattern",
    description=(
        "re.compile() or re.match/search/fullmatch is called with a variable "
        "pattern argument, which may originate from user input. Crafted patterns "
        "can cause catastrophic backtracking, leading to denial of service."
    ),
    category=Category.OTHER,
    severity=Severity.MEDIUM,
    pattern=re.compile(
        r"re\.(?:compile|match|search|fullmatch|findall|finditer)\s*\("
        r"\s*(?!(?:['\"].*['\"])\s*[,)])",
        re.IGNORECASE,
    ),
    recommendation=(
        "Never use untrusted input as a regex pattern. If dynamic patterns are "
        "necessary, validate them with a length limit and a timeout wrapper "
        "(e.g. using a thread with a timeout or the re2 library)."
    ),
    cwe_id="CWE-1333",
    owasp_id="A06:2021",
    references=[
        "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
        "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS",
    ],
    tags=["redos", "dos", "regex", "owasp-a06"],
)

# ---------------------------------------------------------------------------
# SSRF rules
# ---------------------------------------------------------------------------

_SSRF_REQUESTS = Rule(
    rule_id="VD150",
    name="Potential SSRF via HTTP request with variable URL",
    description=(
        "An HTTP request is made with a URL that appears to contain a variable. "
        "If the URL is derived from user input without validation, an attacker "
        "can direct the server to make requests to internal services (SSRF)."
    ),
    category=Category.INSECURE_CONFIGURATION,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"(?:requests\.(?:get|post|put|patch|delete|head|options)|urllib\.request\.urlopen|httpx\.(?:get|post|put)|aiohttp\.ClientSession\(\)\.(?:get|post))\s*\("
        r"\s*(?:f['\"]|[a-zA-Z_][a-zA-Z0-9_.]*\s*[+,])",
        re.IGNORECASE,
    ),
    recommendation=(
        "Validate user-supplied URLs against an allowlist of permitted hosts. "
        "Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 127.x, "
        "169.254.x) and reject non-http/https schemes."
    ),
    cwe_id="CWE-918",
    owasp_id="A10:2021",
    references=[
        "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    ],
    tags=["ssrf", "owasp-a10"],
)

# ---------------------------------------------------------------------------
# Insecure file upload
# ---------------------------------------------------------------------------

_FILE_UPLOAD_NO_VALIDATION = Rule(
    rule_id="VD160",
    name="File upload without extension or content-type validation",
    description=(
        "A file upload is saved using a user-supplied filename (e.g. "
        "file.filename or request.FILES) without any extension validation. "
        "Uploading executable files can lead to remote code execution."
    ),
    category=Category.INSECURE_CONFIGURATION,
    severity=Severity.HIGH,
    pattern=re.compile(
        r"(?:file\.save|open)\s*\("
        r"[^)]*(?:filename|file\.name|request\.FILES|uploaded_file)[^)]*\)",
        re.IGNORECASE,
    ),
    recommendation=(
        "Validate the file extension against an allowlist of safe types. "
        "Re-generate the filename with a UUID instead of using the user-supplied name. "
        "Validate the file's magic bytes / content type rather than relying on "
        "the declared MIME type."
    ),
    cwe_id="CWE-434",
    owasp_id="A04:2021",
    references=[
        "https://owasp.org/Top10/A04_2021-Insecure_Design/",
        "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
    ],
    tags=["file-upload", "owasp-a04"],
)

# ---------------------------------------------------------------------------
# Aggregate: all rules tuple (used as the canonical source of truth)
# ---------------------------------------------------------------------------

ALL_RULES: tuple[Rule, ...] = (
    # SQL Injection
    _SQL_INJECTION_FSTRING,
    _SQL_INJECTION_CONCAT,
    _SQL_INJECTION_RAW_QUERY,
    # Command / Code Injection
    _CMD_INJECTION_OS_SYSTEM,
    _CMD_INJECTION_SUBPROCESS_SHELL,
    _CMD_INJECTION_POPEN,
    _CMD_INJECTION_EVAL,
    _CMD_INJECTION_EXEC,
    # LDAP Injection
    _LDAP_INJECTION,
    # Path Traversal
    _PATH_TRAVERSAL_OPEN,
    _PATH_TRAVERSAL_DOTDOT,
    _PATH_TRAVERSAL_SEND_FILE,
    # Hardcoded Secrets
    _SECRET_HARDCODED_PASSWORD,
    _SECRET_AWS_KEY,
    _SECRET_GENERIC_TOKEN,
    _SECRET_PRIVATE_KEY_HEADER,
    _SECRET_GITHUB_TOKEN,
    # Insecure Auth / TLS / Config
    _AUTH_SSL_VERIFY_FALSE,
    _AUTH_SSL_CONTEXT_NO_VERIFY,
    _AUTH_HARDCODED_BASIC_AUTH,
    _AUTH_JWT_NONE_ALG,
    _AUTH_DEBUG_TRUE,
    # Unsafe Deserialization
    _DESER_PICKLE_LOADS,
    _DESER_YAML_LOAD,
    _DESER_MARSHAL,
    _DESER_JSONPICKLE,
    # XSS
    _XSS_INNER_HTML,
    _XSS_DANGEROUS_SET_HTML,
    _XSS_DOCUMENT_WRITE,
    _XSS_PYTHON_MARK_SAFE,
    # Insecure Randomness
    _RANDOM_INSECURE,
    _RANDOM_SEED,
    # Weak Cryptography
    _CRYPTO_MD5,
    _CRYPTO_SHA1,
    _CRYPTO_DES,
    _CRYPTO_RC4,
    _CRYPTO_ECB_MODE,
    _CRYPTO_PLAIN_PASSWORD_HASH,
    # Sensitive Data Exposure
    _SENSITIVE_LOGGING,
    _SENSITIVE_EXCEPTION_INFO,
    # Insecure Configuration
    _CONFIG_SECRET_KEY_WEAK,
    _CONFIG_ALLOWED_HOSTS_WILDCARD,
    _CONFIG_CORS_ALL_ORIGINS,
    # Template Injection / SSTI
    _TEMPLATE_INJECTION_JINJA2,
    # XXE
    _XXE_ETREE_PARSE,
    # ReDoS
    _REDOS,
    # SSRF
    _SSRF_REQUESTS,
    # Insecure file upload
    _FILE_UPLOAD_NO_VALIDATION,
)


def get_all_rules() -> List[Rule]:
    """Return a fresh list containing all vulnerability rules.

    The returned list is an independent copy; modifications to it do not
    affect the module-level :data:`ALL_RULES` tuple.

    Returns:
        A list of all :class:`~vulndiff.models.Rule` instances.
    """
    return list(ALL_RULES)


def get_rules_by_category(category: Category) -> List[Rule]:
    """Return all rules belonging to the given *category*.

    Args:
        category: A :class:`~vulndiff.models.Category` enum value to filter by.

    Returns:
        A list of :class:`~vulndiff.models.Rule` instances whose
        ``category`` attribute matches *category*.
    """
    return [rule for rule in ALL_RULES if rule.category == category]


def get_rules_by_severity(severity: Severity) -> List[Rule]:
    """Return all rules with the given *severity* level.

    Args:
        severity: A :class:`~vulndiff.models.Severity` enum value to filter by.

    Returns:
        A list of :class:`~vulndiff.models.Rule` instances whose
        ``severity`` attribute matches *severity*.
    """
    return [rule for rule in ALL_RULES if rule.severity == severity]


def get_rules_at_or_above_severity(severity: Severity) -> List[Rule]:
    """Return all rules whose severity is >= *severity*.

    This is useful for filtering the rule set down to only high-impact
    rules when running in a noise-sensitive environment.

    Args:
        severity: Minimum :class:`~vulndiff.models.Severity` level (inclusive).

    Returns:
        A list of :class:`~vulndiff.models.Rule` instances at or above
        *severity*.
    """
    return [rule for rule in ALL_RULES if rule.severity >= severity]


def get_rule_by_id(rule_id: str) -> Rule:
    """Look up a single rule by its unique identifier.

    Args:
        rule_id: The rule identifier string to search for (e.g. ``"VD001"``).

    Returns:
        The matching :class:`~vulndiff.models.Rule` instance.

    Raises:
        KeyError: If no rule with the given *rule_id* exists.
    """
    for rule in ALL_RULES:
        if rule.rule_id == rule_id:
            return rule
    raise KeyError(f"No rule found with rule_id={rule_id!r}")


def get_rule_ids() -> List[str]:
    """Return a sorted list of all rule identifier strings.

    Returns:
        A list of rule ID strings, e.g. ``["VD001", "VD002", ...]``.
    """
    return sorted(rule.rule_id for rule in ALL_RULES)
