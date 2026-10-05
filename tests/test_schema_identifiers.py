"""No column may be named after a SQL reserved word.

The incident: `runs` had a column called `user`. That is reserved in Postgres,
so every read had to be quoted -- and an unquoted one does not fail, it silently
resolves to CURRENT_USER and returns the database role name. One such read fed
an authorization comparison; another fed a per-tenant fairness cap, which
therefore counted zero and never fired. The schema migration could not run on
Postgres at all, so the multi-node path was broken end to end while every
single-node test stayed green, because SQLite accepts the unquoted form and
means the column by it.

The first defence was a static-analysis test that policed every call site: 235
lines of AST reassembly, an allowlist, and a comment-stripping order discovered
by mutation testing. It was rewritten three times and missed a real site twice.
That was the wrong layer. A call site can only be wrong if a reserved word is a
column name, so this asserts the schema instead -- the one place such a name can
enter. It cannot go blind, because there is nothing to parse.
"""

import re

import pytest

from andyur import db

# Reserved in Postgres (and mostly in SQL:2016). Not exhaustive across every
# engine, but complete for the words a schema is realistically tempted to use.
# Sourced from Postgres 16's reserved list, filtered to plausible column names.
RESERVED = {
    "all", "analyse", "analyze", "and", "any", "array", "as", "asc", "authorization",
    "between", "both", "case", "cast", "check", "collate", "column", "constraint",
    "create", "cross", "current_catalog", "current_date", "current_role",
    "current_schema", "current_time", "current_timestamp", "current_user",
    "default", "deferrable", "desc", "distinct", "do", "else", "end", "except",
    "false", "fetch", "for", "foreign", "freeze", "from", "full", "grant", "group",
    "having", "ilike", "in", "initially", "inner", "intersect", "into", "is",
    "isnull", "join", "lateral", "leading", "left", "like", "limit", "localtime",
    "localtimestamp", "natural", "not", "notnull", "null", "offset", "on", "only",
    "or", "order", "outer", "overlaps", "placing", "primary", "references",
    "returning", "right", "select", "session_user", "similar", "some", "symmetric",
    "table", "tablesample", "then", "to", "trailing", "true", "union", "unique",
    "user", "using", "variadic", "verbose", "when", "where", "window", "with",
}

# `CREATE TABLE x (` ... `)` -- enough to read the column names out of a schema
# written the way this one is: one column per line, name first.
_TABLE = re.compile(r"CREATE TABLE(?:\s+IF NOT EXISTS)?\s+(\w+)\s*\((.*?)\n\);",
                    re.DOTALL | re.IGNORECASE)


def _columns():
    """(table, column) for every column the schema declares."""
    for table, body in _TABLE.findall(db.SCHEMA):
        for line in body.splitlines():
            line = line.strip().rstrip(",")
            if not line or line.startswith("--"):
                continue
            first = line.split()[0].strip('"')
            # skip table-level constraints (UNIQUE(...), FOREIGN KEY, ...)
            if first.upper() in ("UNIQUE", "PRIMARY", "FOREIGN", "CHECK", "CONSTRAINT"):
                continue
            yield table, first


def test_the_schema_declares_at_least_one_table():
    """Guards the regex: if it stops matching, every assertion below passes
    vacuously, which is how the previous version of this test went blind."""
    tables = {t for t, _ in _TABLE.findall(db.SCHEMA)}
    assert "runs" in tables and "agents" in tables, tables
    assert len(list(_columns())) > 20


@pytest.mark.parametrize("table, column", sorted(set(_columns())))
def test_no_schema_column_is_a_reserved_word(table, column):
    assert column.lower() not in RESERVED, (
        f"{table}.{column} is a SQL reserved word. Unquoted, Postgres resolves it "
        f"to a built-in function and returns a plausible wrong value instead of "
        f"failing. Rename the column."
    )


@pytest.mark.parametrize("table, column, _type", db.MIGRATION_COLUMNS)
def test_no_migrated_column_is_a_reserved_word(table, column, _type):
    assert column.lower() not in RESERVED, (
        f"{table}.{column} is a SQL reserved word; rename it before adding it"
    )
