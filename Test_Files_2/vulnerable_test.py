# vulnerable_test.py
#
# Intentionally vulnerable test file for vulnerability detector testing.
# Contains synthetic reproductions of:
#   - CVE-2020-35518: LDAP authentication information disclosure via
#                     differential server responses (user enumeration)
#   - CVE-2020-36631: SQL injection via unsanitized field name in
#                     UPDATE query (gamespy gs_database.py)
#
# THIS FILE IS INTENTIONALLY VULNERABLE. FOR TESTING PURPOSES ONLY.

import sqlite3
import threading
import unittest


# =============================================================================
# Stub / shim infrastructure
# =============================================================================

class Transaction:
    """Minimal SQLite transaction context manager used by the database layer."""

    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.conn.commit()
        else:
            self.conn.rollback()
        return False

    def nonquery(self, sql, params=()):
        self.conn.execute(sql, params)

    def queryone(self, sql, params=()):
        cur = self.conn.execute(sql, params)
        return cur.fetchone()

    def queryall(self, sql, params=()):
        cur = self.conn.execute(sql, params)
        return cur.fetchall()


# =============================================================================
# Minimal LDAP stubs
# =============================================================================

class LDAPError(Exception):
    pass

class NO_SUCH_OBJECT(LDAPError):
    """Raised when the requested DN does not exist in the directory."""
    pass

class INVALID_CREDENTIALS(LDAPError):
    """Raised when the password is wrong for an existing DN."""
    pass


class FakeLDAPConnection:
    """
    Simulates an LDAP server with two pre-provisioned entries.

    Bind behaviour (mirrors the vulnerable 389-ds / FreeIPA behaviour):
      - DN not found  → raises NO_SUCH_OBJECT  (reveals entry absence)
      - DN found, bad password → raises INVALID_CREDENTIALS
      - DN found, good password → returns bind info dict
    """

    _DIRECTORY = {
        "uid=alice,dc=example,dc=com": "s3cr3t",
        "uid=bob,dc=example,dc=com":   "p@ssw0rd",
    }

    def simple_bind_s(self, dn, password):
        if dn not in self._DIRECTORY:
            # VULNERABILITY (CVE-2020-35518): differential response leaks
            # whether the DN exists.  A uniform "Invalid credentials" error
            # regardless of DN existence would prevent user enumeration.
            raise NO_SUCH_OBJECT(f"No such entry: {dn}")
        if self._DIRECTORY[dn] != password:
            raise INVALID_CREDENTIALS("Invalid credentials")
        return {"result": 0, "desc": "Success", "dn": dn}

    def unbind_s(self):
        pass


# =============================================================================
# CVE-2020-35518
# Vulnerability: LDAP authentication information disclosure.
#
# LdapAuthenticator.authenticate() propagates the server's differential error
# responses directly to the caller.  An unauthenticated attacker can probe
# arbitrary DNs:
#   - NO_SUCH_OBJECT   → entry does not exist  (user enumeration)
#   - INVALID_CREDENTIALS → entry exists, password wrong
#
# The fix (NOT applied here) is to catch both exception types and raise a
# single, uniform "Authentication failed" error in both cases, e.g.:
#
#   except (NO_SUCH_OBJECT, INVALID_CREDENTIALS):
#       raise AuthenticationError("Invalid credentials")
#
# This ensures that the caller — and any timing/error side-channel observer —
# cannot distinguish a missing DN from a wrong password.
# =============================================================================

class AuthenticationError(Exception):
    pass


class LdapAuthenticator:
    """Authenticates users against an LDAP directory."""

    def __init__(self, ldap_conn):
        self._conn = ldap_conn

    def authenticate(self, dn, password):
        """
        Attempt to bind as *dn* with *password*.

        Returns bind info dict on success.

        VULNERABILITY (CVE-2020-35518): the two failure modes — DN not found
        and wrong password — propagate as distinct exceptions (NO_SUCH_OBJECT
        vs INVALID_CREDENTIALS).  An attacker who can observe error responses
        can enumerate valid DNs without knowing any credentials.

        The fix would catch both exceptions and raise the same
        AuthenticationError, providing a uniform response regardless of
        whether the entry exists.
        """
        try:
            # FIXME: differential error responses leak entry existence.
            bind_info = self._conn.simple_bind_s(dn, password)
            return bind_info
        except NO_SUCH_OBJECT:
            # Vulnerable: reveals that the DN does not exist
            raise AuthenticationError(f"No such entry: {dn}")
        except INVALID_CREDENTIALS:
            # This is the correct generic message, but it is *different*
            # from the one raised for NO_SUCH_OBJECT, enabling enumeration.
            raise AuthenticationError("Invalid credentials")
        finally:
            try:
                self._conn.unbind_s()
            except Exception:
                pass


# =============================================================================
# CVE-2020-36631
# Vulnerability: SQL injection via unsanitized field name in UPDATE query.
#
# GameDatabase.update_profile() embeds field[0] — a caller-supplied string —
# directly into the SQL statement using Python string formatting (%s).
# Although the field *value* (field[1]) is correctly passed as a bound
# parameter, the field *name* is not validated, so an attacker can supply:
#
#   field = ('" = 1; DROP TABLE users; --', 'x')
#
# and the resulting query becomes:
#
#   UPDATE users SET "" = 1; DROP TABLE users; --" = ? WHERE profileid = ?
#
# The fix (NOT applied here) is to whitelist the allowed column names before
# constructing the query:
#
#   if field[0] in ["firstname", "lastname"]:
#       with Transaction(self.conn) as tx:
#           q = 'UPDATE users SET "%s" = ? WHERE profileid = ?'
#           tx.nonquery(q % field[0], (field[1], profileid))
# =============================================================================

class GameDatabase:
    """Manages user profiles and sessions for a GameSpy-compatible server."""

    def __init__(self, conn):
        self.conn = conn
        self._create_schema()

    # ------------------------------------------------------------------
    # Schema bootstrap
    # ------------------------------------------------------------------

    def _create_schema(self):
        with Transaction(self.conn) as tx:
            tx.nonquery("""
                CREATE TABLE IF NOT EXISTS users (
                    profileid  INTEGER PRIMARY KEY AUTOINCREMENT,
                    userid     TEXT,
                    password   TEXT,
                    gsbrcd     TEXT,
                    email      TEXT,
                    uniquenick TEXT,
                    pid        INTEGER DEFAULT 0,
                    lon        REAL    DEFAULT 0.0,
                    lat        REAL    DEFAULT 0.0,
                    loc        TEXT    DEFAULT '',
                    firstname  TEXT    DEFAULT '',
                    lastname   TEXT    DEFAULT '',
                    stat       INTEGER DEFAULT 0,
                    partnerid  INTEGER DEFAULT 0,
                    console    INTEGER DEFAULT 0,
                    csnum      TEXT    DEFAULT '',
                    cfc        TEXT    DEFAULT '',
                    bssid      TEXT    DEFAULT '',
                    devname    TEXT    DEFAULT '',
                    birth      TEXT    DEFAULT '',
                    gameid     TEXT    DEFAULT '',
                    enabled    INTEGER DEFAULT 1,
                    zipcode    TEXT    DEFAULT '',
                    aim        TEXT    DEFAULT ''
                )
            """)
            tx.nonquery("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session     TEXT PRIMARY KEY,
                    loginticket TEXT,
                    profileid   INTEGER
                )
            """)
            tx.nonquery("""
                CREATE TABLE IF NOT EXISTS pending_messages (
                    sourceid  INTEGER,
                    targetid  INTEGER,
                    msg       TEXT
                )
            """)

    # ------------------------------------------------------------------
    # Profile management
    # ------------------------------------------------------------------

    def create_profile(self, userid, password, gsbrcd, email, uniquenick,
                       pid=0, lon=0.0, lat=0.0, loc='', firstname='',
                       lastname='', stat=0, partnerid=0, console=0,
                       csnum='', cfc='', bssid='', devname='', birth='',
                       gameid='', enabled=1, zipcode='', aim=''):
        with Transaction(self.conn) as tx:
            q = (
                "INSERT INTO users "
                "(userid, password, gsbrcd, email, uniquenick, pid, lon, lat,"
                " loc, firstname, lastname, stat, partnerid, console, csnum,"
                " cfc, bssid, devname, birth, gameid, enabled, zipcode, aim)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            )
            tx.nonquery(q, (str(userid), password, gsbrcd, email, uniquenick,
                            pid, lon, lat, loc, firstname, lastname, stat,
                            partnerid, console, csnum, cfc, bssid, devname,
                            birth, gameid, enabled, zipcode, aim))
        with Transaction(self.conn) as tx:
            row = tx.queryone(
                "SELECT profileid FROM users WHERE uniquenick = ?",
                (uniquenick,)
            )
        return row[0] if row else None

    def get_user_list(self):
        with Transaction(self.conn) as tx:
            rows = tx.queryall("SELECT * FROM users")
        return [self._get_dict(row) for row in rows]

    def save_pending_message(self, sourceid, targetid, msg):
        with Transaction(self.conn) as tx:
            tx.nonquery(
                "INSERT INTO pending_messages VALUES (?,?,?)",
                (sourceid, targetid, msg)
            )

    def get_pending_messages(self, profileid):
        with Transaction(self.conn) as tx:
            rows = tx.queryall(
                "SELECT * FROM pending_messages WHERE targetid = ?",
                (profileid,)
            )
        return [self._get_dict(row) for row in rows]

    def update_profile(self, profileid, field):
        """Update a single field in a user's profile.

        :param profileid: integer profile identifier
        :param field:     2-tuple of (column_name, new_value)

        VULNERABILITY (CVE-2020-36631): field[0] is a caller-supplied string
        that is embedded directly into the SQL statement via %-formatting
        without any whitelist check.  An attacker can supply a crafted column
        name to inject arbitrary SQL.

        Example exploit input:
            field = ('" = 1; DROP TABLE users; --', 'ignored')

        Resulting query:
            UPDATE users SET "" = 1; DROP TABLE users; --" = ?
            WHERE profileid = ?

        The fix (NOT applied here) is to add:
            # TODO: Check if other values than firstname/lastname are set
            if field[0] in ["firstname", "lastname"]:
                <execute query>
        """
        # FIXME: Possible security issue due to embedding an unsanitized
        # string directly into the statement.
        with Transaction(self.conn) as tx:
            q = 'UPDATE users SET "%s" = ? WHERE profileid = ?'
            tx.nonquery(q % field[0], (field[1], profileid))

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def get_profileid_from_session_key(self, session_key):
        # TODO: Cache session keys so we don't have to query the database
        # every time we get a profile id.
        with Transaction(self.conn) as tx:
            row = tx.queryone(
                "SELECT profileid FROM sessions WHERE session = ?",
                (session_key,)
            )
            r = self._get_dict(row) if row else None

        profileid = -1
        if r is not None:
            profileid = r["profileid"]
        return profileid

    def get_profileid_from_loginticket(self, loginticket):
        with Transaction(self.conn) as tx:
            row = tx.queryone(
                "SELECT profileid FROM sessions WHERE loginticket = ?",
                (loginticket,)
            )
        profileid = -1
        if row:
            profileid = int(row[0])
        return profileid

    def get_profile_from_session_key(self, session_key):
        profileid = self.get_profileid_from_session_key(session_key)
        profile = {}
        if profileid and profileid != -1:
            with Transaction(self.conn) as tx:
                row = tx.queryone(
                    "SELECT * FROM users WHERE profileid = ?",
                    (profileid,)
                )
            if row:
                profile = self._get_dict(row)
        return profile

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_dict(self, row):
        if row is None:
            return None
        if hasattr(row, "keys"):
            return dict(row)
        # sqlite3 Row — use description from a fresh cursor
        return dict(zip(
            [d[0] for d in self.conn.execute(
                "SELECT * FROM users LIMIT 0").description],
            row
        )) if len(row) > 3 else {"profileid": row[0]}


# =============================================================================
# Tests
# =============================================================================

class TestCVE202035518(unittest.TestCase):
    """
    CVE-2020-35518 — LDAP user enumeration via differential bind responses.

    These tests confirm the *vulnerable* behaviour: a caller can distinguish
    a missing DN from a wrong password by catching different error messages.
    A fixed implementation would raise the same AuthenticationError text in
    both cases.
    """

    def setUp(self):
        self.ldap   = FakeLDAPConnection()
        self.auth   = LdapAuthenticator(self.ldap)
        self.valid_dn    = "uid=alice,dc=example,dc=com"
        self.missing_dn  = "uid=nobody,dc=example,dc=com"
        self.valid_pass  = "s3cr3t"
        self.wrong_pass  = "wrong"

    def test_successful_bind(self):
        """A valid DN + correct password succeeds."""
        result = self.auth.authenticate(self.valid_dn, self.valid_pass)
        self.assertEqual(result["result"], 0)

    def test_bind_nonexistent_entry(self):
        """
        VULNERABILITY (CVE-2020-35518): binding as a non-existent DN raises
        an AuthenticationError whose message contains 'No such entry',
        revealing that the DN does not exist in the directory.

        A fixed implementation would surface the same generic message as
        test_bind_wrong_password() below.
        """
        with self.assertRaises(AuthenticationError) as ctx:
            self.auth.authenticate(self.missing_dn, self.wrong_pass)

        error_msg = str(ctx.exception)
        # Confirm the vulnerable behaviour: the error leaks DN absence.
        self.assertIn("No such entry", error_msg,
                      "Vulnerable: error message reveals the DN does not exist")

    def test_bind_wrong_password(self):
        """
        Binding as an *existing* DN with the wrong password raises a
        different AuthenticationError message ('Invalid credentials').

        The difference between this message and 'No such entry' is what
        enables user enumeration — the core of CVE-2020-35518.
        """
        with self.assertRaises(AuthenticationError) as ctx:
            self.auth.authenticate(self.valid_dn, self.wrong_pass)

        error_msg = str(ctx.exception)
        self.assertIn("Invalid credentials", error_msg)

    def test_error_messages_differ(self):
        """
        Directly demonstrates the information leak: the two error messages are
        distinguishable, allowing an attacker to enumerate valid DNs.
        """
        missing_msg = ""
        wrong_pass_msg = ""

        try:
            self.auth.authenticate(self.missing_dn, "x")
        except AuthenticationError as e:
            missing_msg = str(e)

        try:
            self.auth.authenticate(self.valid_dn, "x")
        except AuthenticationError as e:
            wrong_pass_msg = str(e)

        self.assertNotEqual(
            missing_msg, wrong_pass_msg,
            "Vulnerable: different errors for missing vs wrong-password DN"
        )


class TestCVE202036631(unittest.TestCase):
    """
    CVE-2020-36631 — SQL injection via unsanitized field name in UPDATE query.

    These tests confirm the *vulnerable* behaviour: any column name (including
    crafted SQL fragments) can be passed as field[0] and will be embedded
    directly into the statement.
    """

    def setUp(self):
        # Use an in-memory SQLite database; enable multi-statement execution
        # to make the injection demo visible.
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.isolation_level = None          # autocommit off
        self.db = GameDatabase(self.conn)
        self.profileid = self.db.create_profile(
            userid="1", password="pass", gsbrcd="GSGAME",
            email="test@example.com", uniquenick="testuser",
            firstname="Alice", lastname="Smith"
        )

    def tearDown(self):
        self.conn.close()

    def test_legitimate_update(self):
        """A well-formed (firstname, value) update works correctly."""
        self.db.update_profile(self.profileid, ("firstname", "Bob"))
        with Transaction(self.conn) as tx:
            row = tx.queryone(
                "SELECT firstname FROM users WHERE profileid = ?",
                (self.profileid,)
            )
        self.assertEqual(row[0], "Bob")

    def test_sql_injection_via_field_name(self):
        """
        VULNERABILITY (CVE-2020-36631): an attacker-controlled field name is
        embedded directly into the SQL statement.

        Injecting a crafted column name that closes the UPDATE and appends a
        second statement (e.g. DROP TABLE or an additional UPDATE) will be
        executed by the database engine.

        Here we demonstrate the injection by overwriting the *password* column
        — a field that should never be writable through update_profile() — by
        supplying it as the column name without any validation.
        """
        # The vulnerable call: field[0] goes straight into the SQL string.
        # FIXME: Possible security issue due to embedding an unsanitized
        # string directly into the statement.
        self.db.update_profile(self.profileid, ("password", "INJECTED"))

        with Transaction(self.conn) as tx:
            row = tx.queryone(
                "SELECT password FROM users WHERE profileid = ?",
                (self.profileid,)
            )

        # Confirms the injection succeeded — password was overwritten even
        # though update_profile() should only touch safe fields.
        self.assertEqual(row[0], "INJECTED",
                         "Vulnerable: arbitrary column 'password' was updated")

    def test_arbitrary_column_accepted(self):
        """
        Any column name is accepted without validation.  A fixed version
        would only allow 'firstname' and 'lastname'.
        """
        # Columns that should be off-limits but are accepted by the vuln code
        for col in ("password", "enabled", "email", "stat"):
            try:
                # If no exception is raised, the column name was accepted
                self.db.update_profile(self.profileid, (col, "tampered"))
                accepted = True
            except Exception:
                accepted = False

            self.assertTrue(
                accepted,
                f"Vulnerable: column '{col}' should be blocked but was accepted"
            )


# =============================================================================
# Entry point
# =============================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
