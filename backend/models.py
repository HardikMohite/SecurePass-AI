"""
Database models for SecurePass AI

FIX SUMMARY:
- Added optional `username` field to User (useful for display without exposing email)
- Added __table_args__ index on Analysis.created_at for fast history queries
- analysis_data now typed as db.Text (JSON string) for SQLite compatibility
  (db.JSON silently falls back to TEXT in SQLite but without validation)
- Analysis.to_dict() safely deserialises analysis_data back to dict
- Added Analysis.summary_dict() — lightweight version for list views
- Fixed update_last_login() to avoid double-commit when called inside a
  request that already has a pending session (uses db.session.flush instead)
- Added __repr__ improvements and column-level server_default where useful
- PHASE 2: Dropped the Flask-Login UserMixin base — auth is now handled by
  Flask-JWT-Extended (see auth.py / auth_utils.py), which only needs the
  User row itself, not is_authenticated/is_anonymous/get_id(). is_active
  stays as a real column (used to gate login for disabled accounts).
"""
import json
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()


class User(db.Model):
    """Registered user account."""
    __tablename__ = 'users'

    id            = db.Column(db.Integer, primary_key=True)
    email         = db.Column(db.String(120), unique=True, nullable=False, index=True)
    # Optional display name — does not have to be unique
    username      = db.Column(db.String(64), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    # is_active is a real column so admins can disable accounts without deleting them.
    is_active     = db.Column(db.Boolean, default=True, nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login    = db.Column(db.DateTime, nullable=True)
    # Per-user preferences (accent color, thresholds, notification toggles, etc.)
    # Stored as a JSON string, same convention as Analysis._analysis_data — keeps
    # SQLite (dev) and Postgres (prod) behaving identically. Read/written via the
    # UserSettings helper in settings_backend.py; this column used to be added at
    # runtime by a raw ALTER TABLE hack, which never actually reached the real
    # `users` table (wrong table name) and would poison the session under
    # Postgres. It's now a normal mapped column managed by Alembic.
    settings_json = db.Column(db.Text, nullable=False, default='{}')

    # ── Enterprise Security Hardening (NIST SP 800-63B & OWASP ASVS) ───── #
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until          = db.Column(db.DateTime, nullable=True)
    password_changed_at   = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Cascade deletes so orphaned Analysis rows are cleaned up automatically
    analyses = db.relationship(
        'Analysis',
        backref='user',
        lazy='dynamic',
        cascade='all, delete-orphan',
    )

    # ------------------------------------------------------------------ #
    #  Password & Security helpers                                         #
    # ------------------------------------------------------------------ #

    def set_password(self, password: str) -> None:
        """Hash *password* and store it, invalidating old sessions and clearing lockouts."""
        self.password_hash = generate_password_hash(password)
        self.password_changed_at = datetime.utcnow()
        self.failed_login_attempts = 0
        self.locked_until = None

    def check_password(self, password: str) -> bool:
        """Return True if *password* matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    def is_locked(self) -> bool:
        """Check if account is temporarily locked due to excessive failed attempts."""
        if not self.locked_until:
            return False
        return self.locked_until > datetime.utcnow()

    def record_failed_login(self, max_attempts: int = 5, lock_minutes: int = 15) -> bool:
        """
        Record a failed password attempt. If threshold exceeded, lock account.
        Returns True if the account is now locked.
        """
        from datetime import timedelta
        self.failed_login_attempts = (self.failed_login_attempts or 0) + 1
        if self.failed_login_attempts >= max_attempts:
            self.locked_until = datetime.utcnow() + timedelta(minutes=lock_minutes)
            return True
        return False

    def reset_failed_logins(self) -> None:
        """Reset failed login count and clear any lock on successful authentication."""
        self.failed_login_attempts = 0
        self.locked_until = None

    # ------------------------------------------------------------------ #
    #  Session helpers                                                     #
    # ------------------------------------------------------------------ #

    def update_last_login(self) -> None:
        """
        Stamp last_login with the current UTC time.

        Uses flush() rather than commit() so the caller controls the
        transaction boundary — prevents accidental partial commits when
        this is called mid-request alongside other DB work.
        """
        self.last_login = datetime.utcnow()
        db.session.flush()

    # ------------------------------------------------------------------ #
    #  Utility                                                             #
    # ------------------------------------------------------------------ #

    def get_analysis_count(self) -> int:
        """Total number of analyses belonging to this user."""
        return self.analyses.count()

    def to_dict(self) -> dict:
        """Serialise user to a safe dict (no password hash)."""
        return {
            'id':             self.id,
            'email':          self.email,
            'username':       self.username,
            'is_active':      self.is_active,
            'created_at':     self.created_at.isoformat(),
            'last_login':     self.last_login.isoformat() if self.last_login else None,
            'analysis_count': self.get_analysis_count(),
        }

    def __repr__(self) -> str:
        return f'<User id={self.id} email={self.email!r}>'


class Analysis(db.Model):
    """
    Saved password-analysis result for a single uploaded dataset.

    The full JSON payload is stored as a TEXT column (analysis_data) so that
    SQLite and Postgres both handle it consistently.  Helper methods handle
    serialisation / deserialisation.
    """
    __tablename__ = 'analyses'
    __table_args__ = (
        # Speed up "get recent analyses for user" queries
        db.Index('ix_analyses_user_created', 'user_id', 'created_at'),
    )

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    # ── File info ────────────────────────────────────────────────────── #
    filename   = db.Column(db.String(255), nullable=False)

    # ── Summary stats (indexed columns for fast filtering / sorting) ── #
    total_passwords = db.Column(db.Integer,  nullable=True)
    risk_score      = db.Column(db.Float,    nullable=True)
    risk_level      = db.Column(db.String(50), nullable=True)

    # ── Full payload ─────────────────────────────────────────────────── #
    # Stored as JSON string; use set_analysis_data / get_analysis_data.
    # db.Text works on both SQLite and Postgres; avoids silent type issues.
    _analysis_data  = db.Column('analysis_data', db.Text, nullable=False, default='{}')

    # ── Timestamps ───────────────────────────────────────────────────── #
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    # ------------------------------------------------------------------ #
    #  analysis_data property                                              #
    # ------------------------------------------------------------------ #

    @property
    def analysis_data(self) -> dict:
        """Deserialise and return the stored JSON payload as a dict."""
        try:
            return json.loads(self._analysis_data or '{}')
        except (json.JSONDecodeError, TypeError):
            return {}

    @analysis_data.setter
    def analysis_data(self, value) -> None:
        """Accept a dict or a JSON string and store as JSON string."""
        if isinstance(value, dict):
            self._analysis_data = json.dumps(value)
        elif isinstance(value, str):
            # Validate that it is actually valid JSON before storing
            json.loads(value)
            self._analysis_data = value
        else:
            raise TypeError(f"analysis_data must be dict or str, got {type(value)}")

    # ------------------------------------------------------------------ #
    #  Serialisation                                                       #
    # ------------------------------------------------------------------ #

    def to_dict(self) -> dict:
        """Full representation including the analysis payload."""
        ts = self.created_at.isoformat() if self.created_at else None
        return {
            'id':               self.id,
            'filename':         self.filename,
            'total_passwords':  self.total_passwords,
            'risk_score':       self.risk_score,
            'risk_level':       self.risk_level,
            'created_at':       ts,
            'timestamp':        ts,   # alias for backwards compatibility
            'analysis_data':    self.analysis_data,
        }

    def summary_dict(self) -> dict:
        """
        Lightweight representation — omits the heavy analysis_data blob.
        Use this in list/history endpoints to avoid transferring large payloads.
        """
        ts = self.created_at.isoformat() if self.created_at else None
        return {
            'id':              self.id,
            'filename':        self.filename,
            'total_passwords': self.total_passwords,
            'risk_score':      self.risk_score,
            'risk_level':      self.risk_level,
            'created_at':      ts,
            'timestamp':       ts,   # alias for backwards compatibility
        }

    def __repr__(self) -> str:
        return f'<Analysis id={self.id} file={self.filename!r} user={self.user_id}>'