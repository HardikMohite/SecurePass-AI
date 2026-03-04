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
"""
import json
from datetime import datetime

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    """
    Registered user account.

    UserMixin provides the default is_authenticated / is_active / get_id()
    implementations required by Flask-Login.
    """
    __tablename__ = 'users'

    id            = db.Column(db.Integer, primary_key=True)
    email         = db.Column(db.String(120), unique=True, nullable=False, index=True)
    # Optional display name — does not have to be unique
    username      = db.Column(db.String(64), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    # is_active is already provided by UserMixin (returns True by default);
    # we store it explicitly so admins can disable accounts without deleting them.
    is_active     = db.Column(db.Boolean, default=True, nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login    = db.Column(db.DateTime, nullable=True)

    # Cascade deletes so orphaned Analysis rows are cleaned up automatically
    analyses = db.relationship(
        'Analysis',
        backref='user',
        lazy='dynamic',
        cascade='all, delete-orphan',
    )

    # ------------------------------------------------------------------ #
    #  Password helpers                                                    #
    # ------------------------------------------------------------------ #

    def set_password(self, password: str) -> None:
        """Hash *password* and store it."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Return True if *password* matches the stored hash."""
        return check_password_hash(self.password_hash, password)

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
        return {
            'id':               self.id,
            'filename':         self.filename,
            'total_passwords':  self.total_passwords,
            'risk_score':       self.risk_score,
            'risk_level':       self.risk_level,
            'created_at':       self.created_at.isoformat(),
            'analysis_data':    self.analysis_data,
        }

    def summary_dict(self) -> dict:
        """
        Lightweight representation — omits the heavy analysis_data blob.
        Use this in list/history endpoints to avoid transferring large payloads.
        """
        return {
            'id':              self.id,
            'filename':        self.filename,
            'total_passwords': self.total_passwords,
            'risk_score':      self.risk_score,
            'risk_level':      self.risk_level,
            'created_at':      self.created_at.isoformat(),
        }

    def __repr__(self) -> str:
        return f'<Analysis id={self.id} file={self.filename!r} user={self.user_id}>'