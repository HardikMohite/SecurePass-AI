"""
migrate_db.py — One-time migration script
Adds missing columns to existing tables without dropping any data.
Run once with: python migrate_db.py
"""
import os
# Ensure dev environment is set before importing app (prevents SECRET_KEY crash)
os.environ.setdefault('FLASK_ENV', 'development')
os.environ.setdefault('SECRET_KEY', 'migrate-temp-key')

from app import app
from models import db
from sqlalchemy import text, inspect

def migrate():
    with app.app_context():
        inspector = inspect(db.engine)

        # ── users table ──────────────────────────────────────────────── #
        existing_user_cols = [c['name'] for c in inspector.get_columns('users')]
        print(f"Current users columns: {existing_user_cols}")

        with db.engine.connect() as conn:
            # Add username column if missing
            if 'username' not in existing_user_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN username VARCHAR(64)"))
                print("✅ Added column: users.username")

            # Add is_active column if missing
            if 'is_active' not in existing_user_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1"))
                print("✅ Added column: users.is_active")

            # Add last_login column if missing
            if 'last_login' not in existing_user_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN last_login DATETIME"))
                print("✅ Added column: users.last_login")

            conn.commit()

        # ── analyses table ───────────────────────────────────────────── #
        if 'analyses' in inspector.get_table_names():
            existing_analysis_cols = [c['name'] for c in inspector.get_columns('analyses')]
            print(f"Current analyses columns: {existing_analysis_cols}")

            with db.engine.connect() as conn:
                if 'risk_level' not in existing_analysis_cols:
                    conn.execute(text("ALTER TABLE analyses ADD COLUMN risk_level VARCHAR(50)"))
                    print("✅ Added column: analyses.risk_level")

                if 'total_passwords' not in existing_analysis_cols:
                    conn.execute(text("ALTER TABLE analyses ADD COLUMN total_passwords INTEGER"))
                    print("✅ Added column: analyses.total_passwords")

                if 'risk_score' not in existing_analysis_cols:
                    conn.execute(text("ALTER TABLE analyses ADD COLUMN risk_score FLOAT"))
                    print("✅ Added column: analyses.risk_score")

                # BUG FIX: ensure analysis_data column exists (actual DB column name)
                if 'analysis_data' not in existing_analysis_cols:
                    conn.execute(text("ALTER TABLE analyses ADD COLUMN analysis_data TEXT NOT NULL DEFAULT '{}'"))
                    print("✅ Added column: analyses.analysis_data")

                # BUG FIX: old schema used 'timestamp', new schema uses 'created_at'
                # SQLite does not support RENAME COLUMN before v3.25 so we handle both:
                # if 'timestamp' exists but 'created_at' does not, add created_at and copy data
                if 'timestamp' in existing_analysis_cols and 'created_at' not in existing_analysis_cols:
                    conn.execute(text("ALTER TABLE analyses ADD COLUMN created_at DATETIME"))
                    conn.execute(text("UPDATE analyses SET created_at = timestamp"))
                    print("✅ Migrated: analyses.timestamp → created_at")
                elif 'created_at' not in existing_analysis_cols:
                    conn.execute(text("ALTER TABLE analyses ADD COLUMN created_at DATETIME NOT NULL DEFAULT (datetime('now'))"))
                    print("✅ Added column: analyses.created_at")

                conn.commit()

        # Ensure any remaining tables/columns from the current models are created
        db.create_all()
        print("\n✅ Migration complete — database is up to date.")

        # Show final schema
        inspector2 = inspect(db.engine)
        for table in inspector2.get_table_names():
            cols = [c['name'] for c in inspector2.get_columns(table)]
            print(f"  Table '{table}': {cols}")

if __name__ == '__main__':
    migrate()