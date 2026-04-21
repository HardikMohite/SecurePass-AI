"""
Database initialization script for SecurePass AI

This script creates all database tables.
Run this once to set up the database.

WARNING: In development, this drops all existing tables and recreates them.
         Do NOT use this in production with real data!

Usage:
    python init_db.py
"""
import os
os.environ.setdefault('FLASK_ENV', 'development')
os.environ.setdefault('SECRET_KEY', 'init-temp-key')

from app import app
from models import db, User, Analysis

def init_database():
    """Initialize the database with all tables"""
    with app.app_context():
        print("Initializing database...")
        
        # Create all tables
        db.create_all()
        
        print("✓ Database tables created successfully!")
        print(f"✓ Database location: {app.config['SQLALCHEMY_DATABASE_URI']}")
        
        # Print table info
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        print(f"✓ Tables created: {', '.join(tables)}")
        
        print("\nDatabase is ready to use!")
        print("You can now run: python app.py")


def reset_database():
    """
    Drop all tables and recreate them
    WARNING: This deletes all data!
    """
    with app.app_context():
        print("WARNING: This will delete all existing data!")
        confirm = input("Type 'yes' to continue: ")
        
        if confirm.lower() == 'yes':
            print("Dropping all tables...")
            db.drop_all()
            print("Creating new tables...")
            db.create_all()
            print("✓ Database reset complete!")
        else:
            print("Reset cancelled.")


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--reset':
        reset_database()
    else:
        init_database()