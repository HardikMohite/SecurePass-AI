#!/bin/bash

echo "🔒 SecurePass AI - Setup Script"
echo "================================"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

echo "✓ Python 3 found: $(python3 --version)"
echo ""

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi
echo "✓ Dependencies installed"
echo ""

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "⚙️  Creating .env file..."
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    cat > .env << EOF
# SecurePass AI - Environment Variables
SECRET_KEY=$SECRET_KEY
FLASK_ENV=development
FLASK_DEBUG=True
DATABASE_URL=sqlite:///securepass.db
SESSION_COOKIE_SECURE=False
REMEMBER_COOKIE_SECURE=False
EOF
    echo "✓ .env file created with secure secret key"
else
    echo "⚠️  .env file already exists, skipping..."
fi
echo ""

# Initialize database
echo "🗄️  Initializing database..."
python3 init_db.py
if [ $? -ne 0 ]; then
    echo "❌ Failed to initialize database"
    exit 1
fi
echo ""

echo "✅ Setup complete!"
echo ""
echo "To start the application, run:"
echo "  python3 app.py"
echo ""
echo "Then visit: http://localhost:5000"
echo ""
echo "⚠️  Default admin credentials:"
echo "  Username: admin"
echo "  Password: admin123"
echo "  (Please change this password immediately!)"