#!/bin/bash

# AWS Scanner Build and Setup Script

set -e

echo "🔧 AWS Scanner - Build Script"
echo "=============================="

# Check Node.js version
NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo "❌ Error: Node.js 18+ required"
    exit 1
fi

echo "✅ Node.js version: $(node -v)"
echo "✅ npm version: $(npm -v)"

# Clean previous builds
echo "🧹 Cleaning previous builds..."
npm run clean || true

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Run linting
echo "🔍 Running linter..."
npm run lint || echo "⚠️  Lint warnings found"

# Run tests
echo "🧪 Running tests..."
npm run test:coverage

# Build
echo "🔨 Building..."
npm run build

# Create .env file from template
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp .env.example .env || echo "⚠️  Could not create .env file"
fi

echo ""
echo "✅ Build complete!"
echo ""
echo "Next steps:"
echo "1. Configure AWS credentials: aws configure"
echo "2. Run scanner: npm run dev scan"
echo "3. Or: npm start scan --help"
echo ""
echo "Usage examples:"
echo "  npm run dev scan"
echo "  npm run dev scan --region us-west-2"
echo "  npm run dev scan --config config/production-scan.yaml"
echo ""
