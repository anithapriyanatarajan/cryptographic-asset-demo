#!/bin/bash

echo "=== Cryptographic Asset Demo - Build Script ==="
echo

# Check if Java is installed
if ! command -v java &> /dev/null; then
    echo "❌ Java is not installed. Please install Java 11 or higher."
    exit 1
fi

# Check Java version
JAVA_VERSION=$(java -version 2>&1 | grep -oP 'version "?(1\.)?\K\d+' | head -1)
if [ "$JAVA_VERSION" -lt 11 ]; then
    echo "❌ Java 11 or higher is required. Current version: $JAVA_VERSION"
    exit 1
fi

echo "✓ Java $JAVA_VERSION detected"

# Check if Maven is installed
if ! command -v mvn &> /dev/null; then
    echo "❌ Maven is not installed. Please install Maven 3.6 or higher."
    exit 1
fi

echo "✓ Maven detected"
echo

# Build the project
echo "Building the project..."
mvn clean compile

if [ $? -eq 0 ]; then
    echo
    echo "✓ Build successful!"
    echo
    echo "Running the Cryptographic Asset Demo..."
    echo "========================================"
    mvn exec:java
else
    echo "❌ Build failed. Please check the error messages above."
    exit 1
fi
