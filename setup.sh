#!/bin/bash

# Activity 2 - Threat Model - Data Flow Diagram - Web-based User Feedback System
# Automated Setup Script
# Author: Marc Reyes <hi@marcr.xyz>
#
# This script automatically installs all dependencies required for the threat model
# following OWASP pytm documentation and best practices.

set -e  # Exit on any error

echo "🔧 Setting up Web Feedback System Threat Model Environment"
echo "=========================================================="

# Check if we're on macOS or Linux
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macOS"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="Linux"
else
    echo "❌ Unsupported operating system: $OSTYPE"
    echo "This script supports macOS and Linux only."
    exit 1
fi

echo "📋 Detected OS: $OS"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check Python 3
echo "🐍 Checking Python 3..."
if command_exists python3; then
    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
    echo "✅ Python 3 found: $PYTHON_VERSION"
    PYTHON_CMD="python3"
elif command_exists python; then
    PYTHON_VERSION=$(python --version 2>&1 | cut -d' ' -f2)
    if [[ $PYTHON_VERSION == 3.* ]]; then
        echo "✅ Python 3 found: $PYTHON_VERSION"
        PYTHON_CMD="python"
    else
        echo "❌ Python 3 required, found Python $PYTHON_VERSION"
        exit 1
    fi
else
    echo "❌ Python 3 not found. Please install Python 3.x first."
    exit 1
fi

# Install Graphviz
echo "📊 Installing Graphviz..."
if command_exists dot; then
    echo "✅ Graphviz already installed: $(dot -V 2>&1)"
else
    if [[ "$OS" == "macOS" ]]; then
        if command_exists brew; then
            echo "🍺 Installing Graphviz via Homebrew..."
            brew install graphviz
        elif command_exists conda; then
            echo "🐍 Installing Graphviz via Conda..."
            conda install -c conda-forge graphviz
        else
            echo "❌ Please install Homebrew or Conda first, then run this script again."
            echo "   Homebrew: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
            exit 1
        fi
    elif [[ "$OS" == "Linux" ]]; then
        if command_exists apt-get; then
            echo "📦 Installing Graphviz via apt..."
            sudo apt-get update
            sudo apt-get install -y graphviz
        elif command_exists yum; then
            echo "📦 Installing Graphviz via yum..."
            sudo yum install -y graphviz
        elif command_exists conda; then
            echo "🐍 Installing Graphviz via Conda..."
            conda install -c conda-forge graphviz
        else
            echo "❌ Please install Graphviz manually using your package manager."
            exit 1
        fi
    fi
fi

# Check Java
echo "☕ Checking Java..."
if command_exists java; then
    JAVA_VERSION=$(java -version 2>&1 | head -n 1)
    echo "✅ Java found: $JAVA_VERSION"
else
    echo "📦 Installing Java..."
    if [[ "$OS" == "macOS" ]]; then
        if command_exists brew; then
            brew install openjdk@11
            echo 'export PATH="/opt/homebrew/opt/openjdk@11/bin:$PATH"' >> ~/.zshrc
        else
            echo "❌ Please install Java manually or install Homebrew first."
            exit 1
        fi
    elif [[ "$OS" == "Linux" ]]; then
        if command_exists apt-get; then
            sudo apt-get install -y openjdk-11-jdk
        elif command_exists yum; then
            sudo yum install -y java-11-openjdk-devel
        else
            echo "❌ Please install Java manually using your package manager."
            exit 1
        fi
    fi
fi

# Download PlantUML
echo "🌱 Downloading PlantUML..."
if [[ -f "plantuml.jar" ]]; then
    echo "✅ PlantUML already exists"
else
    echo "📥 Downloading plantuml.jar..."
    if command_exists wget; then
        wget -O plantuml.jar "http://sourceforge.net/projects/plantuml/files/plantuml.jar/download"
    elif command_exists curl; then
        curl -L -o plantuml.jar "http://sourceforge.net/projects/plantuml/files/plantuml.jar/download"
    else
        echo "❌ Please install wget or curl to download PlantUML."
        exit 1
    fi

    if [[ -f "plantuml.jar" ]]; then
        echo "✅ PlantUML downloaded successfully"
    else
        echo "❌ Failed to download PlantUML"
        exit 1
    fi
fi

# Test PlantUML
echo "🧪 Testing PlantUML..."
if java -jar plantuml.jar -version >/dev/null 2>&1; then
    echo "✅ PlantUML working correctly"
else
    echo "❌ PlantUML test failed"
    exit 1
fi

# Install Python dependencies
echo "📦 Installing Python dependencies..."
if [[ -f "requirements.txt" ]]; then
    echo "📋 Installing from requirements.txt..."
    if $PYTHON_CMD -m pip install -r requirements.txt 2>/dev/null; then
        echo "✅ Python dependencies installed"
    else
        echo "🔧 Using --break-system-packages flag..."
        $PYTHON_CMD -m pip install --break-system-packages -r requirements.txt
        echo "✅ Python dependencies installed"
    fi
else
    echo "📋 Installing pytm directly..."
    if $PYTHON_CMD -m pip install "pytm>=1.3.1" "graphviz>=0.20.1" 2>/dev/null; then
        echo "✅ Core dependencies installed"
    else
        echo "🔧 Using --break-system-packages flag..."
        $PYTHON_CMD -m pip install --break-system-packages "pytm>=1.3.1" "graphviz>=0.20.1"
        echo "✅ Core dependencies installed"
    fi
fi

# Test pytm installation
echo "🧪 Testing pytm installation..."
if $PYTHON_CMD -c "from pytm import TM, Actor, Server, Datastore, Dataflow, Boundary, Data, Classification; print('✅ pytm imported successfully')" 2>/dev/null; then
    echo "✅ pytm installation verified"
else
    echo "❌ pytm installation failed"
    exit 1
fi

# Create output directory
echo "📁 Creating output directory..."
mkdir -p output
echo "✅ Output directory created"

# Test the threat model
echo "🧪 Testing threat model..."
if $PYTHON_CMD web_feedback_system_dfd.py >/dev/null 2>&1; then
    echo "✅ Threat model runs successfully"
else
    echo "❌ Threat model test failed"
    exit 1
fi

# Final verification
echo ""
echo "🎉 Setup Complete!"
echo "=================="
echo "✅ Python 3: $PYTHON_VERSION"
echo "✅ Graphviz: $(dot -V 2>&1 | head -n 1)"
echo "✅ Java: $(java -version 2>&1 | head -n 1 | cut -d'"' -f2)"
echo "✅ PlantUML: $(java -jar plantuml.jar -version 2>&1 | head -n 1)"
echo "✅ pytm: Installed and working"
echo ""
echo "🚀 Ready to use! Try these commands:"
echo "   make help           # Show all available commands"
echo "   make dfd            # Generate Data Flow Diagram"
echo "   make seq            # Generate Sequence Diagram"
echo "   make list-threats   # List all available threats"
echo "   python web_feedback_system_dfd.py --help  # Show all options"
echo ""
echo "📖 See README.md for complete documentation"
