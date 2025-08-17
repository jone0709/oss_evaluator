# OpenSSF Security Evaluator - MCP Server

🛡️ **Security evaluation for software packages with Claude Desktop integration**

## Overview

The OpenSSF Security Evaluator is a FastMCP server that provides comprehensive security analysis for software packages across multiple ecosystems. It integrates seamlessly with Claude Desktop to provide AI-powered security evaluation capabilities.

## Features

### 🛡️ Security Analysis
- **Vulnerability Scanning** - Real-time vulnerability detection via OSV.dev
- **Supply Chain Protection** - Typosquatting and malicious package detection
- **Version-Specific Analysis** - Evaluate specific package versions
- **Risk Scoring** - 0-100 security scoring system
- **GitHub Security Analysis** - Repository health and maintenance metrics

### 📦 Package Manager Support
- **npm** (JavaScript/Node.js) - ✅ Full support
- **PyPI** (Python) - ✅ Full support  
- **Cargo** (Rust) - ✅ Full support
- **Maven** (Java) - ✅ Full support
- **NuGet** (.NET) - ✅ Full support
- **RubyGems** (Ruby) - ✅ Full support
- **Go Modules** - 🟡 Basic support

### 🔄 Alternative Discovery
- **Enhanced Ranking** - Multi-factor compatibility scoring
- **Curated Alternatives** - AI-picked alternatives for popular packages
- **License Compatibility** - Automatic license checking

## Installation

### Prerequisites
- Python 3.8 or higher
- Claude Desktop application

### Step 1: Clone and Setup
```bash
# Create project directory
mkdir openssf-evaluator
cd openssf-evaluator

# Download the files (or clone if using git)
# Place evaluator.py, requirements.txt, openssf_config.ini in this directory
