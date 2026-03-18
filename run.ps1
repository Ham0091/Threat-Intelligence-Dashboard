#!/usr/bin/env pwsh

# Advanced Threat Intelligence Dashboard - PowerShell Launch Script

Write-Host ""
Write-Host "  || THREAT INTELLIGENCE DASHBOARD ||" -ForegroundColor Cyan
Write-Host "  Glassmorphism OSINT Command Center v2.0" -ForegroundColor Cyan
Write-Host ""

# Check if .env file exists
if (-not (Test-Path '.env')) {
    Write-Host "[!] WARNING: .env file not found!" -ForegroundColor Yellow
    Write-Host "[*] Copying .env.example to .env" -ForegroundColor Yellow
    Copy-Item '.env.example' '.env'
    Write-Host "[*] Please edit .env with your API keys" -ForegroundColor Yellow
    Write-Host ""
}

# Check Python
try {
    $python_version = & python --version 2>&1
    Write-Host "[✓] $python_version" -ForegroundColor Green
} catch {
    Write-Host "[X] Python not found. Please install Python 3.8+" -ForegroundColor Red
    exit 1
}

# Install dependencies
Write-Host "[*] Installing/updating dependencies..." -ForegroundColor Yellow
& python -m pip install -q flask requests python-dotenv flask-cors sqlalchemy

if ($LASTEXITCODE -ne 0) {
    Write-Host "[X] Failed to install dependencies" -ForegroundColor Red
    exit 1
}

Write-Host "[✓] Dependencies ready" -ForegroundColor Green
Write-Host ""
Write-Host "[*] Starting Threat Intelligence Dashboard..." -ForegroundColor Yellow
Write-Host "[*] Open browser: http://localhost:5001" -ForegroundColor Cyan
Write-Host "[*] Press Ctrl+C to stop the server" -ForegroundColor Cyan
Write-Host ""

& python app.py
