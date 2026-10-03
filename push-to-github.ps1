# CYBERSPLOI - Push to GitHub Script (Windows)
# Run this after creating a repository on GitHub

param(
    [string]$Username = "your-github-username",
    [string]$Repo = "cybersploi"
)

Write-Host "🚀 CYBERSPLOI GitHub Push Script"
Write-Host ""
Write-Host "To push your code to GitHub:"
Write-Host ""
Write-Host "STEP 1: Create GitHub Repository"
Write-Host "  1. Go to https://github.com/new"
Write-Host "  2. Repository name: cybersploi"
Write-Host "  3. Select Public or Private"
Write-Host "  4. DO NOT initialize with README"
Write-Host "  5. Click 'Create repository'"
Write-Host ""
Write-Host "STEP 2: Update credentials in this script"
Write-Host "  Change USERNAME to your GitHub username"
Write-Host "  Change REPO to your repository name"
Write-Host ""
Write-Host "STEP 3: Run this script with your username"
Write-Host ""

if ($Username -eq "your-github-username") {
    Write-Host "❌ Please provide your GitHub username!"
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\push-to-github.ps1 -Username your-username -Repo cybersploi"
    Write-Host ""
    Write-Host "Example:"
    Write-Host "  .\push-to-github.ps1 -Username peter-great -Repo cybersploi"
    exit 1
}

Write-Host "✅ Using GitHub username: $Username"
Write-Host "✅ Repository: $Repo"
Write-Host ""

$CybersploiPath = Join-Path (Get-Location) "cybersploi"

if (-not (Test-Path $CybersploiPath)) {
    Write-Host "❌ Could not find cybersploi directory at: $CybersploiPath"
    exit 1
}

Push-Location $CybersploiPath

Write-Host "📋 Configuring git..."
git config user.name "Peter Great"
git config user.email "peter@cybersploi.com"

Write-Host "🔗 Adding GitHub remote..."
git remote remove origin 2>$null  # Remove if exists
git remote add origin "https://github.com/$Username/$Repo.git"

Write-Host "🌿 Renaming branch to main..."
git branch -M main

Write-Host "📤 Pushing code to GitHub..."
git push -u origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "✅ SUCCESS! Code pushed to GitHub"
    Write-Host ""
    Write-Host "View your repository:"
    Write-Host "  https://github.com/$Username/$Repo"
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "❌ Push failed!"
    Write-Host ""
    Write-Host "Troubleshooting:"
    Write-Host "  1. Verify GitHub username is correct"
    Write-Host "  2. Verify repository exists on GitHub"
    Write-Host "  3. Check internet connection"
    Write-Host "  4. If using SSH, configure SSH keys"
}

Pop-Location
