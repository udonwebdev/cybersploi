#!/bin/bash
# CYBERSPLOI - Push to GitHub Script
# Run this after creating a repository on GitHub

# STEP 1: Replace USERNAME and REPO with your values
USERNAME="your-github-username"
REPO="cybersploi"

# STEP 2: Create repository on https://github.com/new
# - Repository name: cybersploi
# - Description: CYBERSPLOI - Enterprise Cybersecurity Platform
# - Public or Private: Your choice
# - DO NOT initialize with README

# STEP 3: Run these commands:
cd "$(dirname "$0")/cybersploi"

# Configure user (one time only)
git config user.name "Peter Great"
git config user.email "peter@cybersploi.com"

# Add GitHub remote
git remote add origin https://github.com/$USERNAME/$REPO.git

# Rename branch to main (GitHub default)
git branch -M main

# Push code
git push -u origin main

echo "✅ Code pushed to GitHub!"
echo "View at: https://github.com/$USERNAME/$REPO"
