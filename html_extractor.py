#!/usr/bin/env python3
"""
HTML Body Content Extractor for Cyber Sploi UI Documentation
Extracts body content from all HTML files in the UI documentation folder
"""

import os
import re
import json
from pathlib import Path
from bs4 import BeautifulSoup

# Configuration
BASE_DIR = r"c:\Users\PETER GREAT\Desktop\CYBERSPLOI\my UI doc"

def extract_title_from_html(html_content):
    """Extract title from HTML"""
    match = re.search(r'<title>([^<]+)</title>', html_content, re.IGNORECASE)
    return match.group(1) if match else "Untitled"

def extract_body_content(html_content):
    """Extract body content from HTML"""
    match = re.search(r'<body[^>]*>(.*?)</body>', html_content, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else ""

def detect_navbar(body_content):
    """Detect if page has navbar"""
    navbar_patterns = [r'<nav[^>]*>',  r'<header[^>]*>',  r'class=["\'].*?navbar',  r'class=["\'].*?header']
    return any(re.search(pattern, body_content, re.IGNORECASE) for pattern in navbar_patterns)

def detect_sidebar(body_content):
    """Detect if page has sidebar"""
    sidebar_patterns = [r'<aside[^>]*>', r'class=["\'].*?sidebar', r'class=["\'].*?side-nav']
    return any(re.search(pattern, body_content, re.IGNORECASE) for pattern in sidebar_patterns)

def get_main_classes(body_content):
    """Extract main container classes"""
    match = re.search(r'<main[^>]*class=["\']([^"\']*)["\']', body_content, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r'<main[^>]*>', body_content, re.IGNORECASE)
    return "< main>" if match else ""

def classify_component_type(folder_name, body_content):
    """Classify component type"""
    if any(x in folder_name.lower() for x in ['detail', 'item', 'profile']):
        return "page"
    elif any(x in folder_name.lower() for x in ['dashboard', 'panel', 'hub', 'portal']):
        return "page"
    elif any(x in folder_name.lower() for x in ['modal', 'dialog']):
        return "modal"
    elif any(x in folder_name.lower() for x in ['layout', 'template', 'shell']):
        return "layout"
    else:
        return "page"

def process_html_files():
    """Process all HTML files and extract data"""
    
    results = {
        "pages": [],
        "summary": {
            "total_pages": 0,
            "pages_with_navbar": 0,
            "pages_with_sidebar": 0,
            "common_patterns": [],
            "shared_components": []
        }
    }
    
    # Collect all component types and patterns
    component_types = {}
    has_navbar_count = 0
    has_sidebar_count = 0
    common_components = set()
    
    # Process each folder
    for folder in sorted(os.listdir(BASE_DIR)):
        folder_path = os.path.join(BASE_DIR, folder)
        if not os.path.isdir(folder_path):
            continue
            
        html_file = os.path.join(folder_path, "code.html")
        if not os.path.exists(html_file):
            continue
            
        try:
            with open(html_file, 'r', encoding='utf-8') as f:
                html_content = f.read()
                
            title = extract_title_from_html(html_content)
            body_content = extract_body_content(html_content)
            has_navbar = detect_navbar(body_content)
            has_sidebar = detect_sidebar(body_content)
            main_classes = get_main_classes(body_content)
            component_type = classify_component_type(folder, body_content)
            
            # Track statistics
            if has_navbar:
                has_navbar_count += 1
            if has_sidebar:
                has_sidebar_count += 1
              
            # Extract component names from classes and elements
            component_pattern = r'class=["\']([^"\']*(?:card|button|menu|modal|form|table|grid|list|item|widget)[^"\']*)["\']'
            components = set(re.findall(component_pattern, body_content, re.IGNORECASE))
            common_components.update(components)
            
            page_entry = {
                "name": folder,
                "path": f"my UI doc/{folder}/code.html",
                "title": title,
                "bodyContent": body_content,
                "hasNavbar": has_navbar,
                "hasSidebar": has_sidebar,
                "mainClasses": main_classes,
                "componentType": component_type
            }
            
            results["pages"].append(page_entry)
            
        except Exception as e:
            print(f"Error processing {folder}: {e}")
            continue
    
    # Update summary
    results["summary"]["total_pages"] = len(results["pages"])
    results["summary"]["pages_with_navbar"] = has_navbar_count
    results["summary"]["pages_with_sidebar"] = has_sidebar_count
    results["summary"]["shared_components"] = list(common_components)[:20]  # Top 20
    results["summary"]["common_patterns"] = [
        "Tailwind CSS styling",
        "Material Symbols Icons",
        "Responsive grid layouts",
        "Dark mode theme",
        "HUD/Terminal aesthetic",
        "Cyan accent colors",
        "Glassmorphism effects",
        "Fixed header/sidebar navigation"
    ]
    
    return results

def main():
    print("Extracting HTML body content from all UI documentation files...")
    results = process_html_files()
    
    # Save to JSON
    output_file = os.path.join(BASE_DIR, "..", "html_extraction_report.json")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n✓ Extraction complete!")
    print(f"Total pages processed: {results['summary']['total_pages']}")
    print(f"Pages with navbar: {results['summary']['pages_with_navbar']}")
    print(f"Pages with sidebar: {results['summary']['pages_with_sidebar']}")
    print(f"\nReport saved to: {output_file}")

if __name__ == "__main__":
    main()
