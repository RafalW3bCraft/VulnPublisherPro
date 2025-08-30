#!/usr/bin/env python3
"""
Test script to interact with VulnPublisherPro CLI
"""

import subprocess
import time
import sys
from pathlib import Path

def run_cli_command(command_sequence):
    """Run CLI commands in sequence"""
    try:
        # Start the interactive CLI
        process = subprocess.Popen(
            ["python", "main.py", "interactive"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=0
        )
        
        # Send commands
        for cmd in command_sequence:
            print(f"Sending command: {cmd}")
            process.stdin.write(cmd + '\n')
            process.stdin.flush()
            time.sleep(2)  # Wait for response
        
        # Get output
        try:
            output, error = process.communicate(timeout=10)
            return output, error
        except subprocess.TimeoutExpired:
            process.kill()
            output, error = process.communicate()
            return output, error
            
    except Exception as e:
        print(f"Error running CLI: {e}")
        return None, str(e)

def test_scraping():
    """Test vulnerability scraping"""
    print("Testing vulnerability scraping...")
    commands = ["1", "1", "10"]  # Deep scan, NVD, 10 results
    output, error = run_cli_command(commands)
    print("Scraping Output:", output)
    if error:
        print("Scraping Error:", error)

def test_content_generation():
    """Test content generation"""
    print("Testing content generation...")
    commands = ["5", "1"]  # Content forge, generate from latest
    output, error = run_cli_command(commands)
    print("Generation Output:", output)
    if error:
        print("Generation Error:", error)

def test_publishing():
    """Test publishing to Dev.to"""
    print("Testing publishing to Dev.to...")
    commands = ["7", "1"]  # Stealth pub, dev.to
    output, error = run_cli_command(commands)
    print("Publishing Output:", output)
    if error:
        print("Publishing Error:", error)

if __name__ == "__main__":
    print("Starting VulnPublisherPro CLI Testing...")
    
    # Test each major feature
    test_scraping()
    time.sleep(2)
    test_content_generation() 
    time.sleep(2)
    test_publishing()
    
    print("CLI testing completed.")