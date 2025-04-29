"""
Configuration settings for the website security scanner.
"""
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# API Keys
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

# ZAP Configuration
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")  # ZAP API key if configured
ZAP_PORT = int(os.getenv("ZAP_PORT", "8080"))  # Default ZAP port
ZAP_HOST = os.getenv("ZAP_HOST", "127.0.0.1")  # Default ZAP host

# Docker Configuration
USE_DOCKER = os.getenv("USE_DOCKER", "true").lower() == "true"  # Whether to use Docker for ZAP
DOCKER_IMAGE = os.getenv("DOCKER_IMAGE", "ghcr.io/zaproxy/zaproxy:stable")  # ZAP Docker image
DOCKER_CONTAINER_NAME = os.getenv("DOCKER_CONTAINER_NAME", "zap-security-scanner")  # Container name

# Scan Configuration
DEFAULT_SCAN_LEVEL = os.getenv("DEFAULT_SCAN_LEVEL", "quick")  # Options: quick, standard, full
