# config.py
# Global configuration for the OSINT Pivot Engine.
# All modules import from here. 

import logging
logging.getLogger().setLevel(logging.ERROR)

import os
from pathlib import Path
from dotenv import load_dotenv

# Paths resolve against this file, not the working directory — the MCP server
# runs as a subprocess with an arbitrary cwd, where relative paths fail
# silently rather than raising.
PROJECT_ROOT = Path(__file__).resolve().parent
MODEL_DIR = str(PROJECT_ROOT / "models")
DATA_DIR = str(PROJECT_ROOT / "data")
STIX_CACHE_PATH = str(PROJECT_ROOT / "data" / "enterprise-attack.json")

load_dotenv(PROJECT_ROOT / ".env")

# API Keys
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
CENSYS_API_KEY = os.getenv("CENSYS_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY", "")
WHOISXML_API_KEY = os.getenv("WHOISXML_API_KEY", "")
MALWAREBAZAAR_API_KEY = os.getenv("THREATFOX_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

#Agent settings
MAX_PIVOT_DEPTH = 3 # Amount of pivots the agent can make 
MAX_RESULTS_PER_SOURCE = 10

# Output settings
DEFAULT_OUTPUT_FORMAT = "terminal" # options: terminal, json, csv
