# config.py
# Global configuration for the OSINT Pivot Engine.
# All modules import from here. 

import os
from dotenv import load_dotenv

load_dotenv()

# API Keys
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
CENSYS_API_KEY = os.getenv("CENSYS_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

#Agent settings
MAX_PIVOT_DEPTH = 3 # Amount of pivots the agent can make 
MAX_RESULTS_PER_SOURCE = 10

# Output settings
DEFAULT_OUTPUT_FORMAT = "terminal" # options: terminal, json, csv
