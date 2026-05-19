# Detection thresholds
SYN_RATE_THRESHOLD = 100    # SYNs/s per IP
UDP_RATE_THRESHOLD = 500    # UDP packets/s per IP
ICMP_RATE_THRESHOLD = 200   # ICMP echo/s per IP
RATE_WINDOW = 5             # seconds for sliding window

# Block settings
BLOCK_TTL = 300             # seconds

# Anomaly detection
ANOMALY_WINDOW = 60         # seconds for rolling baseline
ANOMALY_MIN_SAMPLES = 3
ANOMALY_STDDEV_MULT = 3.0

# Entropy engine
ENTROPY_WINDOW = 10         # seconds
ENTROPY_HIGH_THRESH = 7.0
ENTROPY_PORT_LOW_THRESH = 2.0

# Count-Min Sketch
CMS_WIDTH = 4096
CMS_DEPTH = 4
CMS_PROMOTE_THRESHOLD = 3   # CMS estimate must exceed this for exact tracking

# SYN cookies
SYN_COOKIE_TIMESLOT = 64    # seconds (two slots accepted)

# IP reputation
import os as _os
REPUTATION_DECAY_LAMBDA = 0.001  # half-life ≈ 693s ≈ 11 min
REPUTATION_DB_PATH = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "reputation.db")

# Score tiers (lower bound of each tier)
TIER_MONITOR = 0
TIER_RATE_LIMIT = 30
TIER_CHALLENGE = 60
TIER_BLOCK = 80

# Token bucket
TOKEN_BUCKET_CAPACITY = 100
TOKEN_BUCKET_RATE_LIMIT_FACTOR = 0.2   # 20% capacity when rate-limited

# Infrastructure
DASHBOARD_PORT = 5000
DEFAULT_INTERFACE = "eth0"
FIREWALL_CHAIN = "DDOS_MITIGATE"
WHITELIST_FILE = "whitelist.txt"
