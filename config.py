import os
import string

CONFIG = {
    "PATHS_TO_WATCH": [f"{d}:/" for d in string.ascii_uppercase if os.path.exists(f"{d}:/")],
    "SCAN_THREADS": 2,
    "FILE_RETRY_ATTEMPTS": 5,
    "FILE_RETRY_DELAY": 1,
    "SKIP_EXTENSIONS": {".tmp", ".partial", ".crdownload", ".download"},
    "SKIP_PATTERNS": {"installer", "setup", "temp"},
    "LOG_FILE": "file_scanner.log",
    "MAX_LOG_SIZE": 10 * 1024 * 1024,
    "LOG_BACKUPS": 3,
    "SIEM_ENDPOINT": "http://localhost:8088/services/collector",
    "SPLUNK_TOKEN": os.getenv("SPLUNK_TOKEN"),
    "COMPLIANCE_DB": "compliance_tracker.db",
    "RISK_THRESHOLD": 0.7,
    "ZERO_TRUST_POLICY": {
        "min_file_size": 1024,
        "blocked_types": [".js", ".vbs"]
    }
}
