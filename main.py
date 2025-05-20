import os
import time
import json
import hashlib
import threading
import logging
import requests
import sqlite3
import uuid
from queue import Queue, Empty
from datetime import datetime
from logging.handlers import RotatingFileHandler
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from send2trash import send2trash

load_dotenv()

CONFIG = {
    "PATHS_TO_WATCH": ["/home/kali", "~/Documents", "~/Downloads"],
    "SCAN_THREADS": 2,
    "FILE_RETRY_ATTEMPTS": 5,
    "FILE_RETRY_DELAY": 1,
    "SKIP_EXTENSIONS": {".tmp", ".partial", ".crdownload", ".download"},
    "SKIP_PATTERNS": {"installer", "setup", "temp"},
    "LOG_FILE": "file_scanner.log",
    "MAX_LOG_SIZE": 10 * 1024 * 1024,
    "LOG_BACKUPS": 3,
    "SIEM_ENDPOINT": "http://192.168.1.227:8088/services/collector",
    "SPLUNK_TOKEN": os.getenv("SPLUNK_TOKEN"),
    "COMPLIANCE_DB": "compliance_tracker.db",
    "RISK_THRESHOLD": 0.7,
    "ZERO_TRUST_POLICY": {"min_file_size": 1024, "blocked_types": [".js", ".vbs"]}
}

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh = RotatingFileHandler(CONFIG["LOG_FILE"], maxBytes=CONFIG["MAX_LOG_SIZE"], backupCount=CONFIG["LOG_BACKUPS"])
fh.setFormatter(formatter)
ch = logging.StreamHandler()
ch.setFormatter(formatter)
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(fh)
logger.addHandler(ch)

@dataclass
class ScanResult:
    filepath: str
    timestamp: str
    sha256: str
    status: str
    details: dict
    def to_dict(self):
        return {"filepath": self.filepath, "timestamp": self.timestamp, "sha256": self.sha256, "status": self.status, "details": self.details}

class ComplianceTracker:
    def __init__(self):
        self.conn = sqlite3.connect(CONFIG["COMPLIANCE_DB"])
        self.conn.execute('CREATE TABLE IF NOT EXISTS controls (id TEXT PRIMARY KEY, nist_id TEXT, description TEXT, status TEXT)')
        self.conn.commit()
    def log_control(self, nist_id: str, description: str):
        self.conn.execute('INSERT INTO controls VALUES (?, ?, ?, ?)', (str(uuid.uuid4()), nist_id, description, "Implemented"))
        self.conn.commit()

class ThreatIntel:
    def map_detection(self, filename: str) -> dict:
        if filename.lower().endswith(".exe"):
            return {"technique": "T1204.002", "tactic": "Execution", "mitigation": "Application whitelisting"}
        return {"technique": "T1105", "tactic": "Command and Control", "mitigation": "Network segmentation"}

class AISecurityAnalyzer:
    def calculate_entropy(self, data: bytes) -> float:
        import math, collections
        if not data: return 0.0
        freq = collections.Counter(data)
        return -sum((c/len(data))*math.log2(c/len(data)) for c in freq.values())
    def analyze(self, data: bytes) -> float:
        entropy = self.calculate_entropy(data)
        risk = 0.2 + (0.3 if entropy > 7.0 else 0) + (0.2 if len(data) > 1_000_000 else 0)
        return min(risk, 1.0)

def send_to_siem(event: dict):
    token = CONFIG["SPLUNK_TOKEN"]
    if not token: return
    headers = {"Authorization": f"Splunk {token}", "Content-Type": "application/json"}
    requests.post(CONFIG["SIEM_ENDPOINT"], headers=headers, json={"event": event}, verify=False)

class ScannerEngine:
    def __init__(self):
        self.queue = Queue()
        self.processed = set()
        self.running = True
        self.results = []
        self.lock = threading.Lock()
        self.compliance = ComplianceTracker()
        self.threat_intel = ThreatIntel()
        self.compliance.log_control("SI-4", "File integrity monitoring")
        self.compliance.log_control("RA-5", "Vulnerability scanning")
    def start(self):
        for _ in range(CONFIG["SCAN_THREADS"]):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
    def worker(self):
        while self.running:
            try:
                path = self.queue.get(timeout=1)
            except Empty:
                continue
            self.process(path)
            self.queue.task_done()
    def process(self, path: str):
        if path in self.processed: return
        ext = Path(path).suffix.lower()
        if ext in CONFIG["SKIP_EXTENSIONS"] or any(p in path.lower() for p in CONFIG["SKIP_PATTERNS"]): return
        if ext in CONFIG["ZERO_TRUST_POLICY"]["blocked_types"] or Path(path).stat().st_size < CONFIG["ZERO_TRUST_POLICY"]["min_file_size"]:
            status = "BLOCKED"
        else:
            try:
                data = Path(path).read_bytes()
            except:
                return
            hashv = hashlib.sha256(data).hexdigest()
            risk = AISecurityAnalyzer().analyze(data)
            if "malware" in Path(path).name.lower():
                status = "MALICIOUS"
            elif risk >= CONFIG["RISK_THRESHOLD"]:
                status = "HIGH_RISK"
            else:
                status = "CLEAN"
        if status in ("BLOCKED", "MALICIOUS"):
            send2trash(path)
        details = {"risk_score": locals().get("risk", 0), "mitre": self.threat_intel.map_detection(path)}
        result = ScanResult(path, datetime.now().isoformat(), locals().get("hashv", ""), status, details)
        with self.lock:
            self.results.append(result)
        send_to_siem(result.to_dict())
        logger.info(f"{result}")
        self.processed.add(path)
    def queue_file(self, path: str):
        self.queue.put(path)
    def stop(self):
        self.running = False
    def export(self):
        with open("scan_results.json","w") as f:
            json.dump([r.to_dict() for r in self.results], f, indent=2)

class Handler(FileSystemEventHandler):
    def __init__(self, engine): self.engine = engine
    def on_created(self, e): 
        if not e.is_directory: self.engine.queue_file(e.src_path)

def main():
    engine = ScannerEngine()
    observer = Observer()
    observer.schedule(Handler(engine), CONFIG["PATHS_TO_WATCH"][0], recursive=False)
    engine.start()
    observer.start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        engine.stop()
        engine.export()
        observer.join()

if __name__ == "__main__":
    main()
