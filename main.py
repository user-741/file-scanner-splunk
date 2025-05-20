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
from typing import Optional
from dotenv import load_dotenv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from send2trash import send2trash

load_dotenv()

CONFIG = {
    "PATHS_TO_WATCH": ["/home/kali/Downloads"],
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
    "VIRUSTOTAL_KEY": os.getenv("VIRUSTOTAL_KEY"),
    "COMPLIANCE_DB": "compliance_tracker.db",
    "RISK_THRESHOLD": 0.7,
    "ZERO_TRUST_POLICY": {
        "min_file_size": 1024,
        "blocked_types": [".js", ".vbs"]
    }
}

def setup_logging():
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh = RotatingFileHandler(CONFIG["LOG_FILE"], maxBytes=CONFIG["MAX_LOG_SIZE"], backupCount=CONFIG["LOG_BACKUPS"])
    fh.setFormatter(formatter)
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

logger = setup_logging()

@dataclass
class ScanResult:
    filepath: str
    timestamp: str
    sha256: str
    status: str
    details: dict

    def to_dict(self):
        return {
            "filepath": self.filepath,
            "timestamp": self.timestamp,
            "sha256": self.sha256,
            "status": self.status,
            "details": self.details
        }

class ComplianceTracker:
    def __init__(self):
        self.conn = sqlite3.connect(CONFIG["COMPLIANCE_DB"])
        self.conn.execute('''CREATE TABLE IF NOT EXISTS controls (id TEXT PRIMARY KEY, nist_id TEXT, description TEXT, status TEXT)''')
        self.conn.commit()

    def log_control(self, nist_id: str, description: str):
        control_id = str(uuid.uuid4())
        self.conn.execute('INSERT INTO controls VALUES (?, ?, ?, ?)', (control_id, nist_id, description, "Implemented"))
        self.conn.commit()

class ThreatIntel:
    def map_detection(self, filename: str) -> dict:
        if filename.lower().endswith(".exe"):
            return {
                "technique": "T1204.002",
                "tactic": "Execution",
                "mitigation": "Application whitelisting"
            }
        return {
            "technique": "T1105",
            "tactic": "Command and Control",
            "mitigation": "Network segmentation"
        }

class AISecurityAnalyzer:
    def calculate_entropy(self, data: bytes) -> float:
        import math, collections
        if not data:
            return 0.0
        freq = collections.Counter(data)
        return -sum((count/len(data)) * math.log2(count/len(data)) for count in freq.values())

    def analyze(self, file_data: bytes) -> float:
        entropy = self.calculate_entropy(file_data)
        risk = 0.2
        if entropy > 7.0:
            risk += 0.3
        if len(file_data) > 1_000_000:
            risk += 0.2
        return min(risk, 1.0)

def send_to_siem(event: dict):
    token = CONFIG["SPLUNK_TOKEN"]
    if not token:
        return
    headers = {
        "Authorization": f"Splunk {token}",
        "Content-Type": "application/json"
    }
    payload = {
        "event": event,
        "sourcetype": "_json",
        "source": "file_scanner"
    }
    try:
        requests.post(CONFIG["SIEM_ENDPOINT"], headers=headers, json=payload, verify=False)
    except Exception as e:
        logger.error(f"SIEM error: {e}")

class ScannerEngine:
    def __init__(self):
        self.file_queue = Queue()
        self.processed_files = set()
        self.workers = []
        self.running = True
        self.scan_results = []
        self.result_lock = threading.Lock()
        self.compliance = ComplianceTracker()
        self.threat_intel = ThreatIntel()
        self.compliance.log_control("SI-4", "File integrity monitoring")
        self.compliance.log_control("RA-5", "Vulnerability scanning")

    def start_workers(self):
        for i in range(CONFIG["SCAN_THREADS"]):
            t = threading.Thread(target=self._worker_thread, daemon=True, name=f"Scanner-{i+1}")
            t.start()
            self.workers.append(t)
        logger.info("Scanner workers started")

    def _worker_thread(self):
        while self.running:
            try:
                filepath = self.file_queue.get(timeout=1)
                self._process_file(filepath)
                self.file_queue.task_done()
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Worker error: {e}")

    def _process_file(self, filepath: str):
        if filepath in self.processed_files:
            return
        if any(filepath.endswith(ext) for ext in CONFIG["SKIP_EXTENSIONS"]):
            return
        if any(pattern in filepath.lower() for pattern in CONFIG["SKIP_PATTERNS"]):
            return
        attempts = CONFIG["FILE_RETRY_ATTEMPTS"]
        while attempts > 0:
            try:
                with open(filepath, "rb") as f:
                    data = f.read()
                    sha256 = hashlib.sha256(data).hexdigest()
                    risk_score = AISecurityAnalyzer().analyze(data)
                    detection = self.threat_intel.map_detection(filepath)
                    status = "blocked" if risk_score >= CONFIG["RISK_THRESHOLD"] else "safe"
                    if status == "blocked":
                        send2trash(filepath)
                    result = ScanResult(
                        filepath=filepath,
                        timestamp=str(datetime.now()),
                        sha256=sha256,
                        status=status,
                        details={
                            "risk_score": risk_score,
                            "mitre": detection
                        }
                    )
                    with self.result_lock:
                        self.scan_results.append(result)
                    send_to_siem(result.to_dict())
                    self.processed_files.add(filepath)
                    return
            except Exception:
                attempts -= 1
                time.sleep(CONFIG["FILE_RETRY_DELAY"])

    def queue_file(self, filepath: str):
        self.file_queue.put(filepath)

    def shutdown(self):
        self.running = False
        for t in self.workers:
            t.join()

    def export_results(self):
        with open("scan_results.json", "w") as f:
            json.dump([r.to_dict() for r in self.scan_results], f, indent=2)

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, scanner: ScannerEngine):
        self.scanner = scanner

    def on_created(self, event):
        if not event.is_directory:
            self.scanner.queue_file(event.src_path)

class FileMonitor:
    def __init__(self, scanner: ScannerEngine):
        self.observer = Observer()
        self.handler = FileEventHandler(scanner)

    def start(self):
        for path in CONFIG["PATHS_TO_WATCH"]:
            self.observer.schedule(self.handler, path, recursive=False)
        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join()

def main():
    scanner = ScannerEngine()
    monitor = FileMonitor(scanner)
    scanner.start_workers()
    monitor.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
        scanner.shutdown()
        scanner.export_results()

if __name__ == "__main__":
    main()
