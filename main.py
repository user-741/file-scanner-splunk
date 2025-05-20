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
        self.conn.execute('''CREATE TABLE IF NOT EXISTS controls (
                              id TEXT PRIMARY KEY,
                              nist_id TEXT,
                              description TEXT,
                              status TEXT)''')
        self.conn.commit()

    def log_control(self, nist_id: str, description: str):
        control_id = str(uuid.uuid4())
        self.conn.execute('INSERT INTO controls VALUES (?, ?, ?, ?)',
                          (control_id, nist_id, description, "Implemented"))
        self.conn.commit()

class ThreatIntel:
    def map_detection(self, filename: str) -> dict:
        if filename.lower().endswith(".exe"):
            return {"technique": "T1204.002", "tactic": "Execution", "mitigation": "Application whitelisting"}
        return {"technique": "T1105", "tactic": "Command and Control", "mitigation": "Network segmentation"}

class AISecurityAnalyzer:
    def calculate_entropy(self, data: bytes) -> float:
        import math, collections
        if not data:
            return 0.0
        freq = collections.Counter(data)
        entropy = -sum((count/len(data)) * math.log2(count/len(data)) for count in freq.values())
        return entropy

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
    headers = {"Authorization": f"Splunk {token}", "Content-Type": "application/json"}
    payload = {"event": event, "sourcetype": "_json", "source": "file_scanner"}
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
        if not self._zero_trust_check(filepath):
            self._record_scan_result(filepath, "BLOCKED", {"reason": "Zero Trust violation"})
            return
        file_hash = self._calculate_hash(filepath)
        if not file_hash:
            return
        risk = self._assess_risk(filepath)
        if risk > CONFIG["RISK_THRESHOLD"]:
            self._record_scan_result(filepath, "HIGH_RISK", {"risk_score": risk}, file_hash)
        status = "MALICIOUS" if "malware" in filepath.lower() else "CLEAN"
        self._record_scan_result(filepath, status, {"detection": "Simulated"}, file_hash)
        if status == "MALICIOUS":
            self._quarantine_file(filepath)

    def _zero_trust_check(self, filepath: str) -> bool:
        ext = Path(filepath).suffix.lower()
        if ext in CONFIG["ZERO_TRUST_POLICY"]["blocked_types"]:
            return False
        if Path(filepath).stat().st_size < CONFIG["ZERO_TRUST_POLICY"]["min_file_size"]:
            return False
        return True

    def _calculate_hash(self, filepath: str) -> Optional[str]:
        try:
            b = Path(filepath).read_bytes()
            return hashlib.sha256(b).hexdigest()
        except Exception as e:
            logger.error(f"Hash error: {e}")
            return None

    def _assess_risk(self, filepath: str) -> float:
        ext = Path(filepath).suffix.lower()
        risk = 0.3
        if ext in {".exe", ".dll"}:
            risk += 0.4
        if "temp" in filepath.lower():
            risk += 0.2
        return min(risk, 1.0)

    def _record_scan_result(self, filepath: str, status: str, details: dict, file_hash: str = None):
        result = ScanResult(
            filepath=filepath,
            timestamp=datetime.now().isoformat(),
            sha256=file_hash or "unknown",
            status=status,
            details=details
        )
        with self.result_lock:
            self.scan_results.append(result)
        event = {
            "timestamp": result.timestamp,
            "file": Path(filepath).name,
            "hash": result.sha256,
            "status": status,
            "mitre": self.threat_intel.map_detection(filepath),
            "risk_score": details.get("risk_score", 0)
        }
        send_to_siem(event)
        logger.info(f"Scan Result: {result}")

    def _quarantine_file(self, filepath: str):
        quarantine_dir = Path(filepath).parent / "Quarantine"
        quarantine_dir.mkdir(exist_ok=True)
        try:
            new_path = quarantine_dir / f"QUAR_{Path(filepath).name}"
            Path(filepath).rename(new_path)
            logger.warning(f"Quarantined: {new_path}")
        except Exception as e:
            logger.error(f"Quarantine failed: {e}")

    def queue_file(self, filepath: str) -> bool:
        if filepath in self.processed_files:
            return False
        ext = Path(filepath).suffix.lower()
        if ext in CONFIG["SKIP_EXTENSIONS"]:
            return False
        if any(p in Path(filepath).name.lower() for p in CONFIG["SKIP_PATTERNS"]):
            return False
        self.file_queue.put(filepath)
        return True

    def shutdown(self):
        self.running = False
        for w in self.workers:
            w.join(timeout=5)
        logger.info("Scanner stopped")

    def export_results(self):
        data = [r.to_dict() for r in self.scan_results]
        with open("scan_results.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

class FileHandler(FileSystemEventHandler):
    def __init__(self, scanner: ScannerEngine):
        self.scanner = scanner

    def on_created(self, event):
        if not event.is_directory:
            self.scanner.queue_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            time.sleep(1)
            self.scanner.queue_file(event.src_path)

class FileMonitor:
    def __init__(self, scanner: ScannerEngine):
        self.scanner = scanner
        self.observer = Observer()

    def start(self):
        for path in CONFIG["PATHS_TO_WATCH"]:
            if Path(path).exists():
                self.observer.schedule(FileHandler(self.scanner), path, recursive=True)
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
