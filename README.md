# File Activity Scanner with Splunk

A Python tool that watches a folder in real time, checks every new or changed file, and sends the results to Splunk so they can be searched and alerted on like a SIEM.

## What it does

- **Real-time monitoring** of a folder using `watchdog`, with a pool of worker threads
- **Zero trust checks** that block script types like `.js` and `.vbs` and tiny or incomplete files
- **SHA-256 hashing** of every file it scans
- **Risk scoring** based on file type, location and content entropy (packed or encrypted files score higher)
- **Quarantine** of files flagged as malicious into a `Quarantine` folder
- **MITRE ATT&CK mapping** for each result (for example T1204.002 User Execution)
- **NIST control logging** (SI-4, RA-5) to a local SQLite database
- **Splunk HEC output** so every scan result shows up as a JSON event in Splunk
- Rotating log file and a JSON export of results on exit

Malware detection is simulated: a file is flagged as malicious if its name contains "malware". This is so the quarantine and Splunk alerting flow can be tested safely without real samples.

## Built with

Python, watchdog, requests, SQLite, Splunk HTTP Event Collector.

## Run it

1. Install the requirements:

   ```bash
   pip install -r requirements.txt
   ```

2. Copy `.env.example` to `.env` and fill in your Splunk HEC token. Set `WATCH_PATH` if you want to watch a folder other than Downloads.

3. Start it:

   ```bash
   python main.py
   ```

Press Ctrl+C to stop. Results are saved to `scan_results.json` and `file_scanner.log`.

## Splunk setup

1. In Splunk, go to Settings > Data Inputs > HTTP Event Collector and create a new token.
2. Put the token in `.env` as `SPLUNK_TOKEN`.
3. Search for results with `source="file_scanner"`.
