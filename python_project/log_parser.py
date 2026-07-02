# log_parser.py
"""
SOC Log Parser Module
=====================
This module handles reading, validating, and normalizing raw CSV log files.
In a professional SOC workflow, parsing must be resilient to corrupted records, 
missing fields, and malformed timestamps. It transforms raw string data into 
structured dictionaries with typed variables (datetime objects, booleans)
that the Threat Detector and Risk Engine can analyze reliably.
"""

import csv
import sys
from datetime import datetime


class LogParser:
    """
    Handles CSV parsing, field validation, and data normalization for security logs.
    """
    def __init__(self, filepath):
        self.filepath = filepath
        self.parsed_records = []
        self.error_count = 0

    def parse_logs(self):
        """
        Reads CSV and parses each row into a normalized structure.
        Gracefully handles missing files, empty lines, and malformed timestamps.
        """
        try:
            with open(self.filepath, mode='r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                
                # Verify header requirements
                required_headers = {'timestamp', 'username', 'ip_address', 'event_type', 'status', 'details', 'is_admin'}
                actual_headers = set(reader.fieldnames or [])
                missing_headers = required_headers - actual_headers
                
                if missing_headers:
                    print(f"[-] PARSE ERROR: Log file is missing critical security headers: {missing_headers}", file=sys.stderr)
                    sys.exit(1)

                for line_num, row in enumerate(reader, start=2):
                    try:
                        # Extract and strip values
                        raw_time = row['timestamp'].strip()
                        username = row['username'].strip()
                        ip_address = row['ip_address'].strip()
                        event_type = row['event_type'].strip()
                        status = row['status'].strip()
                        details = row['details'].strip()
                        is_admin_str = row['is_admin'].strip().lower()

                        # 1. Normalize Timestamp (Supports ISO 8601 / standard UTC stamps)
                        try:
                            # Replace 'Z' with UTC offset for datetime compatibility
                            clean_time = raw_time.replace('Z', '+00:00')
                            timestamp = datetime.fromisoformat(clean_time)
                        except ValueError:
                            # Fallback parse format for common CSV exports
                            timestamp = datetime.strptime(raw_time, "%Y-%m-%d %H:%M:%S")

                        # 2. Normalize Booleans
                        is_admin = is_admin_str in ('true', '1', 'yes', 'y')

                        # Build structured record
                        record = {
                            'id': line_num - 1,
                            'timestamp': timestamp,
                            'raw_timestamp': raw_time,
                            'username': username,
                            'ip_address': ip_address,
                            'event_type': event_type,
                            'status': status,
                            'details': details,
                            'is_admin': is_admin
                        }
                        self.parsed_records.append(record)

                    except Exception as e:
                        self.error_count += 1
                        print(f"[!] WARNING: Failed parsing log record at line {line_num}: {e}. Skipping.", file=sys.stderr)

            # Sort records chronologically to guarantee accurate time-window threat detection
            self.parsed_records.sort(key=lambda x: x['timestamp'])
            return self.parsed_records

        except FileNotFoundError:
            print(f"[-] CRITICAL ERROR: Log file '{self.filepath}' was not found. Please verify the path.", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[-] CRITICAL ERROR during log ingestion: {e}", file=sys.stderr)
            sys.exit(1)

    def get_summary(self):
        """Returns brief statistics on the parser session."""
        return {
            "total_parsed": len(self.parsed_records),
            "errors_skipped": self.error_count,
            "span_start": self.parsed_records[0]['timestamp'] if self.parsed_records else None,
            "span_end": self.parsed_records[-1]['timestamp'] if self.parsed_records else None
        }


# Quick diagnostic check
if __name__ == "__main__":
    import os
    sample_path = os.path.join(os.path.dirname(__file__), 'sample_logs.csv')
    if os.path.exists(sample_path):
        parser = LogParser(sample_path)
        records = parser.parse_logs()
        summary = parser.get_summary()
        print(f"[+] Diagnostic Parsing Success: Loaded {summary['total_parsed']} records.")
        print(f"[+] Time range: {summary['span_start']} to {summary['span_end']}")
    else:
        print(f"[-] Diagnostic Check: 'sample_logs.csv' not found. Put it in: {sample_path}")
