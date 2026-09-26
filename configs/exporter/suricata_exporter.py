#!/usr/bin/env python3

import json
import os
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Lock, Thread

EVE_FILE = "/var/log/suricata/eve.json"
PORT = 9917

events_total = Counter()
alerts_total = Counter()
alerts_by_signature = Counter()
alerts_by_category = Counter()

counter_lock = Lock()


def process_event(event):
    event_type = event.get("event_type", "unknown")

    with counter_lock:
        events_total[event_type] += 1

        if event_type == "alert":
            alert = event.get("alert", {})

            signature = alert.get("signature", "unknown")
            category = alert.get("category", "unknown")

            alerts_total["total"] += 1
            alerts_by_signature[signature] += 1
            alerts_by_category[category] += 1


def read_existing_events():
    try:
        with open(EVE_FILE, "r") as f:
            for line in f:
                try:
                    event = json.loads(line)
                    process_event(event)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        pass


def monitor_eve():
    while True:
        try:
            with open(EVE_FILE, "r") as f:
                f.seek(0, os.SEEK_END)

                while True:
                    line = f.readline()

                    if line:
                        try:
                            event = json.loads(line)
                            process_event(event)
                        except json.JSONDecodeError:
                            pass
                    else:
                        time.sleep(0.5)

        except FileNotFoundError:
            time.sleep(1)

        except Exception as e:
            print(f"EVE monitor error: {e}")
            time.sleep(1)


def escape_label(value):
    return value.replace("\\", "\\\\").replace('"', '\\"')


class MetricsHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return

        output = []

        with counter_lock:

            output.append("# HELP suricata_events_total Total Suricata events")
            output.append("# TYPE suricata_events_total counter")

            for event_type, count in events_total.items():
                safe_event_type = escape_label(event_type)

                output.append(
                    f'suricata_events_total'
                    f'{{event_type="{safe_event_type}"}} {count}'
                )

            output.append("")

            output.append("# HELP suricata_alerts_total Total Suricata alerts")
            output.append("# TYPE suricata_alerts_total counter")

            output.append(
                f'suricata_alerts_total {alerts_total["total"]}'
            )

            output.append("")

            output.append(
                "# HELP suricata_alerts_by_signature_total "
                "Suricata alerts grouped by signature"
            )
            output.append("# TYPE suricata_alerts_by_signature_total counter")

            for signature, count in alerts_by_signature.items():
                safe_signature = escape_label(signature)

                output.append(
                    f'suricata_alerts_by_signature_total'
                    f'{{signature="{safe_signature}"}} {count}'
                )

            output.append("")

            output.append(
                "# HELP suricata_alerts_by_category_total "
                "Suricata alerts grouped by category"
            )
            output.append("# TYPE suricata_alerts_by_category_total counter")

            for category, count in alerts_by_category.items():
                safe_category = escape_label(category)

                output.append(
                    f'suricata_alerts_by_category_total'
                    f'{{category="{safe_category}"}} {count}'
                )

        body = "\n".join(output) + "\n"

        self.send_response(200)
        self.send_header(
            "Content-Type",
            "text/plain; version=0.0.4"
        )
        self.send_header(
            "Content-Length",
            str(len(body))
        )
        self.end_headers()

        self.wfile.write(body.encode())


if __name__ == "__main__":

    # Load existing events once
    read_existing_events()

    # Start background monitor for new events
    monitor_thread = Thread(
        target=monitor_eve,
        daemon=True
    )

    monitor_thread.start()

    server = HTTPServer(
        ("0.0.0.0", PORT),
        MetricsHandler
    )

    print(f"Suricata exporter listening on :{PORT}")

    server.serve_forever()
