#!/usr/bin/env python3
"""Local exfil sink for Attack 2 generation -- the "attacker's server" this
lab starts and controls itself, listening on loopback only. Never reachable
from outside the container, never a real external endpoint. Logs received
POST bodies to --log-path purely so generation can be verified to have
actually reached it, then discards them.
"""
import argparse
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


def make_handler(log_path: str):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            with open(log_path, "a") as f:
                f.write(body + "\n---\n")
            print(f"[sink] received {length} bytes on {self.path}", file=sys.stderr)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format, *args):
            pass  # quiet -- do_POST already prints one line per receipt

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8199)
    parser.add_argument("--log-path", required=True)
    args = parser.parse_args()
    server = HTTPServer(("127.0.0.1", args.port), make_handler(args.log_path))
    print(f"[sink] listening on 127.0.0.1:{args.port}", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
