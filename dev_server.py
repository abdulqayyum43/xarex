#!/usr/bin/env python3
"""Live-reload dev server for Xarex frontend."""

import os
from pathlib import Path
from livereload import Server

ROOT = Path(__file__).parent / "frontend"
os.chdir(ROOT)

server = Server()
server.watch("index.html")
server.watch("css/style.css")
server.watch("js/app.js")

print(f"\n  Xarex frontend  →  http://localhost:3000\n")
server.serve(root=str(ROOT), port=3000, host="localhost", open_url_delay=1)
