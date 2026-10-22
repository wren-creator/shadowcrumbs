"""Start the dashboard: python run.py  (then open http://127.0.0.1:8470)"""
import argparse

import uvicorn

from shadowcrumbs import config

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Shadowcrumbs recon dashboard")
    ap.add_argument("--host", default="127.0.0.1", help="leave this on localhost, the data is client confidential")
    ap.add_argument("--port", type=int, default=8470)
    args = ap.parse_args()
    loaded, problem = config.load_env_file()
    if loaded:
        print(f"Loaded {len(loaded)} setting(s) from {config.env_file().name}: {', '.join(loaded)}")
    if problem:
        print(f"WARNING: {problem}")
    uvicorn.run("shadowcrumbs.app:app", host=args.host, port=args.port)
