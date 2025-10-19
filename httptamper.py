#!/usr/bin/env python3
"""
httptamper - spinner-enhanced HTTP methods tester
"""

from __future__ import annotations
import argparse
import json
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterator, List, Dict, Optional
from urllib.parse import urlparse, urlunparse

import requests
import pyfiglet
from colorama import Fore, Style, init as color_init

STOP_EVENT = threading.Event()
EXECUTOR: ThreadPoolExecutor | None = None
SPINNER = None  # your Spinner instance

# init colorama
color_init(autoreset=True)

SAFE_DEFAULT_METHODS = ["GET", "HEAD", "OPTIONS", "POST", "TRACE", "CONNECT", "FOO", "BAR"]
ALL_METHODS = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "FOO", "BAR"]

# ---------- CLI ----------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Spinner HTTP methods tester from a wordlist of URLs")
    p.add_argument("-w", "--wordlist", required=True,
                   help="Path to wordlist file (one URL per line). Use '-' to read from stdin.")
    
    p.add_argument("-m", "--methods", default=",".join(SAFE_DEFAULT_METHODS),
                   help=("Comma-separated HTTP methods to test. "
                         f"Default: {','.join(SAFE_DEFAULT_METHODS)}. "
                         "⚠️ Dangerous methods (PUT, DELETE, PATCH) are excluded by default."
                   )
    )
    p.add_argument(
        "-a", "--all",
        action="store_true",
        help="Test all HTTP methods (including dangerous methods like PUT and DELETE). Overrides --methods."
    )

    p.add_argument("-t", "--threads", type=int, default=10, help="Number of worker threads")
    p.add_argument("-c", "--cookies", default=None,
                   help='Cookies string, e.g. "k1=v1; k2=v2" (optional)')
    p.add_argument("-o", "--output", default=None, help="JSON output file (if omitted, prints summary only)")
    p.add_argument("--no-banner", action="store_true", help="Do not print ASCII banner")
    return p


# ---------- helpers ----------
def parse_cookies(cookie_str: Optional[str]) -> Dict[str, str]:
    if not cookie_str:
        return {}
    cookies: Dict[str, str] = {}
    for part in cookie_str.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return raw
    parsed = urlparse(raw, "http")
    if not parsed.netloc and parsed.path and "." in parsed.path:
        parsed = urlparse("http://" + raw)
    return urlunparse(parsed)


def load_urls(path: str) -> Iterator[str]:
    if path == "-":
        fh = sys.stdin
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            yield normalize_url(line)
        return

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Wordlist not found: {path}")
    with p.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            yield normalize_url(line)


def print_banner() -> None:
    banner = pyfiglet.figlet_format("httptamper", font="slant")
    
    print(Fore.WHITE + Style.BRIGHT + banner + Style.RESET_ALL, file=sys.stderr)
    print("\t\t 💀 Fuck them APIs 💀\n")


# ---------- probing ----------
def probe_one(session: requests.Session, url: str, method: str, timeout: float = 6.0) -> Dict:
    method = method.upper()
    entry = {
        "method": method,
        "status_code": None,
        "reason": None,
        "elapsed": None,
        "error": None,
    }
    try:
        start = time.time()
        resp = session.request(method, url, timeout=timeout, allow_redirects=True)
        entry["status_code"] = resp.status_code
        entry["reason"] = resp.reason
        entry["elapsed"] = round(time.time() - start, 3)
    except requests.RequestException as e:
        entry["error"] = f"{type(e).__name__}: {e}"
    except Exception as e:
        entry["error"] = f"{type(e).__name__}: {e}"
    return entry


def worker_task(url: str, methods: List[str], cookies: Dict[str, str], timeout: float = 6.0) -> Dict:
    session = requests.Session()
    if cookies:
        session.cookies.update(cookies)
    session.headers.update({"User-Agent": "httptamper/1.0"})
    result = {"url": url, "methods": {}}
    for m in methods:
        result["methods"][m] = probe_one(session, url, m, timeout)
    session.close()
    return result


# ---------- spinner thread ----------
class Spinner:
    def __init__(self, total: int):
        self._spinner_cycle = ["|", "/", "-", "\\"]
        self._idx = 0
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.total = total
        self.done = 0
        self.current: Optional[str] = None

    def start(self):
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def _run(self):
        while not self._stop.is_set():
            with self._lock:
                ch = self._spinner_cycle[self._idx % len(self._spinner_cycle)]
                cur = self.current or ""
                done = self.done
                total = self.total
                self._idx += 1
            # build line and write to stderr, carriage-return to overwrite
            line = f" {ch} Probing: [{done}/{total}] {cur}"
            # pad to clear previous content
            sys.stderr.write("\r" + line + " " * 10)
            sys.stderr.flush()
            time.sleep(0.08)
        # Clear line on finish
        sys.stderr.write("\r" + " " * 80 + "\r")
        sys.stderr.flush()

    def stop(self):
        self._stop.set()

    def update(self, done: int, current: Optional[str]):
        with self._lock:
            self.done = done
            self.current = current

    def clear(self):
        """Clear the spinner line immediately (use before printing)."""
        with self._lock:
            sys.stderr.write("\r" + " " * 80 + "\r")
            sys.stderr.flush()


# ---------- main ----------
def main():
    # --- graceful Ctrl+C support ---
    import signal
    import threading

    stop_event = threading.Event()
    spinner = None
    executor = None

    def handle_sigint(signum, frame):
        """Handle Ctrl+C cleanly."""
        stop_event.set()
        if spinner:
            try:
                spinner.clear()
            except Exception:
                pass

        sys.stderr.write(Fore.YELLOW + "\n[!] Interrupted by user — stopping...\n" + Style.RESET_ALL)
        sys.stderr.flush()
        # stop spinner immediately
        if spinner:
            try:
                spinner.stop()
            except Exception:
                pass
        # tell executor to stop accepting new work
        if executor:
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass
        # return control; main will exit gracefully
        return

    signal.signal(signal.SIGINT, handle_sigint)
    # --------------------------------------------

    args = build_parser().parse_args()

    if not args.no_banner:
        print_banner()
    print(Fore.YELLOW + "[*] httptamper - Simple HTTP methods tester" + Style.RESET_ALL, file=sys.stderr)
    print(Fore.YELLOW + "[*] Developed by Vapour\n" + Style.RESET_ALL, file=sys.stderr)

    # --- safety check for dangerous methods ---
    if args.all:
        methods = ALL_METHODS.copy()
    else:
        methods = [m.strip().upper() for m in args.methods.split(",") if m.strip()]

    if not methods:
        print(Fore.RED + "[!] No methods specified; aborting." + Style.RESET_ALL, file=sys.stderr)
        sys.exit(2)

    # Warn if dangerous methods present
    dangerous = {"PUT", "DELETE", "CONNECT", "TRACE"}
    present_dangerous = [m for m in methods if m in dangerous]
    if present_dangerous:
        print(
            Fore.RED + Style.BRIGHT +
            "[!] Warning: the following methods may alter or delete data on the target server: "
            f"{', '.join(present_dangerous)}\n"
            "    Proceed only if you have explicit permission!" +
            Style.RESET_ALL,
            file=sys.stderr
        )
        # small pause so user can notice the warning (remove if you find it annoying)
        time.sleep(1.3)
    # -------------------------------------------------------------

    cookies = parse_cookies(args.cookies)
    urls = list(load_urls(args.wordlist))
    total_urls = len(urls)
    if total_urls == 0:
        print(Fore.RED + "[!] No URLs found in wordlist." + Style.RESET_ALL, file=sys.stderr)
        sys.exit(1)

    print(Fore.CYAN + f"[i] Found {total_urls} URL(s). Testing {len(methods)} method(s): "
          f"{', '.join(methods)}" + Style.RESET_ALL, file=sys.stderr)

    results: List[Dict] = []
    start_time = time.time()

    spinner = Spinner(total=total_urls)
    spinner.start()

    done_count = 0
    future_to_url = {}

    try:
        with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
            executor = ex  # make visible to signal handler
            for url in urls:
                if stop_event.is_set():
                    break
                fut = ex.submit(worker_task, url, methods, cookies)
                future_to_url[fut] = url

            for fut in as_completed(future_to_url):
                if stop_event.is_set():
                    break

                url = future_to_url[fut]
                spinner.update(done_count, url)

                try:
                    res = fut.result()
                    results.append(res)
                    done_count += 1
                    spinner.update(done_count, None)
                    ok_any = any((entry.get("status_code") or 0) in range(200, 400)
                                 for entry in res["methods"].values())
                    spinner.clear()
                    status = Fore.GREEN + "[OK]" if ok_any else Fore.RED + "[NO]"
                    print(f"{status}{Style.RESET_ALL} {res['url']}", file=sys.stderr)
                except Exception as e:
                    done_count += 1
                    spinner.update(done_count, None)
                    url = future_to_url.get(fut, "<unknown>")
                    spinner.clear()
                    print(Fore.RED + f"[ERR] {url} -> {e}" + Style.RESET_ALL, file=sys.stderr)

    except KeyboardInterrupt:
        # fallback if signal handler missed
        stop_event.set()
        sys.stderr.write(Fore.YELLOW + "\n[!] KeyboardInterrupt detected — cleaning up...\n" + Style.RESET_ALL)

    finally:
        # stop spinner safely
        if spinner:
            try:
                spinner.stop()
            except Exception:
                pass
        # shutdown executor quickly
        if executor:
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass

    # if interrupted, exit immediately (no report generation)
    if stop_event.is_set():
        spinner.clear()
        sys.stderr.write(Fore.YELLOW + "[!] Interrupted before completion — exiting cleanly.\n" + Style.RESET_ALL)
        sys.exit(130)

    # --- normal completion path ---
    elapsed = round(time.time() - start_time, 2)
    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_urls": total_urls,
        "methods_tested": methods,
        "runtime_seconds": elapsed,
        "results": results,
    }

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(Fore.GREEN + f"\n[+] Report written to {args.output}" + Style.RESET_ALL, file=sys.stderr)
    else:
        print(json.dumps(report, indent=2))

    succ_urls = sum(1 for r in results if any(
        ((m.get("status_code") or 0) >= 200 and (m.get("status_code") or 0) < 400)
        for m in r["methods"].values()))

    print(Fore.CYAN + "\nSummary:" + Style.RESET_ALL, file=sys.stderr)
    print(f"  Total URLs: {Fore.WHITE}{total_urls}{Style.RESET_ALL}", file=sys.stderr)
    print(f"  URLs with 2xx/3xx: {Fore.GREEN}{succ_urls}{Style.RESET_ALL}", file=sys.stderr)
    print(f"  Runtime: {Fore.YELLOW}{elapsed}s{Style.RESET_ALL}\n", file=sys.stderr)

if __name__ == "__main__":
    main()
