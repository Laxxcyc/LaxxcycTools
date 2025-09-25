#!/usr/bin/env python3
"""
scr.py - LaxxcyTools AGGRESSIVE (same-domain only) Scraper for Termux
Author: DevSonnet-Termux-Search (adapted for LaxxcyTools)
Description:
 - Aggressive defaults: multi-thread, low delay, deeper link-following.
 - Strictly SAME DOMAIN: script WILL NOT download assets from other domains.
 - Resume support using MD5 checksum; saves metadata.json and url_map.csv.
 - Filters via --types (html,css,js,images,other), --only-images option.
 - Safety: --ignore-robots optional but asks confirmation.
 - Additional controls: --max-requests, --jitter (random delay), --no-blink to disable blinking.
Notes:
 - Single-file, Python stdlib only.
 - Use responsibly even though defaults are aggressive.
"""

from __future__ import annotations
import sys, os, re, time, json, csv, queue, threading, hashlib, random
import urllib.request, urllib.parse, urllib.robotparser
from html.parser import HTMLParser
from datetime import datetime
from typing import Set, Optional

# ---------------- DEFAULTS (Aggressive but SAME-DOMAIN) ----------------
USER_AGENT_DEFAULT = "LaxxcyTools/2.0 (aggressive-mode)"
THREADS_DEFAULT = 12        # aggressive default
DELAY_DEFAULT = 0.02        # tiny base delay (jitter will add randomness)
DEPTH_DEFAULT = 3           # follow links up to depth 3 by default
MAX_FILE_SIZE = 160 * 1024 * 1024  # 160 MB guard
SAVE_INDEX_FOR_DIR = True
ALLOWED_SCHEMES = ("http", "https")
MAX_REQUESTS_DEFAULT = 10000

# ---------------- ASCII + ANSI UI ----------------
LAXXCY_ASCII = r'''
 _                _  __  _____
| |    __ _  ___ (_)/ _\|_   _|__  __ _ ___
| |   / _` |/ _ \| \ \  | | |/ _ \/ _` / __|
| |__| (_| | (_) | |\ \ | | |  __/ (_| \__ \
|_____\__, |\___/|_| \__/ |_|  \___|\__,_|___/
      |___/    LaxxcyTools - Termux Scraper (AGGRESSIVE)
'''
CSI = "\033["
RESET = CSI + "0m"
BOLD = CSI + "1m"
RED = CSI + "31m"
YELLOW = CSI + "33m"
GREEN = CSI + "32m"
BLINK = CSI + "5m"

def print_header(ignore_robots_flag: bool, blink_on: bool):
    try:
        os.system("")  # enable ANSI on some terminals
    except Exception:
        pass
    print(LAXXCY_ASCII)
    if blink_on:
        warn = f"{BLINK}{RED}{BOLD}!!! WARNING: AGGRESSIVE MODE ACTIVE — USE RESPONSIBLY !!!{RESET}"
    else:
        warn = f"{RED}{BOLD}!!! WARNING: AGGRESSIVE MODE ACTIVE — USE RESPONSIBLY !!!{RESET}"
    print(warn)
    print()
    summary = f"{YELLOW}Defaults:{RESET} depth={DEPTH_DEFAULT} threads={THREADS_DEFAULT} base-delay={DELAY_DEFAULT}s (with jitter)"
    if ignore_robots_flag:
        summary += f"  {RED}[IGNORING robots.txt]{RESET}"
    print(summary)
    print()

# ---------------- Helpers ----------------
def safe_mkdir(path):
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        pass

def md5sum_bytes(data: bytes) -> str:
    h = hashlib.md5()
    h.update(data)
    return h.hexdigest()

def normalize_url(base: str, link: str) -> str:
    return urllib.parse.urljoin(base, link)

def url_to_local(base_output: str, base_url: str, resource_url: str) -> str:
    parsed = urllib.parse.urlparse(urllib.parse.urljoin(base_url, resource_url))
    host = parsed.netloc or urllib.parse.urlparse(base_url).netloc
    path = parsed.path or "/"
    if path.endswith("/"):
        path = path + "index.html" if SAVE_INDEX_FOR_DIR else path + "index"
    if not os.path.splitext(path)[1]:
        # assign .html if no extension
        path = path + ".html"
    safe_path = os.path.normpath(host + path)
    if safe_path.startswith(".."):
        safe_path = safe_path.replace("..", "")
    local = os.path.join(base_output, safe_path.lstrip("/"))
    return local

def same_domain_only(base: str, url: str, allow_subdomains: bool=False) -> bool:
    pb = urllib.parse.urlparse(urllib.parse.urljoin(base, url))
    pa = urllib.parse.urlparse(base)
    na = pa.netloc.lower()
    nb = pb.netloc.lower()
    if allow_subdomains:
        # allow if nb endswith na
        return nb == na or nb.endswith("." + na)
    return nb == na

_css_url_re = re.compile(r'url\(\s*["\']?(.*?)["\']?\s*\)', re.IGNORECASE)

# ---------------- HTML Parser ----------------
class ResourceParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base = base_url
        self.css: Set[str] = set()
        self.js: Set[str] = set()
        self.img: Set[str] = set()
        self.links: Set[str] = set()
        self.others: Set[str] = set()
        self.meta: dict = {}
        self.inline_styles = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "link":
            href = a.get("href")
            rel = a.get("rel","").lower()
            if href:
                if "stylesheet" in rel or href.lower().endswith(".css"):
                    self.css.add(normalize_url(self.base, href))
                else:
                    self.others.add(normalize_url(self.base, href))
        elif tag == "script":
            src = a.get("src")
            if src:
                self.js.add(normalize_url(self.base, src))
        elif tag == "img":
            src = a.get("src")
            if src:
                self.img.add(normalize_url(self.base, src))
            srcset = a.get("srcset")
            if srcset:
                for part in srcset.split(","):
                    url = part.strip().split()[0]
                    if url:
                        self.img.add(normalize_url(self.base, url))
        elif tag == "a":
            href = a.get("href")
            if href:
                self.links.add(normalize_url(self.base, href))
        if tag == "meta":
            name = a.get("name") or a.get("property") or a.get("http-equiv")
            if name:
                self.meta[name.lower()] = a.get("content") or a.get("value") or ""
        style = a.get("style")
        if style:
            self.inline_styles.append(style)

    def error(self, message):
        pass

def extract_css_urls(css_text: str, base_url: str):
    found = set()
    for m in _css_url_re.finditer(css_text):
        raw = m.group(1).strip()
        if raw and not raw.startswith("data:"):
            found.add(normalize_url(base_url, raw))
    return found

def extract_from_inline_styles(styles, base_url):
    s = set()
    for st in styles:
        for m in _css_url_re.finditer(st):
            raw = m.group(1).strip()
            if raw and not raw.startswith("data:"):
                s.add(normalize_url(base_url, raw))
    return s

# ---------------- Crawler (aggressive but same-domain) ----------------
class AggressiveCrawler:
    def __init__(self, start_url: str, outdir: str,
                 threads: int=THREADS_DEFAULT,
                 base_delay: float=DELAY_DEFAULT,
                 jitter: float=0.02,
                 depth: int=DEPTH_DEFAULT,
                 include_subdomains: bool=False,
                 ignore_robots: bool=False,
                 types_filter: Optional[Set[str]]=None,
                 only_images: bool=False,
                 max_requests: int=MAX_REQUESTS_DEFAULT,
                 user_agent: str=USER_AGENT_DEFAULT,
                 blink_on: bool=True):
        self.start_url = start_url if urllib.parse.urlparse(start_url).scheme else "http://" + start_url
        self.outdir = outdir
        self.threads = max(1, threads)
        self.base_delay = max(0.0, float(base_delay))
        self.jitter = max(0.0, float(jitter))
        self.depth = max(0, int(depth))
        self.include_subdomains = include_subdomains
        self.ignore_robots = ignore_robots
        self.types_filter = types_filter or set(["html","css","js","images","other"])
        self.only_images = only_images
        self.max_requests = max_requests
        self.user_agent = user_agent
        self.blink_on = blink_on

        self.q = queue.Queue()
        self.visited = set()  # (url, depth)
        self.lock = threading.Lock()
        self.workers = []
        self.stop_event = threading.Event()

        self.stats = {"downloaded":0, "failed":0, "bytes":0, "queued":0, "requests":0}
        # robots
        self.robot = urllib.robotparser.RobotFileParser()
        try:
            self.robot.set_url(urllib.parse.urljoin(self.start_url, "/robots.txt"))
            if not self.ignore_robots:
                self.robot.read()
        except Exception:
            pass

        # outputs
        self.metadata = {}
        self.url_map_rows = []  # list of tuples (url, local_path, content_type, size, md5)

    def allowed_by_robots(self, url: str) -> bool:
        if self.ignore_robots:
            return True
        try:
            return self.robot.can_fetch(self.user_agent, url)
        except Exception:
            return True

    def enqueue(self, url: str, curdepth: int):
        full = normalize_url(self.start_url, url)
        full = urllib.parse.urldefrag(full)[0]
        # enforce same-domain only
        if not same_domain_only(self.start_url, full, allow_subdomains=self.include_subdomains):
            return
        key = (full, curdepth)
        with self.lock:
            if key in self.visited or self.stats["requests"] >= self.max_requests:
                return
            self.visited.add(key)
            self.stats["queued"] += 1
        self.q.put((full, curdepth))

    def _type_allowed_by_filter(self, content_hint: str, url: str) -> bool:
        hint = (content_hint or "").lower() + " " + url.lower()
        if self.only_images:
            # allow images and css (for backgrounds)
            if any(x in hint for x in ("image/", ".png", ".jpg", ".jpeg", ".gif", ".svg")):
                return True
            if "text/css" in hint or url.endswith(".css"):
                return True
            return False
        # normal filter:
        if "html" in self.types_filter and ("text/html" in hint or url.endswith(".html") or url.endswith("/")):
            return True
        if "css" in self.types_filter and ("text/css" in hint or url.endswith(".css")):
            return True
        if "js" in self.types_filter and ("javascript" in hint or url.endswith(".js")):
            return True
        if "images" in self.types_filter and any(x in hint for x in ("image/",".png",".jpg",".jpeg",".gif",".svg")):
            return True
        if "other" in self.types_filter:
            return True
        return False

    def _file_exists_and_same_md5(self, local_path: str, md5_expected: Optional[str]) -> bool:
        if not os.path.exists(local_path):
            return False
        try:
            with open(local_path, "rb") as f:
                existing = f.read()
            existing_md5 = md5sum_bytes(existing)
            if md5_expected:
                return existing_md5 == md5_expected
            # if expected md5 not provided, assume file present => skip rewrite
            return True
        except Exception:
            return False

    def worker(self):
        opener = urllib.request.build_opener()
        opener.addheaders = [("User-Agent", self.user_agent)]
        while not self.stop_event.is_set():
            try:
                url, curdepth = self.q.get(timeout=1)
            except Exception:
                break
            with self.lock:
                if self.stats["requests"] >= self.max_requests:
                    self.q.task_done()
                    continue
                self.stats["requests"] += 1
            if not self.allowed_by_robots(url):
                with self.lock:
                    self.metadata[url] = {"status":"skipped_by_robots","time":datetime.utcnow().isoformat()}
                    self.q.task_done()
                continue
            try:
                req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
                with opener.open(req, timeout=25) as resp:
                    ct = resp.headers.get("Content-Type","").lower()
                    length = resp.headers.get("Content-Length")
                    expected_len = None
                    if length:
                        try:
                            expected_len = int(length)
                            if expected_len > MAX_FILE_SIZE:
                                raise ValueError("File too large")
                        except Exception:
                            expected_len = None
                    raw = resp.read()
                    headers = dict(resp.getheaders())
                # decide based on types filter / only_images
                if not self._type_allowed_by_filter(ct, url):
                    with self.lock:
                        self.metadata[url] = {"status":"skipped_by_filter","content_type":ct,"time":datetime.utcnow().isoformat()}
                    self.q.task_done()
                    time.sleep(self.base_delay + random.random()*self.jitter)
                    continue

                local = url_to_local(self.outdir, self.start_url, url)
                safe_mkdir(os.path.dirname(local))
                checksum = md5sum_bytes(raw)

                # resume: if local exists and md5 matches, skip
                if self._file_exists_and_same_md5(local, checksum):
                    existing_size = os.path.getsize(local) if os.path.exists(local) else 0
                    with self.lock:
                        self.metadata[url] = {
                            "local_path": os.path.relpath(local, self.outdir),
                            "status": "skipped_exists",
                            "content_type": ct,
                            "size": existing_size,
                            "md5": checksum,
                            "timestamp": datetime.utcnow().isoformat()
                        }
                        self.url_map_rows.append((url, os.path.relpath(local, self.outdir), ct, existing_size, checksum))
                    self.q.task_done()
                    time.sleep(self.base_delay + random.random()*self.jitter)
                    continue

                # write file
                try:
                    with open(local, "wb") as f:
                        f.write(raw)
                except Exception:
                    # fallback incremental write
                    with open(local, "wb") as f:
                        for i in range(0, len(raw), 16384):
                            f.write(raw[i:i+16384])

                with self.lock:
                    self.stats["downloaded"] += 1
                    self.stats["bytes"] += len(raw)

                meta_entry = {
                    "local_path": os.path.relpath(local, self.outdir),
                    "status": "saved",
                    "content_type": ct,
                    "size": len(raw),
                    "md5": checksum,
                    "headers": {k:v for k,v in headers.items() if k.lower() in ("server","x-powered-by","content-type","content-length","set-cookie","cache-control")},
                    "meta_tags": {},
                    "timestamp": datetime.utcnow().isoformat()
                }

                # parse if HTML
                if "text/html" in ct or local.endswith(".html"):
                    try:
                        text = raw.decode("utf-8", errors="ignore")
                        rp = ResourceParser(url)
                        rp.feed(text)
                        meta_entry["meta_tags"] = rp.meta
                        # enqueue assets and inline background images
                        for css in rp.css:
                            self.enqueue(css, curdepth)
                        for js in rp.js:
                            self.enqueue(js, curdepth)
                        for img in rp.img:
                            self.enqueue(img, curdepth)
                        for other in rp.others:
                            self.enqueue(other, curdepth)
                        for bg in extract_from_inline_styles(rp.inline_styles, url):
                            self.enqueue(bg, curdepth)
                        # follow links within same domain up to depth
                        if curdepth < self.depth:
                            for link in rp.links:
                                self.enqueue(link, curdepth+1)
                    except Exception:
                        pass
                # parse CSS for url(...) resources
                elif "text/css" in ct or local.endswith(".css"):
                    try:
                        text = raw.decode("utf-8", errors="ignore")
                        for found in extract_css_urls(text, url):
                            self.enqueue(found, curdepth)
                    except Exception:
                        pass

                with self.lock:
                    self.metadata[url] = meta_entry
                    self.url_map_rows.append((url, os.path.relpath(local, self.outdir), ct, len(raw), checksum))
            except KeyboardInterrupt:
                self.stop_event.set()
            except Exception as e:
                with self.lock:
                    self.stats["failed"] += 1
                    self.metadata[url] = {"status":"error","error":str(e)}
                # print short error line (non-verbose)
                try:
                    print(f"\n[!] Failed: {url} -> {e}")
                except Exception:
                    pass
            finally:
                self.q.task_done()
                time.sleep(self.base_delay + random.random()*self.jitter)

    def start(self):
        # seed
        self.enqueue(self.start_url, 0)

        # start threads
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            self.workers.append(t)

        try:
            while any(t.is_alive() for t in self.workers):
                time.sleep(0.6)
                self._print_status()
                # break condition: queue empty and workers idle (they'll exit)
                if self.q.empty():
                    # allow some time for new enqueues from workers
                    time.sleep(0.6)
                    if self.q.empty():
                        break
            # wait for tasks done
            self.q.join()
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user.")
            self.stop_event.set()

        for t in self.workers:
            t.join(timeout=0.5)

        self._print_summary()
        # save metadata and url map
        try:
            meta_path = os.path.join(self.outdir, "metadata.json")
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(self.metadata, f, indent=2, ensure_ascii=False)
            map_path = os.path.join(self.outdir, "url_map.csv")
            with open(map_path, "w", encoding="utf-8", newline='') as f:
                w = csv.writer(f)
                w.writerow(("url","local_path","content_type","size","md5"))
                for row in self.url_map_rows:
                    w.writerow(row)
            print(f"\nMetadata saved: {meta_path}")
            print(f"URL map saved: {map_path}")
        except Exception as e:
            print("Failed saving metadata / url_map:", e)

    def _print_status(self):
        with self.lock:
            queued = self.q.qsize()
            downloaded = self.stats["downloaded"]
            failed = self.stats["failed"]
            bytes_ = self.stats["bytes"]
            requests = self.stats["requests"]
        sys.stdout.write(f"\rQueued: {queued:5d}  Downloaded: {downloaded:5d}  Failed: {failed:5d}  Bytes: {bytes_:,}  Req: {requests}")
        sys.stdout.flush()

    def _print_summary(self):
        print("\n\n--- Summary ---")
        print("Start URL:", self.start_url)
        print("Output dir:", os.path.abspath(self.outdir))
        print(f"Threads: {self.threads}  Base delay: {self.base_delay}  Jitter: {self.jitter}  Depth: {self.depth}")
        print("Include subdomains:", self.include_subdomains)
        print("Ignore robots.txt:", self.ignore_robots)
        print("Only images mode:", self.only_images)
        print("Types filter:", ",".join(sorted(self.types_filter)))
        print("Max requests:", self.max_requests)
        print("Downloaded:", self.stats["downloaded"])
        print("Failed:", self.stats["failed"])
        print("Total bytes:", self.stats["bytes"])

# ---------------- CLI / Main ----------------
def parse_args(argv):
    import argparse
    p = argparse.ArgumentParser(prog="scr.py", description="LaxxcyTools AGGRESSIVE same-domain scraper")
    p.add_argument("start", nargs="?", help="start URL (optional). If omitted, you'll be prompted.")
    p.add_argument("--out","-o", help="output folder (default: <domain>_laxxcy_tools)", default=None)
    p.add_argument("--threads","-t", type=int, default=THREADS_DEFAULT, help="worker threads")
    p.add_argument("--delay","-d", type=float, default=DELAY_DEFAULT, help="base delay per worker (s)")
    p.add_argument("--jitter", type=float, default=0.02, help="random jitter added to delay (s)")
    p.add_argument("--depth", type=int, default=DEPTH_DEFAULT, help="link-follow depth (0 = assets only)")
    p.add_argument("--subdomains", action="store_true", help="allow crawling subdomains of start domain")
    p.add_argument("--ignore-robots", action="store_true", help="ignore robots.txt (confirm required)")
    p.add_argument("--only-images", action="store_true", help="only download images and css (for backgrounds)")
    p.add_argument("--types", help="comma-separated types to include: html,css,js,images,other", default="html,css,js,images,other")
    p.add_argument("--max-requests", type=int, default=MAX_REQUESTS_DEFAULT, help="stop after this many requests")
    p.add_argument("--user-agent", default=USER_AGENT_DEFAULT, help="custom User-Agent")
    p.add_argument("--no-blink", action="store_true", help="disable blinking in header")
    return p.parse_args(argv[1:])

def main():
    args = parse_args(sys.argv)
    blink_on = not args.no_blink
    ignore_flag = bool(args.ignore_robots)
    print_header(ignore_flag, blink_on)
    if args.start:
        start = args.start.strip()
    else:
        start = input("Paste start URL (or domain) and press Enter: ").strip()
    if not start:
        print("No URL provided. Exiting.")
        return
    if not urllib.parse.urlparse(start).scheme:
        start = "https://" + start  # prefer https
    parsed = urllib.parse.urlparse(start)
    safe_name = parsed.netloc.replace(":","_")
    outdir = args.out or (safe_name + "_laxxcy_tools")
    safe_mkdir(outdir)

    # confirm ignore robots
    if args.ignore_robots:
        print(f"\n{RED}!!! You selected --ignore-robots !!!{RESET}")
        conf = input("Type 'I UNDERSTAND' to proceed: ").strip()
        if conf != "I UNDERSTAND":
            print("Confirmation not given. Exiting.")
            return

    # parse types
    types_set = set([t.strip().lower() for t in args.types.split(",") if t.strip()])
    # normalize images alias
    if "img" in types_set: types_set.add("images")
    print_header(ignore_flag, blink_on)
    print(f"{GREEN}Starting aggressive same-domain scraper ->{RESET} {start}")
    crawler = AggressiveCrawler(
        start_url=start,
        outdir=outdir,
        threads=args.threads,
        base_delay=args.delay,
        jitter=args.jitter,
        depth=args.depth,
        include_subdomains=args.subdomains,
        ignore_robots=args.ignore_robots,
        types_filter=types_set,
        only_images=args.only_images,
        max_requests=args.max_requests,
        user_agent=args.user_agent,
        blink_on=blink_on
    )
    crawler.start()
    print(f"\nSaved files under: {os.path.abspath(outdir)}")
    print("Done.")

if __name__ == "__main__":
    main()