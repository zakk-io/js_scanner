# app.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, json, time, concurrent.futures as cf
from collections import defaultdict, deque
from typing import Dict, List, Set, Tuple
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify

app = Flask(__name__)

DETECTION_REGEX = r"""(?i)((access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([0-9a-zA-Z\-_=]{8,64})['"]"""
PATTERN = re.compile(DETECTION_REGEX)

def normalize_url(base: str, href: str) -> str:
    if not href: return ""
    u = urljoin(base, href); u, _ = urldefrag(u); return u

def same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    def port(s): return 443 if s == "https" else 80
    return (pa.scheme, pa.hostname, pa.port or port(pa.scheme)) == (pb.scheme, pb.hostname, pb.port or port(pb.scheme))

def extract_scripts_from_html(base_url: str, html_text: str, debug: bool=False) -> List[str]:
    soup = BeautifulSoup(html_text, "html.parser")
    urls = []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if not src: continue
        if src.strip().lower().startswith("data:"): continue
        if src.startswith("//"):
            parsed = urlparse(base_url)
            src = f"{parsed.scheme}:{src}"
        u = normalize_url(base_url, src)
        if u:
            urls.append(u)
            if debug: print(f"[debug]   <script src> -> {u}")
    return urls

def load_robots_txt(session: requests.Session, root: str, timeout: int) -> Set[str]:
    disallows = set()
    try:
        r = session.get(urljoin(root, "/robots.txt"), timeout=timeout, allow_redirects=True)
        if r.status_code == 200:
            ua_any = False
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"): continue
                if line.lower().startswith("user-agent:"):
                    ua_any = (line.split(":",1)[1].strip() == "*")
                elif ua_any and line.lower().startswith("disallow:"):
                    path = line.split(":",1)[1].strip()
                    if path: disallows.add(path)
    except Exception:
        pass
    return disallows

def allowed_by_robots(disallows: Set[str], url: str, root: str) -> bool:
    try:
        pr, pu = urlparse(root), urlparse(url)
        if (pr.scheme, pr.netloc) != (pu.scheme, pu.netloc): return True
        path = pu.path or "/"
        return not any(path.startswith(p) for p in disallows)
    except Exception:
        return True

def _ensure_root_and_index_targets(start_url: str) -> List[str]:
    u = start_url.rstrip("/")
    parsed = urlparse(u)
    targets = []
    if not parsed.path or parsed.path == "":
        targets = [u + "/", u + "/index.html"]
    else:
        targets = [start_url]
        if start_url.endswith("/"):
            targets.append(start_url + "index.html")
    seen, out = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t); out.append(t)
    return out

def crawl_and_collect_js(start_url: str, session: requests.Session, max_pages: int, max_js: int,
                         allow_offsite_js: bool, timeout: int, respect_robots: bool,
                         scan_inline: bool, debug: bool) -> Tuple[List[str], Dict[str, List[str]]]:
    base_origin = start_url
    queue = deque(_ensure_root_and_index_targets(start_url))
    seen_pages: Set[str] = set()
    seen_js: Set[str] = set()
    js_urls: List[str] = []
    inline_hits: Dict[str, List[str]] = defaultdict(list)

    disallows = load_robots_txt(session, base_origin, timeout) if respect_robots else set()

    while queue and len(seen_pages) < max_pages and len(js_urls) < max_js:
        page = queue.popleft()
        if page in seen_pages: continue
        seen_pages.add(page)

        if respect_robots and not allowed_by_robots(disallows, page, base_origin):
            if debug: print(f"[debug] robots.txt disallow -> {page}")
            continue

        try:
            r = session.get(page, timeout=timeout, allow_redirects=True)
            if r.status_code >= 400:
                if debug: print(f"[debug] {r.status_code} on {page}")
                continue
            html = r.text or ""
        except Exception as e:
            if debug: print(f"[debug] fetch error on {page}: {e}")
            continue

        if debug: print(f"[debug] HTML page -> {page}")

        # 1) collect JS from <script src=...>
        for s in extract_scripts_from_html(page, html, debug):
            if not allow_offsite_js and not same_origin(base_origin, s):
                if debug: print(f"[debug]   skip offsite JS (same-origin-only): {s}")
                continue
            if s not in seen_js:
                seen_js.add(s); js_urls.append(s)
                if len(js_urls) >= max_js: break

        # 2) optionally scan inline JS
        if scan_inline:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all("script"):
                if tag.get("src"): continue
                code = tag.string or ""
                if not code.strip(): continue
                for m in PATTERN.finditer(code):
                    frag = code[max(0, m.start()-80):m.end()+80]
                    inline_hits[page].append(frag)

        # 3) discover more same-origin pages
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a"):
            href = a.get("href")
            if not href: continue
            u = normalize_url(page, href)
            if u and same_origin(base_origin, u) and u not in seen_pages:
                queue.append(u)

    return js_urls, inline_hits

def fetch_url(url: str, session: requests.Session, timeout: int) -> Tuple[str, str]:
    r = session.get(url, timeout=timeout, allow_redirects=True)
    return (url, r.text or "")

def read_local(path: str) -> Tuple[str, str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return (path, fh.read())

def walk_local_paths(root: str, recursive: bool) -> List[str]:
    root = os.path.abspath(root)
    if os.path.isfile(root):
        return [root] if root.lower().endswith((".js",".mjs")) else []
    out = []
    if recursive:
        for d, _, files in os.walk(root):
            for f in files:
                if f.lower().endswith((".js",".mjs")): out.append(os.path.join(d,f))
    else:
        for f in os.listdir(root):
            p = os.path.join(root,f)
            if os.path.isfile(p) and f.lower().endswith((".js",".mjs")): out.append(p)
    return out

def scan_text_for_leaks(js_text: str, pattern: re.Pattern) -> List[Dict[str, str]]:
    hits = []
    for m in pattern.finditer(js_text):
        keyword_blob = m.group(1) or ""
        keyword = m.group(2) or keyword_blob.strip()[:64]
        operator = m.group(3) or ""
        value = m.group(4) or ""
        start, end = m.span()
        ctx = js_text[max(0,start-80):min(len(js_text),end+80)].replace("\n"," ")
        hits.append({"keyword": keyword, "operator": operator, "value": value, "context": ctx})
    return hits

def _parse_header_string(h: str) -> Dict[str, str]:
    d = {}
    for pair in (h or "").split(";"):
        if ":" in pair:
            k, v = pair.split(":", 1)
            d[k.strip()] = v.strip()
    return d

def run_scan(
    url: str = None,
    js: List[str] | str = None,
    path: str = None,
    recursive: bool = False,
    max_pages: int = 100,
    max_js: int = 800,
    timeout: int = 15,
    threads: int = 16,
    headers: Dict[str,str] | str = "",
    proxy: str = "",
    insecure: bool = False,
    same_origin_only: bool = False,
    ignore_robots: bool = False,
    scan_inline: bool = False,
    debug: bool = False
) -> Dict[str, List[Dict[str, str]]]:
    session = requests.Session()
    session.headers.update({"User-Agent": "leakscan/flask"})
    if isinstance(headers, str):
        headers = _parse_header_string(headers)
    session.headers.update(headers or {})
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    session.verify = not insecure

    js_targets: List[str] = []

    # explicit JS list
    if js:
        if isinstance(js, str):
            js_targets.extend([u.strip() for u in js.split(",") if u.strip()])
        else:
            js_targets.extend([u.strip() for u in js if u and u.strip()])

    # crawl
    inline_hits = {}
    if url:
        js_urls, inline_hits = crawl_and_collect_js(
            start_url=url,
            session=session,
            max_pages=max_pages,
            max_js=max_js,
            allow_offsite_js=(not same_origin_only),
            timeout=timeout,
            respect_robots=(not ignore_robots),
            scan_inline=scan_inline,
            debug=debug
        )
        js_targets.extend(js_urls)

    # local fs
    if path:
        js_targets.extend(walk_local_paths(path, recursive))

    # de-dup preserve order
    seen, ordered = set(), []
    for t in js_targets:
        if t not in seen:
            seen.add(t); ordered.append(t)

    def task(target: str) -> Tuple[str, str]:
        if target.startswith("http://") or target.startswith("https://"):
            return fetch_url(target, session, timeout)
        return read_local(target)

    results: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(task, t) for t in ordered]
        for fut in cf.as_completed(futures):
            try:
                src, text = fut.result()
            except Exception as e:
                if debug: print(f"[debug] fetch/read error: {e}")
                continue
            hits = scan_text_for_leaks(text, PATTERN)
            if hits:
                results[src].extend(hits)

    # Return ONLY the simple mapping { "file": [hits], ... }
    return dict(results)

@app.get("/health")
def health():
    return jsonify({"ok": True})

@app.post("/scan")
def scan_endpoint():
    """
    JSON body (all optional except one of: url/js/path):
    {
      "url": "http://host[:port]/start",
      "js": ["https://cdn.example/app.js", "..."] or "https://.../a.js,https://.../b.js",
      "path": "/local/folder/or/file",
      "recursive": false,
      "max_pages": 100,
      "max_js": 800,
      "timeout": 15,
      "threads": 16,
      "headers": "K: V;K2: V2" or {"K":"V"},
      "proxy": "http://127.0.0.1:8080",
      "insecure": false,
      "same_origin_only": false,
      "ignore_robots": false,
      "scan_inline": false,
      "debug": false
    }
    """
    data = request.get_json(silent=True) or {}
    if not any([data.get("url"), data.get("js"), data.get("path")]):
        return jsonify({"error": "Provide one of url, js, or path"}), 400

    findings = run_scan(
        url=data.get("url"),
        js=data.get("js"),
        path=data.get("path"),
        recursive=bool(data.get("recursive", False)),
        max_pages=int(data.get("max_pages", 100)),
        max_js=int(data.get("max_js", 800)),
        timeout=int(data.get("timeout", 15)),
        threads=int(data.get("threads", 16)),
        headers=data.get("headers", ""),
        proxy=data.get("proxy", ""),
        insecure=bool(data.get("insecure", False)),
        same_origin_only=bool(data.get("same_origin_only", False)),
        ignore_robots=bool(data.get("ignore_robots", False)),
        scan_inline=bool(data.get("scan_inline", False)),
        debug=bool(data.get("debug", False)),
    )
    # Simple JSON object: { "<file>": [ {keyword, operator, value, context}, ... ], ... }
    return jsonify(findings), 200

if __name__ == "__main__":
    # Change the port if 5000 is busy
    app.run(host="0.0.0.0", port=5000)
