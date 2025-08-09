#!/usr/bin/env python3
from contextlib import closing
import argparse
import multiprocessing
import os
import os.path
import re
import socket
import subprocess
import sys
import traceback
import urllib.parse
import shlex

import urllib3

import bs4
import dulwich.index
import dulwich.objects
import dulwich.pack
import requests
import socks
from requests_pkcs12 import Pkcs12Adapter

# ------------------------
# util/prints (igual)
# ------------------------
def printf(fmt, *args, file=sys.stdout):
    if args:
        fmt = fmt % args
    file.write(fmt)
    file.flush()

def is_html(response):
    return ("Content-Type" in response.headers
            and "text/html" in response.headers["Content-Type"])

def is_safe_path(path):
    if path.startswith("/"):
        return False
    safe_path = os.path.expanduser("~")
    return (
        os.path.commonpath(
            (os.path.realpath(os.path.join(safe_path, path)), safe_path)
        ) == safe_path
    )

def get_indexed_files(response):
    html = bs4.BeautifulSoup(response.text, "html.parser")
    files = []
    for link in html.find_all("a"):
        url = urllib.parse.urlparse(link.get("href"))
        if (url.path and is_safe_path(url.path) and not url.scheme and not url.netloc):
            files.append(url.path)
    return files

# --- FIX: mensajes consistentes y sin .format roto
def verify_response(response):
    if response.status_code != 200:
        return False, "[-] %s/%s responded with non-200 status\n"
    elif ("Content-Length" in response.headers and str(response.headers["Content-Length"]) == "0"):
        return False, "[-] %s/%s responded with a zero-length body\n"
    elif ("Content-Type" in response.headers and "text/html" in response.headers["Content-Type"]):
        return False, "[-] %s/%s responded with HTML\n"
    else:
        return True, True

def create_intermediate_dirs(path):
    dirname, basename = os.path.split(path)
    if dirname and not os.path.exists(dirname):
        try:
            os.makedirs(dirname)
        except FileExistsError:
            pass

def get_referenced_sha1(obj_file):
    objs = []
    if isinstance(obj_file, dulwich.objects.Commit):
        objs.append(obj_file.tree.decode())
        for parent in obj_file.parents:
            objs.append(parent.decode())
    elif isinstance(obj_file, dulwich.objects.Tree):
        for item in obj_file.iteritems():
            objs.append(item.sha.decode())
    elif isinstance(obj_file, dulwich.objects.Blob):
        pass
    elif isinstance(obj_file, dulwich.objects.Tag):
        pass
    else:
        printf("error: unexpected object type: %r\n" % obj_file, file=sys.stderr)
        sys.exit(1)
    return objs

class Worker(multiprocessing.Process):
    def __init__(self, pending_tasks, tasks_done, args):
        super().__init__()
        self.daemon = True
        self.pending_tasks = pending_tasks
        self.tasks_done = tasks_done
        self.args = args

    def run(self):
        self.init(*self.args)
        while True:
            task = self.pending_tasks.get(block=True)
            if task is None:
                return
            try:
                result = self.do_task(task, *self.args)
            except Exception:
                printf("Task %s raised exception:\n", task, file=sys.stderr)
                traceback.print_exc()
                result = []
            assert isinstance(result, list), "do_task() should return a list of tasks"
            self.tasks_done.put(result)

    def init(self, *args):
        raise NotImplementedError
    def do_task(self, task, *args):
        raise NotImplementedError

def process_tasks(initial_tasks, worker, jobs, args=(), tasks_done=None):
    if not initial_tasks:
        return
    tasks_seen = set(tasks_done) if tasks_done else set()
    pending_tasks = multiprocessing.Queue()
    tasks_done_q = multiprocessing.Queue()
    num_pending_tasks = 0

    for task in initial_tasks:
        assert task is not None
        if task not in tasks_seen:
            pending_tasks.put(task)
            num_pending_tasks += 1
            tasks_seen.add(task)

    processes = [worker(pending_tasks, tasks_done_q, args) for _ in range(jobs)]
    for p in processes:
        p.start()

    while num_pending_tasks > 0:
        task_result = tasks_done_q.get(block=True)
        num_pending_tasks -= 1
        for task in task_result:
            assert task is not None
            if task not in tasks_seen:
                pending_tasks.put(task)
                num_pending_tasks += 1
                tasks_seen.add(task)

    for _ in range(jobs):
        pending_tasks.put(None)
    for p in processes:
        p.join()

class DownloadWorker(Worker):
    def init(self, url, directory, retry, timeout, http_headers, client_cert_p12=None, client_cert_p12_password=None):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers = http_headers
        if client_cert_p12:
            self.session.mount(url, Pkcs12Adapter(pkcs12_filename=client_cert_p12, pkcs12_password=client_cert_p12_password))
        else:
            self.session.mount(url, requests.adapters.HTTPAdapter(max_retries=retry))

    def do_task(self, filepath, url, directory, retry, timeout, http_headers, client_cert_p12=None, client_cert_p12_password=None):
        if os.path.isfile(os.path.join(directory, filepath)):
            printf("[-] Already downloaded %s/%s\n", url, filepath)
            return []
        with closing(self.session.get("%s/%s" % (url, filepath), allow_redirects=False, stream=True, timeout=timeout)) as response:
            printf("[-] Fetching %s/%s [%d]\n", url, filepath, response.status_code)
            valid, error_message = verify_response(response)
            if not valid:
                printf(error_message, url, filepath, file=sys.stderr)
                return []
            abspath = os.path.abspath(os.path.join(directory, filepath))
            create_intermediate_dirs(abspath)
            with open(abspath, "wb") as f:
                for chunk in response.iter_content(4096):
                    f.write(chunk)
            return []

class RecursiveDownloadWorker(DownloadWorker):
    def do_task(self, filepath, url, directory, retry, timeout, http_headers):
        if os.path.isfile(os.path.join(directory, filepath)):
            printf("[-] Already downloaded %s/%s\n", url, filepath)
            return []
        with closing(self.session.get("%s/%s" % (url, filepath), allow_redirects=False, stream=True, timeout=timeout)) as response:
            printf("[-] Fetching %s/%s [%d]\n", url, filepath, response.status_code)
            if (response.status_code in (301, 302) and "Location" in response.headers and response.headers["Location"].endswith(filepath + "/")):
                return [filepath + "/"]
            if filepath.endswith("/"):
                assert is_html(response)
                return [filepath + filename for filename in get_indexed_files(response)]
            else:
                valid, error_message = verify_response(response)
                if not valid:
                    printf(error_message, url, filepath, file=sys.stderr)
                    return []
                abspath = os.path.abspath(os.path.join(directory, filepath))
                create_intermediate_dirs(abspath)
                with open(abspath, "wb") as f:
                    for chunk in response.iter_content(4096):
                        f.write(chunk)
                return []

class FindRefsWorker(DownloadWorker):
    def do_task(self, filepath, url, directory, retry, timeout, http_headers, client_cert_p12=None, client_cert_p12_password=None):
        response = self.session.get("%s/%s" % (url, filepath), allow_redirects=False, timeout=timeout)
        printf("[-] Fetching %s/%s [%d]\n", url, filepath, response.status_code)
        valid, error_message = verify_response(response)
        if not valid:
            printf(error_message, url, filepath, file=sys.stderr)
            return []
        abspath = os.path.abspath(os.path.join(directory, filepath))
        create_intermediate_dirs(abspath)
        with open(abspath, "w") as f:
            f.write(response.text)
        tasks = []
        for ref in re.findall(r"(refs(/[a-zA-Z0-9\-\.\_\*]+)+)", response.text):
            ref = ref[0]
            if not ref.endswith("*") and is_safe_path(ref):
                tasks.append(".git/%s" % ref)
                tasks.append(".git/logs/%s" % ref)
        return tasks

class FindObjectsWorker(DownloadWorker):
    def do_task(self, obj, url, directory, retry, timeout, http_headers, client_cert_p12=None, client_cert_p12_password=None):
        filepath = ".git/objects/%s/%s" % (obj[:2], obj[2:])
        if os.path.isfile(os.path.join(directory, filepath)):
            printf("[-] Already downloaded %s/%s\n", url, filepath)
        else:
            response = self.session.get("%s/%s" % (url, filepath), allow_redirects=False, timeout=timeout)
            printf("[-] Fetching %s/%s [%d]\n", url, filepath, response.status_code)
            valid, error_message = verify_response(response)
            if not valid:
                printf(error_message, url, filepath, file=sys.stderr)
                return []
            abspath = os.path.abspath(os.path.join(directory, filepath))
            create_intermediate_dirs(abspath)
            with open(abspath, "wb") as f:
                f.write(response.content)
        abspath = os.path.abspath(os.path.join(directory, filepath))
        obj_file = dulwich.objects.ShaFile.from_path(abspath)
        return get_referenced_sha1(obj_file)

def sanitize_file(filepath):
    assert os.path.isfile(filepath), "%s is not a file" % filepath
    UNSAFE=r"^\s*fsmonitor|sshcommand|askpass|editor|pager"
    with open(filepath, 'r+') as f:
        content = f.read()
        modified_content = re.sub(UNSAFE, r'# \g<0>', content, flags=re.IGNORECASE)
        if content != modified_content:
            printf("Warning: '%s' file was altered\n" % filepath)
            f.seek(0)
            f.write(modified_content)

def fetch_git(url, directory, jobs, retry, timeout, http_headers, client_cert_p12=None, client_cert_p12_password=None):
    assert os.path.isdir(directory), "%s is not a directory" % directory
    assert jobs >= 1, "invalid number of jobs"
    assert retry >= 1, "invalid number of retries"
    assert timeout >= 1, "invalid timeout"

    session = requests.Session()
    session.verify = False
    session.headers = http_headers
    if client_cert_p12:
        session.mount(url, Pkcs12Adapter(pkcs12_filename=client_cert_p12, pkcs12_password=client_cert_p12_password))
    else:
        session.mount(url, requests.adapters.HTTPAdapter(max_retries=retry))
    if os.listdir(directory):
        printf("Warning: Destination '%s' is not empty\n", directory)

    url = url.rstrip("/")
    if url.endswith("HEAD"):
        url = url[:-4]
    url = url.rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    url = url.rstrip("/")

    printf("[-] Testing %s/.git/HEAD ", url)
    response = session.get("%s/.git/HEAD" % url, timeout=timeout, allow_redirects=False)
    printf("[%d]\n", response.status_code)

    valid, error_message = verify_response(response)
    if not valid:
        printf(error_message, url, "/.git/HEAD", file=sys.stderr)
        return 1
    elif not re.match(r"^(ref:.*|[0-9a-f]{40}$)", response.text.strip()):
        printf("error: %s/.git/HEAD is not a git HEAD file\n", url, file=sys.stderr,)
        return 1

    environment = os.environ.copy()
    configured_proxy = socks.getdefaultproxy()
    if configured_proxy is not None:
        proxy_types = ["http", "socks4h", "socks5h"]
        environment["ALL_PROXY"] = f"http.proxy={proxy_types[configured_proxy[0]]}://{configured_proxy[1]}:{configured_proxy[2]}"

    printf("[-] Testing %s/.git/ ", url)
    response = session.get("%s/.git/" % url, allow_redirects=False)
    printf("[%d]\n", response.status_code)

    if (response.status_code == 200 and is_html(response) and "HEAD" in get_indexed_files(response)):
        printf("[-] Fetching .git recursively\n")
        process_tasks([".git/", ".gitignore"], RecursiveDownloadWorker, jobs, args=(url, directory, retry, timeout, http_headers),)
        os.chdir(directory)
        printf("[-] Sanitizing .git/config\n")
        sanitize_file(".git/config")
        printf("[-] Running git checkout .\n")
        subprocess.check_call(["git", "checkout", "."], env=environment)
        return 0

    printf("[-] Fetching common files\n")
    tasks = [
        ".gitignore",".git/COMMIT_EDITMSG",".git/description",
        ".git/hooks/applypatch-msg.sample",".git/hooks/commit-msg.sample",
        ".git/hooks/post-commit.sample",".git/hooks/post-receive.sample",
        ".git/hooks/post-update.sample",".git/hooks/pre-applypatch.sample",
        ".git/hooks/pre-commit.sample",".git/hooks/pre-push.sample",
        ".git/hooks/pre-rebase.sample",".git/hooks/pre-receive.sample",
        ".git/hooks/prepare-commit-msg.sample",".git/hooks/update.sample",
        ".git/index",".git/info/exclude",".git/objects/info/packs",
    ]
    process_tasks(tasks, DownloadWorker, jobs, args=(url, directory, retry, timeout, http_headers, client_cert_p12, client_cert_p12_password),)

    printf("[-] Finding refs/\n")
    tasks = [
        ".git/FETCH_HEAD",".git/HEAD",".git/ORIG_HEAD",".git/config",".git/info/refs",
        ".git/logs/HEAD",".git/logs/refs/heads/main",".git/logs/refs/heads/master",
        ".git/logs/refs/heads/staging",".git/logs/refs/heads/production",".git/logs/refs/heads/development",
        ".git/logs/refs/remotes/origin/HEAD",".git/logs/refs/remotes/origin/main",".git/logs/refs/remotes/origin/master",
        ".git/logs/refs/remotes/origin/staging",".git/logs/refs/remotes/origin/production",".git/logs/refs/remotes/origin/development",
        ".git/logs/refs/stash",".git/packed-refs",".git/refs/heads/main",".git/refs/heads/master",
        ".git/refs/heads/staging",".git/refs/heads/production",".git/refs/heads/development",
        ".git/refs/remotes/origin/HEAD",".git/refs/remotes/origin/main",".git/refs/remotes/origin/master",
        ".git/refs/remotes/origin/staging",".git/refs/remotes/origin/production",".git/refs/remotes/origin/development",
        ".git/refs/stash",
        ".git/refs/wip/wtree/refs/heads/main",".git/refs/wip/wtree/refs/heads/master",
        ".git/refs/wip/wtree/refs/heads/staging",".git/refs/wip/wtree/refs/heads/production",".git/refs/wip/wtree/refs/heads/development",
        ".git/refs/wip/index/refs/heads/main",".git/refs/wip/index/refs/heads/master",".git/refs/wip/index/refs/heads/staging",
        ".git/refs/wip/index/refs/heads/production",".git/refs/wip/index/refs/heads/development"
    ]
    process_tasks(tasks, FindRefsWorker, jobs, args=(url, directory, retry, timeout, http_headers, client_cert_p12, client_cert_p12_password),)

    printf("[-] Finding packs\n")
    tasks = []
    info_packs_path = os.path.join(directory, ".git", "objects", "info", "packs")
    if os.path.exists(info_packs_path):
        with open(info_packs_path, "r") as f:
            info_packs = f.read()
        for sha1 in re.findall(r"pack-([a-f0-9]{40})\.pack", info_packs):
            tasks.append(".git/objects/pack/pack-%s.idx" % sha1)
            tasks.append(".git/objects/pack/pack-%s.pack" % sha1)
    process_tasks(tasks, DownloadWorker, jobs, args=(url, directory, retry, timeout, http_headers, client_cert_p12, client_cert_p12_password),)

    printf("[-] Finding objects\n")
    objs = set()
    packed_objs = set()
    files = [
        os.path.join(directory, ".git", "packed-refs"),
        os.path.join(directory, ".git", "info", "refs"),
        os.path.join(directory, ".git", "FETCH_HEAD"),
        os.path.join(directory, ".git", "ORIG_HEAD"),
    ]
    for dirpath, _, filenames in os.walk(os.path.join(directory, ".git", "refs")):
        for filename in filenames:
            files.append(os.path.join(dirpath, filename))
    for dirpath, _, filenames in os.walk(os.path.join(directory, ".git", "logs")):
        for filename in filenames:
            files.append(os.path.join(dirpath, filename))
    for filepath in files:
        if not os.path.exists(filepath):
            continue
        with open(filepath, "r") as f:
            content = f.read()
        for obj in re.findall(r"(^|\s)([a-f0-9]{40})($|\s)", content):
            obj = obj[1]
            objs.add(obj)
    index_path = os.path.join(directory, ".git", "index")
    if os.path.exists(index_path):
        index = dulwich.index.Index(index_path)
        for entry in index.iterobjects():
            objs.add(entry[1].decode())
    pack_file_dir = os.path.join(directory, ".git", "objects", "pack")
    if os.path.isdir(pack_file_dir):
        for filename in os.listdir(pack_file_dir):
            if filename.startswith("pack-") and filename.endswith(".pack"):
                pack_data_path = os.path.join(pack_file_dir, filename)
                pack_idx_path = os.path.join(pack_file_dir, filename[:-5] + ".idx")
                pack_data = dulwich.pack.PackData(pack_data_path)
                pack_idx = dulwich.pack.load_pack_index(pack_idx_path)
                pack = dulwich.pack.Pack.from_objects(pack_data, pack_idx)
                for obj_file in pack.iterobjects():
                    packed_objs.add(obj_file.sha().hexdigest())
                    objs |= set(get_referenced_sha1(obj_file))

    printf("[-] Fetching objects\n")
    process_tasks(objs, FindObjectsWorker, jobs, args=(url, directory, retry, timeout, http_headers, client_cert_p12, client_cert_p12_password), tasks_done=packed_objs,)

    printf("[-] Running git checkout .\n")
    os.chdir(directory)
    sanitize_file(".git/config")
    subprocess.call(["git", "checkout", "."], stderr=open(os.devnull, "wb"))

    return 0

# ------------------------
# NUEVO: helpers para listas
# ------------------------
def slug_dir_for_url(u: str) -> str:
    """Genera un nombre de carpeta reproducible a partir de la URL."""
    p = urllib.parse.urlparse(u)
    host = (p.netloc or "unknown").strip()
    path = (p.path or "/").strip("/").replace("/", "_")
    if not path:
        path = "root"
    base = f"{host}_{path}"
    # Sanitiza
    base = re.sub(r"[^a-zA-Z0-9._-]", "_", base)
    # Evita nombres raros tipo '.' o muy cortos
    if base in (".", "..", "", "_"):
        base = "repo_dump"
    return base[:200]  # limita longitud

def parse_list_file(path):
    """Lee archivo de objetivos. Admite:
       - URL
       - URL ESPACIO DIR
       - líneas vacías o con '#': ignoradas
    """
    tasks = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Permite comillas en DIR: usa shlex
            parts = shlex.split(line)
            if len(parts) == 1:
                tasks.append((parts[0], None))
            else:
                url = parts[0]
                outdir = " ".join(parts[1:])  # por si el directorio tenía espacios
                tasks.append((url, outdir))
    return tasks

# ------------------------
# main con soporte -f
# ------------------------
def main():
    parser = argparse.ArgumentParser(
        usage="git-dumper [options] URL DIR | -f LISTFILE",
        description="Dump a git repository from a website (single target or list).",
    )

    # Modo exclusivo: lista o single
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-f", "--file", help="Archivo con objetivos (una URL por línea, opcionalmente 'URL DIR').")

    # Posicionales para modo single
    parser.add_argument("url", nargs="?", help="url")
    parser.add_argument("directory", nargs="?", help="output directory")

    # Opciones existentes
    parser.add_argument("--proxy", help="use the specified proxy")
    parser.add_argument("--client-cert-p12", help="client certificate in PKCS#12")
    parser.add_argument("--client-cert-p12-password", help="password for the client certificate")
    parser.add_argument("-j","--jobs", type=int, default=10, help="number of simultaneous requests (per target)")
    parser.add_argument("-r","--retry", type=int, default=3, help="number of request attempts before giving up")
    parser.add_argument("-t","--timeout", type=int, default=3, help="maximum time in seconds before giving up")
    parser.add_argument("-u","--user-agent", type=str, default="Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0", help="user-agent to use for requests")
    parser.add_argument("-H","--header", type=str, action="append", help="additional http headers, e.g `NAME=VALUE`")

    # NUEVO
    parser.add_argument("--out-base", default=".", help="Carpeta base para salidas en modo -f cuando la línea NO especifique DIR (default: .)")
    parser.add_argument("--parallel-targets", type=int, default=1, help="Procesar N objetivos en paralelo (default: 1)")

    args = parser.parse_args()

    # Validaciones básicas
    if args.file:
        # modo lista
        if args.url or args.directory:
            parser.error("No mezcles -f con URL/DIR posicionales.")
    else:
        # modo single
        if not (args.url and args.directory):
            parser.error("Debes indicar URL y DIR, o usar -f LISTFILE.")

    if args.jobs < 1:
        parser.error("invalid number of jobs, got `%d`" % args.jobs)
    if args.retry < 1:
        parser.error("invalid number of retries, got `%d`" % args.retry)
    if args.timeout < 1:
        parser.error("invalid timeout, got `%d`" % args.timeout)
    if args.parallel_targets < 1:
        parser.error("invalid parallel-targets, got `%d`" % args.parallel_targets)

    # Headers
    http_headers = {"User-Agent": args.user_agent}
    if args.header:
        for header in args.header:
            tokens = header.split("=", maxsplit=1)
            if len(tokens) != 2:
                parser.error("http header must have the form NAME=VALUE, got `%s`" % header)
            name, value = tokens
            http_headers[name.strip()] = value.strip()

    # Proxy
    if args.proxy:
        proxy_valid = False
        for pattern, proxy_type in [
            (r"^socks5:(.*):(\d+)$", socks.PROXY_TYPE_SOCKS5),
            (r"^socks4:(.*):(\d+)$", socks.PROXY_TYPE_SOCKS4),
            (r"^http://(.*):(\d+)$", socks.PROXY_TYPE_HTTP),
            (r"^(.*):(\d+)$", socks.PROXY_TYPE_SOCKS5),
        ]:
            m = re.match(pattern, args.proxy)
            if m:
                socks.setdefaultproxy(proxy_type, m.group(1), int(m.group(2)))
                socket.socket = socks.socksocket
                proxy_valid = True
                break
        if not proxy_valid:
            parser.error("invalid proxy, got `%s`" % args.proxy)

    # Cert cliente
    if args.client_cert_p12:
        if not os.path.exists(args.client_cert_p12):
            parser.error("client certificate `%s` does not exist" % args.client_cert_p12)
        if not os.path.isfile(args.client_cert_p12):
            parser.error("client certificate `%s` is not a file" % args.client_cert_p12)
        if args.client_cert_p12_password is None:
            parser.error("client certificate password is required")

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Construir lista de tareas
    tasks = []
    if args.file:
        for url, maybe_dir in parse_list_file(args.file):
            out_dir = maybe_dir if maybe_dir else os.path.join(args.out_base, slug_dir_for_url(url))
            tasks.append( (url, out_dir) )
    else:
        tasks.append( (args.url, args.directory) )

    # Crear dirs y ejecutar
    def run_one(t):
        url, outdir = t
        try:
            if not os.path.exists(outdir):
                os.makedirs(outdir, exist_ok=True)
            if not os.path.isdir(outdir):
                printf("`%s` is not a directory\n", outdir, file=sys.stderr)
                return 1
            printf("\n===== Target: %s -> %s =====\n", url, outdir)
            rc = fetch_git(url, outdir, args.jobs, args.retry, args.timeout, http_headers, args.client_cert_p12, args.client_cert_p12_password)
            if rc == 0:
                printf("[OK] %s -> %s\n", url, outdir)
            else:
                printf("[FAIL] %s -> %s (rc=%d)\n", url, outdir, rc)
            return rc
        except Exception as e:
            printf("[ERROR] %s -> %s: %s\n", url, outdir, repr(e), file=sys.stderr)
            return 1

    rc_total = 0
    if len(tasks) == 1 or args.parallel_targets == 1:
        for t in tasks:
            rc_total |= run_one(t)
    else:
        from multiprocessing.pool import ThreadPool
        pool = ThreadPool(processes=args.parallel_targets)
        results = pool.map(run_one, tasks)
        pool.close(); pool.join()
        for rc in results:
            rc_total |= (rc or 0)

    sys.exit(rc_total)

if __name__ == "__main__":
    main()