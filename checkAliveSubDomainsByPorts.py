# sub_check_ports.py
# Чекер нестандартных портов + цветной вывод (Windows совместимый)
# Установи: pip install requests colorama
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import requests
import sys
from colorama import init as colorama_init, Fore, Style

# Инициализируем colorama (для корректных цветов в Windows)
colorama_init()

# --- Настройки ---
INFILE = "req.txt"
HTTP_TIMEOUT = 4.0
TCP_TIMEOUT = 2.0
WORKERS = 100
PORTS = [8000, 8080, 8088, 8443, 3000, 5000, 9000]
# --------------------

requests.packages.urllib3.disable_warnings()

def tcp_connect(host: str, port: int, timeout: float = TCP_TIMEOUT) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def probe_http(host: str, port: int, timeout: float = HTTP_TIMEOUT):
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/"
    try:
        r = requests.head(url, timeout=timeout, allow_redirects=True, verify=False)
        if r.status_code == 405:
            r = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
        return {"ok": True, "scheme": scheme, "status_code": r.status_code, "final_url": r.url}
    except requests.exceptions.SSLError:
        return {"ok": False, "error": "ssl_error", "scheme": "https"}
    except requests.exceptions.RequestException as e:
        return {"ok": False, "error": "request_error", "detail": str(e)}
    except Exception as e:
        return {"ok": False, "error": "other", "detail": str(e)}

def check_host_port(host: str, port: int):
    host = host.strip()
    if not host:
        return None
    res = {"host": host, "port": port, "open": False, "http": None}
    if tcp_connect(host, port):
        res["open"] = True
        res["http"] = probe_http(host, port)
    return res

def load_hosts(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    except FileNotFoundError:
        print(f"Файл {path} не найден. Помести сабдомены в {path} (по одному на строке).")
        sys.exit(1)

def pretty_print(status: str, text: str):
    """Красим вывод в зависимости от статуса"""
    if status in ("OPEN", "OPEN_HTTP"):
        print(Fore.GREEN + text + Style.RESET_ALL)
    elif status == "OPEN_NOHTTP":
        print(Fore.YELLOW + text + Style.RESET_ALL)
    elif status == "CLOSED":
        print(Fore.RED + text + Style.RESET_ALL)
    elif status == "ERROR":
        print(Fore.MAGENTA + text + Style.RESET_ALL)
    else:
        print(text)

def main():
    hosts = load_hosts(INFILE)
    pairs = [(h, p) for h in hosts for p in PORTS]
    print(f"Проверяю {len(hosts)} хостов x {len(PORTS)} портов = {len(pairs)} проверок (workers={WORKERS})")

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = {ex.submit(check_host_port, h, p): (h, p) for (h, p) in pairs}
        for fut in as_completed(futures):
            try:
                r = fut.result()
            except Exception as e:
                h, p = futures[fut]
                pretty_print("ERROR", f"ERROR\t{h}:{p}\t{e}")
                continue
            if r is None:
                continue
            h = r["host"]; p = r["port"]
            if r["open"]:
                http = r["http"]
                if http is None:
                    pretty_print("OPEN", f"OPEN\t{h}:{p}\t(TCP open, no http probe)")
                else:
                    if http.get("ok"):
                        code = http.get("status_code")
                        final = http.get("final_url")
                        pretty_print("OPEN_HTTP", f"OPEN_HTTP\t{h}:{p}\t{http.get('scheme')}\t{code}\t{final}")
                    else:
                        err = http.get("error")
                        detail = http.get("detail", "")
                        pretty_print("OPEN_NOHTTP", f"OPEN_NOHTTP\t{h}:{p}\t{err}\t{detail}")
            else:
                pretty_print("CLOSED", f"CLOSED\t{h}:{p}")

if __name__ == "__main__":
    main()
