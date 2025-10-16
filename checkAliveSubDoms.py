from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import sys
from colorama import init as colorama_init, Fore, Style


colorama_init()

requests.packages.urllib3.disable_warnings() 

HTTP_TIMEOUT = 5  

def check_one(host: str) -> str:
    host = host.strip()
    if not host:
        return ""
    # сначала HTTPS
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            
            r = requests.head(url, timeout=HTTP_TIMEOUT, allow_redirects=True, verify=False)
            
            if r.status_code == 405:
                r = requests.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True, verify=False)
            return f"ALIVE\t{host}\t{scheme}\t{r.status_code}\t{r.url}"
        except requests.exceptions.SSLError:
            return f"ALIVE_SSL_ERROR\t{host}\t{scheme}"
        except requests.exceptions.Timeout:
           
            continue
        except requests.exceptions.ConnectionError:
            
            continue
        except Exception as e:
            return f"ERROR\t{host}\t{e}"
    return f"DEAD\t{host}\tno-http-response"

def pretty_print(line: str):
    """Покрасим ALIVE в зелёный. Остальное оставим без изменения (или можно добавить цвета)."""
    if not line:
        return
    parts = line.split("\t", 1)
    tag = parts[0] if parts else ""
    rest = parts[1] if len(parts) > 1 else ""
    if tag == "ALIVE":
        print(Fore.GREEN + line + Style.RESET_ALL)
    elif tag == "ALIVE_SSL_ERROR":
        
        print(Fore.YELLOW + line + Style.RESET_ALL)
    elif tag == "DEAD":
        print(Fore.RED + line + Style.RESET_ALL)
    elif tag == "ERROR":
        print(Fore.MAGENTA + line + Style.RESET_ALL)
    else:
        print(line)

def main():
    infile = "req.txt"
    try:
        with open(infile, "r", encoding="utf-8") as f:
            hosts = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    except FileNotFoundError:
        print(f"Файл {infile} не найден. Помести сабдомены в {infile} (по одному на строке).")
        sys.exit(1)

    workers = min(30, max(4, len(hosts)//5 + 1)) 
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(check_one, h): h for h in hosts}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                pretty_print(res)

if __name__ == "__main__":
    main()
