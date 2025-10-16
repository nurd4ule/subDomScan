import socket
import subprocess
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init as colorama_init, Fore, Style
import os
import requests

colorama_init()
requests.packages.urllib3.disable_warnings()
HTTP_TIMEOUT = 5
SSH_TIMEOUT = 3
TERRAPIN_EXE_NAMES = ["Terrapin-Scanner.exe", "terrapin-scanner.exe", "Terrapin-Scanner", "terrapin-scanner"]

def check_http(host: str) -> str:
    host = host.strip()
    if not host:
        return ""
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

def tcp_connect(host: str, port:int, timeout:int=SSH_TIMEOUT) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def find_terrapin_exe() -> str | None:
   
    cwd = os.getcwd()
    for name in TERRAPIN_EXE_NAMES:
        p = os.path.join(cwd, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
   
    for name in TERRAPIN_EXE_NAMES:
        path = shutil_which(name)
        if path:
            return path
    return None

def shutil_which(name):
   
    try:
        from shutil import which
        return which(name)
    except Exception:
        return None

def run_terrapin_scan(exe_path: str, host: str, timeout_sec:int=15) -> dict:

    try:
        proc = subprocess.run([exe_path, "-connect", host, "-json"], capture_output=True, text=True, timeout=timeout_sec)
        out = proc.stdout.strip()
        if not out:
          
            out = proc.stderr.strip()
        if not out:
            return {"error": "no-output-from-terrapin"}
       
        try:
            data = json.loads(out)
            return data
        except Exception:
            
            return {"raw": out}
    except subprocess.TimeoutExpired:
        return {"error": "terrapin-timeout"}
    except FileNotFoundError:
        return {"error": "terrapin-not-found"}
    except Exception as e:
        return {"error": str(e)}

def run_nmap_ssh_algos(host: str, timeout_sec:int=20) -> str:

    try:
        proc = subprocess.run(["nmap", "--script", "ssh2-enum-algos", "-p", "22", host], capture_output=True, text=True, timeout=timeout_sec)
        return proc.stdout + proc.stderr
    except Exception:
        return ""

def parse_nmap_algos_output(out: str) -> dict:
    lower = out.lower()
    has_chacha = "chacha20-poly1305" in lower
    has_etm = "-etm" in lower
    return {"has_chacha": has_chacha, "has_etm": has_etm, "raw": out}

def get_ssh_banner(host: str, port:int=22, timeout:int=SSH_TIMEOUT) -> str:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(1.5)
        banner = s.recv(256).decode('utf-8', errors='ignore').strip()
        s.close()
        return banner
    except Exception:
        return ""

def pretty_print(line: str):
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
    elif tag.startswith("SSH"):
        
        if tag == "SSH_OPEN_VULN":
            print(Fore.RED + line + Style.RESET_ALL)
        elif tag == "SSH_OPEN_NOTVULN":
            print(Fore.GREEN + line + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + line + Style.RESET_ALL)
    else:
        print(line)

def check_host(host: str, terrapin_exe: str|None) -> None:
    host = host.strip()
    if not host:
        return
    
    http_result = check_http(host)
    if http_result:
        pretty_print(http_result)
  
    is_open = tcp_connect(host, 22)
    if not is_open:
        pretty_print(f"SSH_CLOSED\t{host}\t22")
        return
    
    pretty_print(f"SSH_OPEN\t{host}\t22")
   
    if terrapin_exe:
        res = run_terrapin_scan(terrapin_exe, host)
        if "error" in res:
            pretty_print(f"SSH_SCAN_ERROR\t{host}\tterrapin:{res['error']}")
           
        else:
           
            verdict = res.get("result") or res.get("verdict") or res.get("vulnerable") or res.get("status")
            if isinstance(verdict, str) and verdict:
                pretty_print(f"SSH_OPEN_VULN\t{host}\t{verdict}\t{json.dumps(res)}")
                return
            else:
                
                if res.get("vulnerable") is True or res.get("is_vulnerable") is True:
                    pretty_print(f"SSH_OPEN_VULN\t{host}\tterrapin-json\t{json.dumps(res)}")
                    return
                
                pretty_print(f"SSH_OPEN_UNKNOWN\t{host}\tterrapin-raw\t{json.dumps(res)}")
                return

    nmap_out = run_nmap_ssh_algos(host)
    if nmap_out:
        parsed = parse_nmap_algos_output(nmap_out)
        if parsed["has_chacha"] and parsed["has_etm"]:
            pretty_print(f"SSH_OPEN_VULN\t{host}\tnmap-sig:chacha+etm")
        elif parsed["has_chacha"] or parsed["has_etm"]:
            pretty_print(f"SSH_OPEN_MAYBE\t{host}\tnmap-partial-sig:{'chacha' if parsed['has_chacha'] else ''}{'+' if parsed['has_chacha'] and parsed['has_etm'] else ''}{'etm' if parsed['has_etm'] else ''}")
        else:
            pretty_print(f"SSH_OPEN_NOTVULN\t{host}\tnmap-no-sig")
        return

    banner = get_ssh_banner(host, 22)
    if banner:
        pretty_print(f"SSH_OPEN_UNKNOWN\t{host}\tbanner:{banner}")
    else:
        pretty_print(f"SSH_OPEN_UNKNOWN\t{host}\tno-banner")

def main():
    infile = "req.txt"
    try:
        with open(infile, "r", encoding="utf-8") as f:
            hosts = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    except FileNotFoundError:
        print(f"Файл {infile} не найден. Помести хосты/субдомены в {infile} (по одному на строке).")
        sys.exit(1)


    terrapin_exe = find_terrapin_exe()
    if terrapin_exe:
        print(f"[+] Found terrapin scanner: {terrapin_exe}")
    else:
        print("[!] Terrapin scanner not found in cwd or PATH. Will try nmap fallback if available.")

    workers = min(30, max(4, len(hosts)//5 + 1))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(check_host, h, terrapin_exe): h for h in hosts}
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception as e:
                print(Fore.MAGENTA + f"ERROR in worker for {futures[fut]}: {e}" + Style.RESET_ALL)

if __name__ == "__main__":
    main()
