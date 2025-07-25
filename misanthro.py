import argparse
import httpx
from bs4 import BeautifulSoup
import yaml
import time
import random
from pathlib import Path
import datetime
import os
import concurrent.futures
import sys
from urllib.parse import urljoin

BLACKLIST_HEADERS = {
    "transfer-encoding",
    "content-length",
    "trailer"
}

ASCII_ART = r"""
                       .       .x+=:.                                  s                                                                           
                      @88>    z`    ^%                                :8      .uef^"                                                    ..         
   ..    .     :      %8P        .   <k                u.    u.      .88    :d88E          .u    .          u.           .d``          @L          
 .888: x888  x888.     .       .@8Ned8"       u      x@88k u@88c.   :888ooo `888E        .d88B :@8c   ...ue888b          @8Ne.   .u   9888i   .dL  
~`8888~'888X`?888f`  .@88u   .@^%8888"     us888u.  ^"8888""8888" -*8888888  888E .z8k  ="8888f8888r  888R Y888r         %8888:u@88N  `Y888k:*888. 
  X888  888X '888>  ''888E` x88:  `)8b. .@88 "8888"   8888  888R    8888     888E~?888L   4888>'88"   888R I888>          `888I  888.   888E  888I 
  X888  888X '888>    888E  8888N=*8888 9888  9888    8888  888R    8888     888E  888E   4888> '     888R I888>           888I  888I   888E  888I 
  X888  888X '888>    888E   %8"    R88 9888  9888    8888  888R    8888     888E  888E   4888>       888R I888>           888I  888I   888E  888I 
  X888  888X '888>    888E    @8Wou 9%  9888  9888    8888  888R   .8888Lu=  888E  888E  .d888L .+   u8888cJ888     .    uW888L  888'   888E  888I 
 "*88%""*88" '888!`   888&  .888888P`   9888  9888   "*88*" 8888"  ^%888*    888E  888E  ^"8888*"     "*888*P"    .@8c  '*88888Nu88P   x888N><888' 
   `~    "    `"`     R888" `   ^"F     "888*""888"    ""   'Y"      'Y"    m888N= 888>     "Y"         'Y"      '%888" ~ '88888F`      "88"  888  
                       ""                ^Y"   ^Y'                           `Y"   888                             ^*      888 ^              88F  
                                                                                  J88"                                     *8E               98"   
                                                                                  @%                                       '8>             ./"     
                                                                                :"                                          "             ~`       
"""

def get_random_ascii_art():
    assets_dir = os.path.join(os.path.dirname(__file__), "assets")
    if not os.path.isdir(assets_dir):
        return ""
    art_files = [f for f in os.listdir(assets_dir) if os.path.isfile(os.path.join(assets_dir, f))]
    if not art_files:
        return ""
    with open(os.path.join(assets_dir, random.choice(art_files)), "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def print_banner():
    print(f"\033[91m{ASCII_ART}\033[0m")
    ascii_art = get_random_ascii_art()
    if ascii_art:
        print(f"\033[91m{ascii_art}\033[0m")
    print()
    print("Attacking indiscriminately every \033[91mheader\033[0m, \033[91mcookie\033[0m, \033[91mGET\033[0m and \033[91mPOST parameter\033[0m with \033[91mblind fury\033[0m.")
    print("Made with \033[91mHATE\033[0m by \033[91mindevi0us\033[0m.\n")

def format_time():
    now = datetime.datetime.now()
    return f"\033[91m[\033[0m{now:%H\033[91m:\033[0m%M\033[91m:\033[0m%S}\033[91m]\033[0m"

def info(msg):
    print(f"\033[91m[\033[0mi\033[91m]\033[0m{format_time()} {msg}")

def vuln(msg):
    print(f"\033[91m[\033[0;1m!\033[91m]\033[0m{format_time()} \033[91m\033[1m{msg}\033[0m")

def load_payloads(path):
    path = Path(path)
    if not path.exists():
        info(f"Payload file not found: {path}")
        sys.exit(2)
    if path.suffix.lower() in {".yaml", ".yml"}:
        p = yaml.safe_load(path.read_text(encoding="utf-8"))
        return p if isinstance(p, list) else [p] if isinstance(p, str) else []
    if path.suffix.lower() == ".json":
        import json
        p = json.loads(path.read_text(encoding="utf-8"))
        return p if isinstance(p, list) else [p] if isinstance(p, str) else []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

def discover_targets(url, client):
    try:
        r = client.get(url, follow_redirects=True, timeout=10)
        base_url = str(r.url)
        soup = BeautifulSoup(r.text, "lxml")
        gets, posts = set(), set()
        hdrs = set(r.headers.keys())
        coks = set(r.cookies.keys())

        for a in soup.find_all("a", href=True):
            full_url = urljoin(base_url, a["href"])
            if "?" in full_url:
                params = full_url.split("?", 1)[1].split("&")
                gets.update(p.split("=")[0] for p in params if "=" in p)

        for form in soup.find_all("form"):
            m = (form.get("method") or "get").lower()
            names = [i.get("name") for i in form.find_all(["input", "textarea", "select"]) if i.get("name")]
            if m == "post":
                posts.update(names)
            else:
                gets.update(names)

        return {"headers": list(hdrs), "cookies": list(coks), "get": list(gets), "post": list(posts)}
    except Exception as e:
        info(f"Discovery error: {e}")
        return {"headers": [], "cookies": [], "get": [], "post": []}

class InjectorBase:
    def __init__(self, url, payloads, targets, threads, rate_limit, client):
        self.url = url
        self.payloads = payloads
        self.targets = targets
        self.threads = threads
        self.rate_limit = rate_limit
        self.client = client

    def inject(self, name, payload):
        raise NotImplementedError

    def run(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.inject, t, f"{p}__INJECT__MARK__") for t in self.targets for p in self.payloads]
            concurrent.futures.wait(futures)

class HeaderInjector(InjectorBase):
    def inject(self, header, payload):
        try:
            r = self.client.get(self.url, headers={header: payload}, timeout=10)
            if "__INJECT__MARK__" in r.text:
                vuln(f'Payload "{payload}" injected in header "{header}"')
            elif payload in r.text:
                info(f"Payload reflected (marker missing) in header '{header}': {payload}")
            if self.rate_limit:
                time.sleep(self.rate_limit)
        except Exception as e:
            info(f"Header[{header}] error: {e}")

class CookieInjector(InjectorBase):
    def inject(self, cookie, payload):
        try:
            r = self.client.get(self.url, cookies={cookie: payload}, timeout=10)
            if "__INJECT__MARK__" in r.text:
                vuln(f'Payload "{payload}" injected in cookie "{cookie}"')
            elif payload in r.text:
                info(f"Payload reflected (marker missing) in cookie '{cookie}': {payload}")
            if self.rate_limit:
                time.sleep(self.rate_limit)
        except Exception as e:
            info(f"Cookie[{cookie}] error: {e}")

class GetInjector(InjectorBase):
    def inject(self, param, payload):
        try:
            r = self.client.get(self.url, params={param: payload}, timeout=10)
            if "__INJECT__MARK__" in r.text:
                vuln(f'Payload "{payload}" injected in GET param "{param}"')
            elif payload in r.text:
                info(f"Payload reflected (marker missing) in GET param '{param}': {payload}")
            if self.rate_limit:
                time.sleep(self.rate_limit)
        except Exception as e:
            info(f"GET[{param}] error: {e}")

class PostInjector(InjectorBase):
    def inject(self, param, payload):
        try:
            r = self.client.post(self.url, data={param: payload}, timeout=10)
            if "__INJECT__MARK__" in r.text:
                vuln(f'Payload "{payload}" injected in POST param "{param}"')
            elif payload in r.text:
                info(f"Payload reflected (marker missing) in POST param '{param}': {payload}")
            if self.rate_limit:
                time.sleep(self.rate_limit)
        except Exception as e:
            info(f"POST[{param}] error: {e}")

class InjectionManager:
    def __init__(self, url, attack_all, vectors, payloads, threads, rate_limit, client):
        self.url = url
        self.attack_all = attack_all
        self.vectors = vectors
        self.payloads = payloads
        self.threads = threads
        self.rate_limit = rate_limit
        self.client = client

    def step(self, msg):
        print(f"\033[91m[\033[0m*\033[91m]\033[0m{format_time()} {msg}")

    def run(self):
        info(f"\033[91mPayloads loaded\033[0m: {len(self.payloads)}.")
        info(f"\033[91mHeaders to attack\033[0m: {self.vectors.get('headers',[])}.")
        info(f"\033[91mCookies to attack\033[0m: {self.vectors.get('cookies',[])}.")
        info(f"\033[91mGET parameters to attack\033[0m: {self.vectors.get('get',[])}.")
        info(f"\033[91mPOST parameters to attack\033[0m: {self.vectors.get('post',[])}.")
        self.step(f"\033[91mAttacking target\033[0m: {self.url}.")

        if self.vectors.get("headers"):
            self.step("\033[91mInjecting into headers\033[0m.")
            HeaderInjector(self.url, self.payloads, self.vectors["headers"], self.threads, self.rate_limit, self.client).run()

        if self.vectors.get("cookies"):
            self.step("\033[91mInjecting into cookies\033[0m.")
            CookieInjector(self.url, self.payloads, self.vectors["cookies"], self.threads, self.rate_limit, self.client).run()

        if self.vectors.get("get"):
            self.step("\033[91mInjecting into GET parameters\033[0m.")
            GetInjector(self.url, self.payloads, self.vectors["get"], self.threads, self.rate_limit, self.client).run()

        if self.vectors.get("post"):
            self.step("\033[91mInjecting into POST parameters\033[0m.")
            PostInjector(self.url, self.payloads, self.vectors["post"], self.threads, self.rate_limit, self.client).run()

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--url', type=str, required=False)
    parser.add_argument('--all', action='store_true')
    parser.add_argument('--headers', type=str, default="")
    parser.add_argument('--cookies', type=str, default="")
    parser.add_argument('--get', type=str, default="")
    parser.add_argument('--post', type=str, default="")
    parser.add_argument('--payloads', type=str, default="payloads.yaml")
    parser.add_argument('--threads', type=int, default=10)
    parser.add_argument('--rate-limit', type=float, default=0.0)
    parser.add_argument('--discovery', action='store_true')
    parser.add_argument('--auth-cookies', type=str, default="")
    parser.add_argument('--help', action='store_true')

    args, unknown = parser.parse_known_args()
    print_banner()

    if args.help or not args.url:
        print(parser.format_usage())
        sys.exit(0)

    auth_cookies = {}
    if args.auth_cookies:
        try:
            auth_cookies = {k.strip(): v for k, v in (pair.split("=", 1) for pair in args.auth_cookies.split(";"))}
        except Exception:
            info("Invalid auth cookie format. Expected: 'name=value; name2=value2'")
            sys.exit(1)

    client = httpx.Client(cookies=auth_cookies, follow_redirects=True)

    vectors = {"headers": [], "cookies": [], "get": [], "post": []}
    discovered = {}

    if args.all or args.discovery:
        discovered = discover_targets(args.url, client)
        info(f"\033[91mDiscovered vectors\033[0m: {discovered}")

    if args.discovery and not args.all and not any([args.headers, args.cookies, args.get, args.post]):
        sys.exit(0)

    vectors = {
        "headers": args.headers.split(",") if args.headers else discovered.get("headers", []),
        "cookies": args.cookies.split(",") if args.cookies else discovered.get("cookies", []),
        "get": args.get.split(",") if args.get else discovered.get("get", []),
        "post": args.post.split(",") if args.post else discovered.get("post", [])
    } if not args.all else discovered

    vectors["headers"] = [h for h in vectors["headers"] if h.lower() not in BLACKLIST_HEADERS]

    payload_list = []
    if args.all or any([args.headers, args.cookies, args.get, args.post]):
        payload_list = load_payloads(args.payloads)
        if not payload_list:
            info("No payloads loaded, aborting.")
            sys.exit(3)

    manager = InjectionManager(args.url, args.all, vectors, payload_list, args.threads, args.rate_limit, client)
    manager.run()
    print(f"\n\033[91mDone\033[0m. Now go unleash your \033[91mhatred\033[0m somewhere else.\n")

if __name__ == "__main__":
    main()

