#!/usr/bin/env python3
import base64, re, json, asyncio, aiohttp
from urllib.parse import parse_qs, unquote
from datetime import datetime

ALLOWED = ["vless", "vmess", "trojan", "hysteria2", "hy2"]
BLOCKED = [".ua", "ukraine", "kyiv", "kiev", "kharkiv", "odesa", "lviv", "dnipro", "donetsk", "zaporizhzhia", "ukr", "укр"]
SOURCES = [
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
]

class Server:
    def __init__(self, url, src):
        self.url = url
        self.src = src
        self.proto = ""
        self.addr = ""
        self.port = 0
        self.sec = "none"
        self.score = 0
        self.alive = False
        self.ping = -1
        self.blocked = False
        self.ok = False

    def parse(self):
        try:
            if self.url.startswith("vless://"):
                self.proto = "vless"
                m = re.match(r'vless://([^@]+)@([^:]+):(\d+)\?([^#]*)#?(.*)', self.url)
                if not m: return
                self.addr = m.group(2).lower()
                self.port = int(m.group(3))
                p = parse_qs(m.group(4))
                self.sec = p.get('security', ['none'])[0].lower()
            elif self.url.startswith("vmess://"):
                self.proto = "vmess"
                j = json.loads(base64.b64decode(self.url.replace("vmess://", "") + '==').decode())
                self.addr = j.get('add', '').lower()
                self.port = int(j.get('port', 0))
                self.sec = j.get('tls', '').lower()
            elif self.url.startswith("trojan://"):
                self.proto = "trojan"
                m = re.match(r'trojan://([^@]+)@([^:]+):(\d+)', self.url)
                if not m: return
                self.addr = m.group(2).lower()
                self.port = int(m.group(3))
                self.sec = "tls"
            elif self.url.startswith("hysteria2://") or self.url.startswith("hy2://"):
                self.proto = "hysteria2"
                u = self.url.replace("hy2://", "hysteria2://")
                m = re.match(r'hysteria2://([^@]+)@([^:]+):(\d+)', u)
                if not m: return
                self.addr = m.group(2).lower()
                self.port = int(m.group(3))
                self.sec = "tls"
            else:
                return

            for k in BLOCKED:
                if k in self.addr:
                    self.blocked = True
                    return
            self.ok = True
        except:
            pass

    def calc_score(self):
        if not self.ok: return 0
        s = 0
        if self.proto in ["vless", "trojan", "hysteria2"]: s += 25
        elif self.proto == "vmess": s += 20
        if self.sec == "reality": s += 35
        elif self.sec in ["tls", "xtls"]: s += 25
        if self.port == 443: s += 10
        self.score = min(s, 100)
        return self.score

async def fetch(session, url):
    try:
        async with session.get(url, timeout=30, ssl=False) as r:
            if r.status != 200: return []
            t = await r.text()
            try:
                d = base64.b64decode(t.strip() + '==').decode()
                lines = d.strip().split('\n')
            except:
                lines = t.strip().split('\n')
            out = []
            for line in lines:
                line = line.strip()
                if any(line.startswith(p + "://") for p in ALLOWED):
                    out.append(line)
            return out
    except:
        return []

async def check(session, srv):
    try:
        st = asyncio.get_event_loop().time()
        _, w = await asyncio.wait_for(asyncio.open_connection(srv.addr, srv.port), timeout=8)
        w.close()
        srv.ping = (asyncio.get_event_loop().time() - st) * 1000
        srv.alive = True
    except:
        srv.alive = False

async def main():
    print(f"[{datetime.now()}] Start...")
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=50, ssl=False)) as session:
        all_urls = []
        for url in SOURCES:
            cfg = await fetch(session, url)
            print(f"  {url}: {len(cfg)}")
            all_urls.extend([(c, "public") for c in cfg])

        servers = []
        seen = set()
        for url, src in all_urls:
            if url in seen: continue
            seen.add(url)
            s = Server(url, src)
            s.parse()
            if s.ok and not s.blocked:
                s.calc_score()
                if s.score >= 60:
                    servers.append(s)

        print(f"Valid secure: {len(servers)}")

        # Check alive
        await asyncio.gather(*[check(session, s) for s in servers])
        alive = [s for s in servers if s.alive]
        print(f"Alive: {len(alive)}")

        alive.sort(key=lambda x: (x.ping if x.ping > 0 else 9999, -x.score))
        final = alive[:50]

        if final:
            txt = '\n'.join([s.url for s in final])
            enc = base64.b64encode(txt.encode()).decode()
            with open('configs.txt', 'w') as f:
                f.write(enc)

            info = {
                "updated_at": datetime.now().isoformat(),
                "total": len(final),
                "protocols": {},
                "avg_ping": round(sum(s.ping for s in final if s.ping > 0) / max(len([s for s in final if s.ping > 0]), 1), 1),
                "avg_score": round(sum(s.score for s in final) / len(final), 1)
            }
            for s in final:
                info["protocols"][s.proto] = info["protocols"].get(s.proto, 0) + 1
            with open('info.json', 'w') as f:
                json.dump(info, f, indent=2)

            print(f"Saved {len(final)} servers")
            for i, s in enumerate(final[:5], 1):
                print(f"  {i}. {s.proto} | {s.addr} | {s.score}/100 | {s.ping:.0f}ms")
        else:
            print("No servers found!")
            with open('configs.txt', 'w') as f: f.write("")
            with open('info.json', 'w') as f: json.dump({"updated_at": datetime.now().isoformat(), "total": 0}, f)

if __name__ == '__main__':
    asyncio.run(main())
