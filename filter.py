import asyncio
import base64
import ssl
import time
import socket
import ipaddress
from pathlib import Path
from urllib.parse import parse_qs, unquote
import yaml
import aiohttp

CFG = yaml.safe_load(Path("config.yaml").read_text(encoding="utf-8"))
OUT = Path(CFG["output_dir"])
OUT.mkdir(exist_ok=True)

# ============================================================
# ИСТОЧНИКИ — публичные репозитории, обновляются автоматически
# ============================================================
SOURCES = [
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/githubmirror/clean/vless.txt",
    "https://raw.githubusercontent.com/srgvsky/goida/main/sub/vless.txt",
    "https://raw.githubusercontent.com/mohammadaz2/v2rayConfigsForYou/main/sub/vless.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/vless.txt",
    "https://raw.githubusercontent.com/histeenn/VLESS-PO-GRIBI/main/deploy/subscriptions/1.txt",
    "https://raw.githubusercontent.com/histeenn/VLESS-PO-GRIBI/main/deploy/subscriptions/2.txt",
    "https://raw.githubusercontent.com/histeenn/VLESS-PO-GRIBI/main/deploy/subscriptions/3.txt",
]

FLAGS = {
    "DE":"🇩🇪","NL":"🇳🇱","FI":"🇫🇮","SE":"🇸🇪","FR":"🇫🇷","GB":"🇬🇧",
    "PL":"🇵🇱","CZ":"🇨🇿","AT":"🇦🇹","CH":"🇨🇭","RO":"🇷🇴","LT":"🇱🇹",
    "LV":"🇱🇻","EE":"🇪🇪","IT":"🇮🇹","ES":"🇪🇸","PT":"🇵🇹","BE":"🇧🇪",
    "DK":"🇩🇰","NO":"🇳🇴","IE":"🇮🇪",
}


# ---------- Скачивание из источников ----------
async def gather_servers(session):
    all_links = set()
    for url in SOURCES:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
                text = await r.text()
                count = 0
                for line in text.splitlines():
                    line = line.strip()
                    if line.startswith("vless://"):
                        all_links.add(line)
                        count += 1
                print(f"[+] {url.split('/')[4]}: +{count}")
        except Exception as e:
            print(f"[!] Не удалось скачать {url}: {e}")
    return list(all_links)


# ---------- Парсинг VLESS ----------
def parse_vless(link):
    try:
        link = link.strip()
        if not link.startswith("vless://"):
            return None
        name = ""
        if "#" in link:
            link, name = link.rsplit("#", 1)
            name = unquote(name)
        body = link.replace("vless://", "")
        uuid, rest = body.split("@", 1)
        hostport, query = rest.split("?", 1) if "?" in rest else (rest, "")
        if hostport.startswith("["):
            host, port = hostport.rsplit("]:", 1)
            host = host.lstrip("[")
        else:
            host, port = hostport.rsplit(":", 1)
        port = int(port)
        params = parse_qs(query)
        return {
            "uuid": uuid, "host": host, "port": port,
            "params": {k: v[0] for k, v in params.items()},
            "name": name,
            "raw": link + (("#" + name) if name else ""),
        }
    except Exception:
        return None


# ---------- Проверки ----------
async def tcp_ok(host, port, timeout):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def tls_ok(host, port, timeout, sni=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni or host),
            timeout,
        )
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def probe(cfg):
    host, port = cfg["host"], cfg["port"]
    timeout = CFG["check"]["timeout"]
    t0 = time.perf_counter()
    if not await tcp_ok(host, port, timeout):
        return False, 0, False
    ping = int((time.perf_counter() - t0) * 1000)
    security = cfg["params"].get("security", "")
    if security in ("tls", "reality") or CFG["check"]["require_tls"]:
        sni = cfg["params"].get("sni") or cfg["params"].get("host") or host
        if not await tls_ok(host, port, timeout, sni):
            return False, 0, False
        return True, ping, True
    return True, ping, False


async def geo_lookup(session, host):
    if not hasattr(geo_lookup, "_cache"):
        geo_lookup._cache = {}
    if host in geo_lookup._cache:
        return geo_lookup._cache[host]
    try:
        ip = host
        try:
            ipaddress.ip_address(host)
        except ValueError:
            ip = socket.gethostbyname(host)
        async with session.get(
            f"http://ip-api.com/json/{ip}?fields=status,countryCode",
            timeout=aiohttp.ClientTimeout(total=3),
        ) as r:
            data = await r.json()
            if data.get("status") == "success":
                geo_lookup._cache[host] = data["countryCode"]
                return data["countryCode"]
    except Exception:
        pass
    geo_lookup._cache[host] = None
    return None


# ---------- Основной проход ----------
async def main():
    async with aiohttp.ClientSession() as session:
        print("[+] Скачиваю конфиги из источников...")
        fresh = await gather_servers(session)
        print(f"[+] Из источников: {len(fresh)} ссылок")

        # Плюс локальный servers.txt (если есть)
        local = []
        if Path(CFG["input"]).exists():
            local = [
                l.strip() for l in Path(CFG["input"]).read_text(encoding="utf-8").splitlines()
                if l.strip().startswith("vless://")
            ]
            print(f"[+] Из servers.txt: {len(local)} ссылок")

        all_links = list(set(fresh + local))
        print(f"[+] Всего уникальных ссылок: {len(all_links)}")

        # Парсинг
        configs = [parse_vless(l) for l in all_links]
        configs = [c for c in configs if c]

        # Дедупликация по host:port
        seen = set()
        unique = []
        for c in configs:
            key = f"{c['host']}:{c['port']}"
            if key not in seen:
                seen.add(key)
                unique.append(c)
        print(f"[+] Уникальных серверов: {len(unique)}")

        sem = asyncio.Semaphore(CFG["check"]["concurrency"])
        attempts = CFG["check"]["attempts"]
        min_ratio = CFG["check"]["min_alive_ratio"]
        max_ping = CFG["check"]["max_ping"]

        async def worker(cfg):
            async with sem:
                results = []
                pings = []
                tls_flags = []
                for _ in range(attempts):
                    alive, ping, tls = await probe(cfg)
                    results.append(alive)
                    if alive:
                        pings.append(ping)
                        tls_flags.append(tls)
                ratio = sum(results) / attempts
                if ratio < min_ratio or not pings:
                    return None
                avg_ping = int(sum(pings) / len(pings))
                if max_ping and avg_ping > max_ping:
                    return None
                if CFG["check"]["require_tls"] and not all(tls_flags):
                    return None
                country = None
                if CFG["geo"]["enabled"]:
                    country = await geo_lookup(session, cfg["host"])
                    if not country:
                        return None
                    in_list = country in CFG["geo"]["countries"]
                    if CFG["geo"]["mode"] == "whitelist" and not in_list:
                        return None
                    if CFG["geo"]["mode"] == "blacklist" and in_list:
                        return None
                return {"cfg": cfg, "ping": avg_ping, "country": country, "alive_ratio": ratio}

        print(f"[+] Проверяю {len(unique)} серверов (x{attempts} попыток)...")
        t0 = time.time()
        raw = await asyncio.gather(*(worker(c) for c in unique))
        elapsed = time.time() - t0

    good = [r for r in raw if r]
    good.sort(key=lambda r: r["ping"])

    print(f"\n[✓] Готово за {elapsed:.1f}с")
    print(f"[✓] Живых после фильтра: {len(good)} из {len(unique)}")

    brand = CFG["brand"]["name"]
    final_links = []
    for r in good:
        cfg = r["cfg"]
        flag = FLAGS.get(r["country"] or "", "")
        new_name = f"{flag} {r['country'] or '??'} | {r['ping']}ms | @{brand}"
        params = "&".join(f"{k}={v}" for k, v in cfg["params"].items())
        new_link = f"vless://{cfg['uuid']}@{cfg['host']}:{cfg['port']}?{params}#{new_name}"
        final_links.append(new_link)

    plain = "\n".join(final_links)
    b64 = base64.b64encode(plain.encode()).decode()
    (OUT / "sub_base64.txt").write_text(b64, encoding="utf-8")
    (OUT / "sub_plain.txt").write_text(plain, encoding="utf-8")

    lines = [
        f"Всего: {len(unique)} | Живых: {len(good)} | Время: {elapsed:.1f}с",
        "",
        f"{'СЕРВЕР':<35} {'ГЕО':<5} {'ПИНГ':<6} {'RATIO'}",
        "-" * 60,
    ]
    for r in good:
        cfg = r["cfg"]
        lines.append(
            f"{cfg['host']+':'+str(cfg['port']):<35} "
            f"{r['country'] or '??':<5} {r['ping']:<6} {r['alive_ratio']:.2f}"
        )
    (OUT / "report.txt").write_text("\n".join(lines), encoding="utf-8")

    print(f"[✓] sub_base64.txt, sub_plain.txt, report.txt")


if __name__ == "__main__":
    asyncio.run(main())
