import asyncio
import base64
import ssl
import time
import socket
import ipaddress
import random
import string
from pathlib import Path
from urllib.parse import parse_qs, unquote
import yaml
import aiohttp

# --- Загрузка конфигурации ---
CFG = yaml.safe_load(Path("config.yaml").read_text(encoding="utf-8"))
OUT = Path(CFG["output_dir"])
OUT.mkdir(exist_ok=True)

# ============================================================
# ИСТОЧНИКИ ДЛЯ СБОРА VLESS-КОНФИГОВ
# ============================================================
SOURCES = [
    # --- Специализированные на обходе белых списков ---
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/githubmirror/clean/vless.txt",
    "https://raw.githubusercontent.com/VOID-Anonymity/V.O.I.D-VPN_Bypass/main/url_work.txt",
    # --- Общие сборники (добавлены по вашему запросу) ---
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix_sub.txt",
]

# Слова для генерации случайных имён серверов
NODE_PREFIXES = ["node", "srv", "proxy", "edge", "cdn", "fast", "cloud", "relay"]
NODE_SUFFIXES = ["net", "com", "org", "io", "xyz", "site", "online", "tech"]


def random_node_name():
    """Генерирует случайное имя, похожее на домен."""
    letters = ''.join(random.choices(string.ascii_lowercase, k=6))
    digits = ''.join(random.choices(string.digits, k=2))
    return f"{random.choice(NODE_PREFIXES)}-{letters}{digits}.{random.choice(NODE_SUFFIXES)}"


async def gather_servers(session):
    """Скачивает VLESS-ссылки из указанных источников."""
    all_links = set()
    for url in SOURCES:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as r:
                r.raise_for_status()
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


def parse_vless(link):
    """Парсит VLESS-ссылку в словарь."""
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
            "uuid": uuid,
            "host": host,
            "port": port,
            "params": {k: v[0] for k, v in params.items()},
            "name": name,
            "raw": link + (("#" + name) if name else ""),
        }
    except Exception:
        return None


async def tcp_ok(host, port, timeout):
    """Проверяет TCP-подключение."""
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
    """Проверяет TLS-рукопожатие с указанным SNI."""
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
    """Основная проверка одного сервера."""
    host, port = cfg["host"], cfg["port"]
    timeout = CFG["check"]["timeout"]
    sni = cfg["params"].get("sni", "") or cfg["params"].get("host", "") or ""

    # --- ФИЛЬТР SNI (обход белых списков) ---
    if not sni:
        return False, 0, False
    sni_lower = sni.lower()
    allowed_sni_keywords = [
        "yandex", "ya.ru", "mail.ru", "vk.com", "ok.ru",
        "sber", "gosuslugi", "wildberries", "ozon",
        "avito", "kinopoisk", "rutube", "dzen", "ria.ru",
        "rt.com", "lenta.ru", "kp.ru", "rambler", "1c.ru",
        "cdnvideo", "beeline", "mts.ru", "megafon",
    ]
    if not any(kw in sni_lower for kw in allowed_sni_keywords):
        return False, 0, False

    # --- TCP Проверка ---
    t0 = time.perf_counter()
    if not await tcp_ok(host, port, timeout):
        return False, 0, False
    ping = int((time.perf_counter() - t0) * 1000)

    # --- TLS/Reality Проверка ---
    security = cfg["params"].get("security", "")
    if security in ("tls", "reality") or CFG["check"]["require_tls"]:
        if not await tls_ok(host, port, timeout, sni):
            return False, 0, False
        return True, ping, True
    return True, ping, False


async def geo_lookup(session, host):
    """Определяет страну по IP-адресу."""
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


async def main():
    async with aiohttp.ClientSession() as session:
        print("[+] Скачиваю конфиги из источников...")
        fresh = await gather_servers(session)
        print(f"[+] Из источников: {len(fresh)} ссылок")

        # Добавляем локальные сервера
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
        print(f"[+] Валидных VLESS-конфигов: {len(configs)}")

        # --- Предварительный фильтр по SNI ---
        before = len(configs)
        configs = [
            c for c in configs
            if any(
                kw in (c["params"].get("sni", "") or c["params"].get("host", "")).lower()
                for kw in [
                    "yandex", "ya.ru", "mail.ru", "vk.com", "ok.ru",
                    "sber", "gosuslugi", "wildberries", "ozon",
                    "avito", "kinopoisk", "rutube", "dzen", "ria.ru",
                    "rt.com", "lenta.ru", "kp.ru", "rambler", "1c.ru",
                    "cdnvideo", "beeline", "mts.ru", "megafon",
                ]
            )
        ]
        print(f"[+] После фильтра SNI: {len(configs)} из {before}")

        if not configs:
            print("[!] Нет серверов с российским SNI. Проверьте источники.")
            (OUT / "sub_base64.txt").write_text("", encoding="utf-8")
            (OUT / "sub_plain.txt").write_text("", encoding="utf-8")
            (OUT / "report.txt").write_text(
                f"Всего: {before} | Живых: 0\nНет серверов с российским SNI.\n",
                encoding="utf-8",
            )
            return

        # Дедупликация по host:port
        seen = set()
        unique = []
        for c in configs:
            key = f"{c['host']}:{c['port']}"
            if key not in seen:
                seen.add(key)
                unique.append(c)
        print(f"[+] Уникальных серверов: {len(unique)}")

        # Параметры проверки
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

    # --- Ограничение до 200 лучших серверов ---
    MAX_SERVERS = 200
    if len(good) > MAX_SERVERS:
        print(f"[!] Найдено {len(good)} серверов, оставляю {MAX_SERVERS} лучших по пингу.")
        good = good[:MAX_SERVERS]

    print(f"\n[✓] Готово за {elapsed:.1f}с")
    print(f"[✓] Живых после фильтра: {len(good)} из {len(unique)}")

    brand = CFG["brand"]["name"]
    final_links = []
    for r in good:
        cfg = r["cfg"]
        flag = {"DE": "🇩🇪", "NL": "🇳🇱", "FI": "🇫🇮", "SE": "🇸🇪", "FR": "🇫🇷",
                "GB": "🇬🇧", "PL": "🇵🇱", "CZ": "🇨🇿", "AT": "🇦🇹", "CH": "🇨🇭",
                "RO": "🇷🇴", "LT": "🇱🇹", "LV": "🇱🇻", "EE": "🇪🇪", "IT": "🇮🇹",
                "ES": "🇪🇸", "PT": "🇵🇹", "BE": "🇧🇪", "DK": "🇩🇰", "NO": "🇳🇴",
                "IE": "🇮🇪"}.get(r["country"] or "", "")

        # --- РАНДОМИЗАЦИЯ ИМЕНИ ---
        random_name = random_node_name()
        new_name = f"{flag} {random_name}"

        params = "&".join(f"{k}={v}" for k, v in cfg["params"].items())
        new_link = f"vless://{cfg['uuid']}@{cfg['host']}:{cfg['port']}?{params}#{new_name}"
        final_links.append(new_link)

    plain = "\n".join(final_links)
    b64 = base64.b64encode(plain.encode()).decode()
    (OUT / "sub_base64.txt").write_text(b64, encoding="utf-8")
    (OUT / "sub_plain.txt").write_text(plain, encoding="utf-8")

    # Отчёт
    lines = [
        f"Всего проверено: {len(unique)} | Живых: {len(good)} | Время: {elapsed:.1f}с",
        "",
        f"{'СЕРВЕР':<35} {'ГЕО':<5} {'ПИНГ':<6} {'RATIO':<6} {'SNI'}",
        "-" * 80,
    ]
    for r in good:
        cfg = r["cfg"]
        sni = cfg["params"].get("sni", "") or cfg["params"].get("host", "")
        lines.append(
            f"{cfg['host']+':'+str(cfg['port']):<35} "
            f"{r['country'] or '??':<5} {r['ping']:<6} {r['alive_ratio']:.2f}   {sni}"
        )
    (OUT / "report.txt").write_text("\n".join(lines), encoding="utf-8")

    print(f"[✓] sub_base64.txt, sub_plain.txt, report.txt")


if __name__ == "__main__":
    asyncio.run(main())
