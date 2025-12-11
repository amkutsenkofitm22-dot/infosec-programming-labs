import argparse, json, os, threading, time, socket, selectors, ipaddress
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import List, Optional

LOG_PATH = 'logs/events.jsonl'

def jlog(obj):
    """Журналювання подій у JSONL формат"""
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, 'a', encoding='utf-8') as f:
        f.write(json.dumps(obj, ensure_ascii=False) + '\n')

@dataclass(order=True)
class Rule:
    """Правило фільтрації пакетів"""
    priority: int
    id: int = field(compare=False, default=0)
    action: str = field(compare=False, default='deny')  # 'allow' | 'deny'
    src_ip_cidr: str = field(compare=False, default='0.0.0.0/0')
    dst_ip_cidr: str = field(compare=False, default='0.0.0.0/0')
    src_port: int = field(compare=False, default=0)     # 0 = any
    dst_port: int = field(compare=False, default=0)
    proto: str = field(compare=False, default='TCP')    # 'TCP' | 'UDP'
    enabled: bool = field(compare=False, default=True)

    def matches(self, src_ip, dst_ip, src_port, dst_port, proto):
        """Перевірка чи відповідає пакет правилу"""
        if not self.enabled: return False
        if self.proto.upper() != proto.upper(): return False
        try:
            if ipaddress.ip_address(src_ip) not in ipaddress.ip_network(self.src_ip_cidr, strict=False):
                return False
            if ipaddress.ip_address(dst_ip) not in ipaddress.ip_network(self.dst_ip_cidr, strict=False):
                return False
        except Exception:
            return False
        if self.src_port and self.src_port != src_port: return False
        if self.dst_port and self.dst_port != dst_port: return False
        return True

class RuleSet:
    """Набір правил з можливістю керування"""
    def __init__(self, rules=None):
        self.rules: List[Rule] = sorted(rules or [])
        self.next_id = (max((r.id for r in self.rules), default=0) + 1)

    def to_dict(self):
        """Конвертація у словник для JSON"""
        return [r.__dict__ for r in self.rules]

    def add(self, r: Rule):
        """Додавання правила з перевіркою на конфлікти"""
        # Виявлення конфліктів: точний дублікат
        for x in self.rules:
            if (x.src_ip_cidr,x.dst_ip_cidr,x.src_port,x.dst_port,x.proto.lower(),x.priority) == \
               (r.src_ip_cidr,r.dst_ip_cidr,r.src_port,r.dst_port,r.proto.lower(),r.priority):
                if x.action == r.action:
                    return {'warning':'duplicate_rule','existing_id':x.id}
                else:
                    return {'warning':'conflict_same_specificity','existing_id':x.id}
        r.id = self.next_id; self.next_id += 1
        self.rules.append(r); self.rules.sort()
        return {'id': r.id}

    def remove(self, rid:int):
        """Видалення правила за ID"""
        self.rules = [r for r in self.rules if r.id != rid]

    def update(self, rid:int, **kw):
        """Оновлення правила"""
        for r in self.rules:
            if r.id == rid:
                for k,v in kw.items():
                    if hasattr(r,k): setattr(r,k,v)
                self.rules.sort()
                return True
        return False

    def decide(self, src_ip, dst_ip, src_port, dst_port, proto):
        """Прийняття рішення за пакетом"""
        for r in self.rules:
            if r.matches(src_ip, dst_ip, src_port, dst_port, proto):
                return r.action, r.id
        return 'allow', 0  # неявний дозвіл якщо жодне правило не спрацювало

# TCP проксі сервер
def tcp_proxy(listen_host, listen_port, target_host, target_port, ruleset: RuleSet):
    """TCP проксі з фільтрацією пакетів"""
    sel = selectors.DefaultSelector()
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((listen_host, listen_port)); ls.listen(128); ls.setblocking(False)
    sel.register(ls, selectors.EVENT_READ)

    def accept(sock):
        """Прийняття нового з'єднання"""
        conn, addr = sock.accept(); conn.setblocking(False)
        src_ip, src_port = addr[0], addr[1]
        dst_ip = socket.gethostbyname(target_host); dst_port = target_port
        action, rid = ruleset.decide(src_ip, dst_ip, src_port, dst_port, 'TCP')
        jlog({'ts': time.time(), 'event':'tcp.connect', 'src':addr, 'dst': [dst_ip, dst_port], 'action':action, 'rule_id':rid})
        print(f"[TCP] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {action.upper()} (rule {rid})")
        if action != 'allow':
            conn.close(); return
        try:
            upstream = socket.create_connection((target_host, target_port), timeout=5)
            upstream.setblocking(False)
        except Exception as e:
            jlog({'ts': time.time(), 'event':'tcp.error', 'src':addr, 'dst':[target_host,target_port], 'err':str(e)})
            conn.close(); return
        sel.register(conn, selectors.EVENT_READ, data=('c', upstream))
        sel.register(upstream, selectors.EVENT_READ, data=('u', conn))

    def forward(src, dst, tag):
        """Пересилання даних між клієнтом та сервером"""
        try:
            data = src.recv(4096)
            if not data:
                sel.unregister(src); sel.unregister(dst); src.close(); dst.close(); return
            dst.sendall(data)
        except Exception:
            try:
                sel.unregister(src); sel.unregister(dst)
            except Exception: pass
            src.close(); dst.close()

    print(f"[TCP Proxy] Listening on {listen_host}:{listen_port} -> {target_host}:{target_port}")
    while True:
        for key,mask in sel.select(timeout=1):
            if key.fileobj is ls:
                accept(ls)
            else:
                role, peer = key.data
                forward(key.fileobj, peer, role)

# UDP проксі
def udp_proxy(listen_host, listen_port, target_host, target_port, ruleset: RuleSet):
    """UDP проксі з фільтрацією пакетів"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((listen_host, listen_port))
    print(f"[UDP Proxy] Listening on {listen_host}:{listen_port} -> {target_host}:{target_port}")
    while True:
        data, addr = sock.recvfrom(65535)
        src_ip, src_port = addr
        dst_ip = socket.gethostbyname(target_host); dst_port = target_port
        action, rid = ruleset.decide(src_ip, dst_ip, src_port, dst_port, 'UDP')
        jlog({'ts': time.time(), 'event':'udp.packet', 'bytes':len(data), 'src':addr, 'dst':[dst_ip,dst_port], 'action':action, 'rule_id':rid})
        print(f"[UDP] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {action.upper()} (rule {rid})")
        if action != 'allow': continue
        # Відправка до цілі та передача відповіді назад
        try:
            upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            upstream.settimeout(2)
            upstream.sendto(data, (dst_ip, dst_port))
            try:
                resp, _ = upstream.recvfrom(65535)
                sock.sendto(resp, addr)
            except socket.timeout:
                pass
            upstream.close()
        except Exception as e:
            jlog({'ts': time.time(), 'event':'udp.error', 'err':str(e)})

# Admin REST API
class Admin(BaseHTTPRequestHandler):
    """HTTP сервер для керування правилами"""
    def _json(self, code, payload):
        """Відправка JSON відповіді"""
        self.send_response(code); self.send_header('Content-Type','application/json'); self.end_headers()
        self.wfile.write(json.dumps(payload, ensure_ascii=False, indent=2).encode())

    def do_GET(self):
        """GET запити - перегляд правил"""
        if self.path.startswith('/rules'):
            self._json(200, rules.ruleset.to_dict())
        elif self.path == '/stats':
            # Підрахунок статистики з логів
            stats = {'total_events': 0, 'blocked': 0, 'allowed': 0}
            if os.path.exists(LOG_PATH):
                with open(LOG_PATH, 'r') as f:
                    for line in f:
                        try:
                            event = json.loads(line)
                            stats['total_events'] += 1
                            if event.get('action') == 'deny':
                                stats['blocked'] += 1
                            elif event.get('action') == 'allow':
                                stats['allowed'] += 1
                        except: pass
            self._json(200, stats)
        else:
            self._json(404, {'error':'not_found'})

    def do_POST(self):
        """POST запити - додавання правил"""
        if self.path.startswith('/rules'):
            ln = int(self.headers.get('Content-Length','0'))
            body = json.loads(self.rfile.read(ln) or b'{}')
            try:
                r = Rule(priority=int(body.get('priority',100)),
                         action=body.get('action','deny'),
                         src_ip_cidr=body.get('src_ip_cidr','0.0.0.0/0'),
                         dst_ip_cidr=body.get('dst_ip_cidr','0.0.0.0/0'),
                         src_port=int(body.get('src_port',0)),
                         dst_port=int(body.get('dst_port',0)),
                         proto=body.get('proto','TCP'),
                         enabled=bool(body.get('enabled',True)))
            except Exception as e:
                return self._json(400, {'error':'bad_rule','detail':str(e)})
            res = rules.ruleset.add(r)
            self._json(200, res)
        elif self.path.startswith('/reload'):
            rules.load(); self._json(200, {'ok':True})
        else:
            self._json(404, {'error':'not_found'})

    def do_PATCH(self):
        """PATCH запити - оновлення правил"""
        if self.path.startswith('/rules/'):
            rid = int(self.path.split('/')[-1])
            ln = int(self.headers.get('Content-Length','0'))
            body = json.loads(self.rfile.read(ln) or b'{}')
            ok = rules.ruleset.update(rid, **body)
            self._json(200 if ok else 404, {'ok':ok})
        else:
            self._json(404, {'error':'not_found'})

    def do_DELETE(self):
        """DELETE запити - видалення правил"""
        if self.path.startswith('/rules/'):
            rid = int(self.path.split('/')[-1])
            rules.ruleset.remove(rid); self._json(200, {'ok':True})
        else:
            self._json(404, {'error':'not_found'})

    def log_message(self, format, *args):
        """Вимкнення логів HTTP сервера"""
        pass

class RuleManager:
    """Менеджер правил та конфігурації"""
    def __init__(self, path):
        self.path = path
        self.ruleset = RuleSet([])
        self.load()

    def load(self):
        """Завантаження конфігурації з файлу"""
        cfg = json.load(open(self.path,'r',encoding='utf-8'))
        global LOG_PATH
        LOG_PATH = cfg.get('logging',{}).get('path', LOG_PATH)
        base_rules = []
        for r in cfg.get('rules', []):
            base_rules.append(Rule(priority=r.get('priority',100), id=r.get('id',0), action=r.get('action','deny'),
                                   src_ip_cidr=r.get('src_ip_cidr','0.0.0.0/0'), dst_ip_cidr=r.get('dst_ip_cidr','0.0.0.0/0'),
                                   src_port=r.get('src_port',0), dst_port=r.get('dst_port',0), proto=r.get('proto','TCP'),
                                   enabled=r.get('enabled',True)))
        self.ruleset = RuleSet(base_rules)
        self.services = cfg.get('services', [])

def main():
    ap = argparse.ArgumentParser(description='Програмний брандмауер з TCP/UDP проксі')
    ap.add_argument('--config', default='config.json', help='Шлях до конфігураційного файлу')
    args = ap.parse_args()
    global rules
    rules = RuleManager(args.config)

    print("="*60)
    print(" "*15 + "FIREWALL")
    print("="*60)
    print(f"\n[INFO] Завантажено правил: {len(rules.ruleset.rules)}")
    print(f"[INFO] Сервісів: {len(rules.services)}")

    # Запуск Admin API
    admin = HTTPServer(( '127.0.0.1', 8081 ), Admin)
    threading.Thread(target=admin.serve_forever, daemon=True).start()
    print(f"\n[API] Admin API: http://127.0.0.1:8081")
    print(f"[API] GET /rules - перегляд правил")
    print(f"[API] POST /rules - додати правило")
    print(f"[API] PATCH /rules/<id> - оновити правило")
    print(f"[API] DELETE /rules/<id> - видалити правило")
    print(f"[API] GET /stats - статистика\n")

    # Запуск проксі сервісів
    threads = []
    for s in rules.services:
        if s.get('proto') == 'TCP':
            t = threading.Thread(target=tcp_proxy, args=(s['listen_host'], s['listen_port'], s['target_host'], s['target_port'], rules.ruleset), daemon=True)
        else:
            t = threading.Thread(target=udp_proxy, args=(s['listen_host'], s['listen_port'], s['target_host'], s['target_port'], rules.ruleset), daemon=True)
        t.start(); threads.append(t)

    print(f"\n[INFO] Брандмауер запущено. Натисніть Ctrl+C для зупинки.\n")
    try:
        [t.join() for t in threads]
    except KeyboardInterrupt:
        print("\n\n[INFO] Зупинка брандмауера...")

if __name__ == '__main__':
    main()