"""Teste do guard de escopo: python3 test_scope.py"""
from agent import check_scope

ok = [
    ("http_request", {"method": "GET", "url": "http://localhost:3000/rest/products/search?q=a"}),
    ("http_request", {"method": "GET", "url": "http://127.0.0.1:3000/"}),
    ("dir_bruteforce", {"base_url": "http://localhost:3000"}),
    ("nmap_scan", {"target_host": "localhost", "ports": "1-10000", "extra_args": "-sV -T4"}),
]
blocked = [
    ("http_request", {"method": "GET", "url": "http://google.com/"}),
    ("http_request", {"method": "GET", "url": "http://localhost:3000@evil.com/"}),
    ("http_request", {"method": "GET", "url": "http://localhost:80/"}),       # WordPress, fora do escopo
    ("http_request", {"method": "GET", "url": "http://localhost:abc/"}),
    ("dir_bruteforce", {"base_url": "http://10.0.80.1:3000"}),
    ("nmap_scan", {"target_host": "192.168.20.0/24"}),
    ("nmap_scan", {"target_host": "localhost", "extra_args": "--script http-enum"}),
    ("nmap_scan", {"target_host": "localhost", "extra_args": "-iL /etc/passwd"}),
    ("nmap_scan", {"target_host": "localhost", "ports": "1-100; rm -rf ~"}),
]
for tool, p in ok:
    assert check_scope(tool, p) is None, (tool, p, check_scope(tool, p))
for tool, p in blocked:
    assert check_scope(tool, p), (tool, p)
print(f"OK: {len(ok)} permitidos, {len(blocked)} bloqueados")
