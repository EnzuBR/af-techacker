"""Testes unitarios do guard de escopo e parser do agente: python3 test_scope.py"""
from agent import check_scope, parse_llm_response

ok = [
    ("http_request", {"method": "GET", "url": "http://localhost:3000/rest/products/search?q=a"}),
    ("http_request", {"method": "POST", "url": "http://127.0.0.1:3000/rest/user/login"}),
    ("dir_bruteforce", {"base_url": "http://localhost:3000"}),
    ("dir_bruteforce", {"base_url": "http://127.0.0.1:3000/", "wordlist": ["metrics", "api/Users"]}),
    ("nmap_scan", {"target_host": "localhost", "ports": "3000", "extra_args": "-sV -T4"}),
    ("nmap_scan", {"target_host": "127.0.0.1", "ports": "3000", "extra_args": ""}),
]

blocked = [
    ("http_request", {"method": "GET", "url": "http://google.com/"}),
    ("http_request", {"method": "GET", "url": "http://localhost:3000@evil.com/"}),
    ("http_request", {"method": "GET", "url": "http://localhost:80/"}),
    ("http_request", {"method": "GET", "url": "https://localhost:3000/"}),
    ("http_request", {"method": "GET", "url": "file:///etc/passwd"}),
    ("http_request", {"method": "GET", "url": "http://localhost:abc/"}),
    ("http_request", {"method": "TRACE", "url": "http://localhost:3000/"}),
    ("dir_bruteforce", {"base_url": "http://10.0.80.1:3000"}),
    ("dir_bruteforce", {"base_url": "http://localhost:3000/?q=1"}),
    ("dir_bruteforce", {"base_url": "http://localhost:3000/#frag"}),
    ("dir_bruteforce", {"base_url": "http://localhost:3000", "wordlist": ["http://evil.com"]}),
    ("dir_bruteforce", {"base_url": "http://localhost:3000", "wordlist": ["../etc/passwd"]}),
    ("dir_bruteforce", {"base_url": "http://localhost:3000", "wordlist": ["@evil.com"]}),
    ("dir_bruteforce", {"base_url": "http://localhost:3000", "wordlist": ["a b"]}),
    ("nmap_scan", {"target_host": "192.168.20.0/24", "ports": "3000"}),
    ("nmap_scan", {"target_host": "localhost", "ports": "1-10000"}),
    ("nmap_scan", {"target_host": "localhost", "ports": "80"}),
    ("nmap_scan", {"target_host": "localhost", "ports": "-"}),
    ("nmap_scan", {"target_host": "localhost", "ports": "22,3000"}),
    ("nmap_scan", {"target_host": "localhost", "ports": "1-100; rm -rf ~"}),
    ("nmap_scan", {"target_host": "localhost", "ports": "3000", "extra_args": "--script http-enum"}),
    ("nmap_scan", {"target_host": "localhost", "ports": "3000", "extra_args": "-iL /etc/passwd"}),
    ("nmap_scan", {"target_host": "localhost", "ports": "3000", "extra_args": "-oN out.txt"}),
    ("shell_exec", {"cmd": "id"}),
]

for tool, p in ok:
    err = check_scope(tool, p)
    assert err is None, f"Esperado permitido: {(tool, p)} -> {err}"

for tool, p in blocked:
    err = check_scope(tool, p)
    assert err is not None, f"Esperado bloqueado: {(tool, p)}"

# Testes do parser de resposta do LLM
p1 = parse_llm_response('{"interpretation":"ok","action":"fetch","tool":"http_request","parameters":{"method":"GET","url":"http://localhost:3000/"}}')
assert p1["tool"] == "http_request"

p2 = parse_llm_response('<think>raciocinio</think>\n{"interpretation":"ok","action":"DONE","conclusion":"fim","findings":[]}')
assert p2["action"] == "DONE"

p3 = parse_llm_response('```json\n{"interpretation":"ok","action":"scan","tool":"nmap_scan","parameters":{"target_host":"localhost","ports":"3000"}}\n```')
assert p3["tool"] == "nmap_scan"

p4 = parse_llm_response('["not", "a", "dict"]')
assert p4["action"] == "DONE"

p5 = parse_llm_response('{"interpretation":"parcial","action":"check","tool":"http_request","parameters":{"method":"GET","url":"http://localhost:3000/metrics')
assert p5["tool"] == "http_request"
assert p5["parameters"]["url"] == "http://localhost:3000/metrics"

p6 = parse_llm_response('{"interpretation":"parcial","action":"check","tool":"http_request","parameters":{"method":"GET","url":"http://localhost:3000/metrics", [trunc')
assert p6["tool"] == "http_request"
assert "interpretation" in p6 and "thinking" not in p6
assert "interpretation" not in p6["parameters"]

print(f"OK: {len(ok)} permitidos, {len(blocked)} bloqueados, 6 casos de parse")
