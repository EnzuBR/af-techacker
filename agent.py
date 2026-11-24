#!/usr/bin/env python3
"""
Agente Supervisionado de Seguranca - Tecnologias Hackers (Insper)
Integra LLM local (Ollama/qwen3:4b) com ferramentas de seguranca
para investigacoes controladas no OWASP Juice Shop.
"""

import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from typing import Any, Optional
from urllib.parse import urlparse

import requests

# Force unbuffered output
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

# ============================================================
# Configuracao
# ============================================================
OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "qwen3:4b"
TARGET = "http://localhost:3000"
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")

os.makedirs(LOG_DIR, exist_ok=True)

# ============================================================
# Escopo: o agente so pode agir contra o Juice Shop local
# ============================================================
ALLOWED_HOSTS = {"localhost", "127.0.0.1"}
ALLOWED_PORT = 3000
ALLOWED_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
# Flags de nmap permitidas (sem --script, -iL, -o*, etc.)
ALLOWED_NMAP_FLAGS = {"-sV", "-sT", "-Pn", "-n", "-F", "-T3", "-T4", "--open"}
MAX_WORDLIST_LEN = 200


def check_scope(tool: str, params: dict) -> Optional[str]:
    """Retorna motivo do bloqueio se a acao sair do escopo, ou None se ok."""
    if not isinstance(params, dict):
        return "Parametros invalidos: esperado objeto JSON"
    if tool not in TOOLS:
        return f"Ferramenta desconhecida: {tool}"

    if tool == "http_request":
        method = str(params.get("method", "")).upper().strip()
        if method not in ALLOWED_HTTP_METHODS:
            return f"Metodo HTTP nao permitido: {method or '(vazio)'}"
        url = params.get("url")
        if not url or not isinstance(url, str):
            return f"URL invalida: {url}"
        try:
            u = urlparse(url)
            port = u.port
        except ValueError:
            return f"URL invalida: {url}"
        if (
            u.scheme != "http"
            or u.username is not None
            or u.password is not None
            or u.hostname not in ALLOWED_HOSTS
            or port != ALLOWED_PORT
        ):
            return f"URL fora do escopo: {url} (permitido: http://localhost:{ALLOWED_PORT})"

    elif tool == "dir_bruteforce":
        base_url = params.get("base_url", TARGET)
        if not base_url or not isinstance(base_url, str):
            return f"base_url invalida: {base_url}"
        try:
            u = urlparse(base_url)
            port = u.port
        except ValueError:
            return f"URL invalida: {base_url}"
        if (
            u.scheme != "http"
            or u.username is not None
            or u.password is not None
            or u.hostname not in ALLOWED_HOSTS
            or port != ALLOWED_PORT
            or u.query
            or u.fragment
        ):
            return f"URL fora do escopo: {base_url} (permitido: http://localhost:{ALLOWED_PORT})"

        if "wordlist" in params and params["wordlist"] is not None:
            wl = params["wordlist"]
            if not isinstance(wl, list) or not (1 <= len(wl) <= MAX_WORDLIST_LEN):
                return f"wordlist invalida: deve ser lista com 1 a {MAX_WORDLIST_LEN} caminhos"
            for item in wl:
                if not isinstance(item, str) or not item:
                    return f"Item invalido na wordlist: {item!r}"
                if (
                    "://" in item
                    or "@" in item
                    or ".." in item
                    or "?" in item
                    or "#" in item
                    or item.startswith("//")
                    or re.search(r"\s", item)
                ):
                    return f"Caminho inseguro/fora do escopo na wordlist: {item!r}"

    elif tool == "nmap_scan":
        host = str(params.get("target_host", "")).strip()
        if host not in ALLOWED_HOSTS:
            return f"Host fora do escopo: {host} (permitido: {sorted(ALLOWED_HOSTS)})"
        ports = str(params.get("ports", str(ALLOWED_PORT))).strip()
        if ports != str(ALLOWED_PORT):
            return f"Porta fora do escopo: {ports} (permitido apenas: {ALLOWED_PORT})"
        raw_args = "" if params.get("extra_args") is None else str(params.get("extra_args", "-sV"))
        bad = [a for a in raw_args.split() if a not in ALLOWED_NMAP_FLAGS]
        if bad:
            return f"Flags de nmap nao permitidas: {bad} (permitidas: {sorted(ALLOWED_NMAP_FLAGS)})"

    return None


# ============================================================
# Ferramentas
# ============================================================

def nmap_scan(target_host: str, ports: str = "3000", extra_args: str = "-sV") -> dict:
    """Executa nmap contra a porta do Juice Shop local."""
    flags = str(extra_args or "").split()
    cmd = ["nmap", *flags, "-p", str(ports), target_host]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {
            "tool": "nmap_scan",
            "success": result.returncode == 0,
            "stdout": result.stdout[:4000],
            "stderr": result.stderr[:1000],
        }
    except subprocess.TimeoutExpired:
        return {"tool": "nmap_scan", "success": False, "error": "timeout"}
    except Exception as e:
        return {"tool": "nmap_scan", "success": False, "error": str(e)}


def http_request(
    method: str,
    url: str,
    headers: Optional[dict] = None,
    body: Optional[Any] = None,
    content_type: Optional[str] = None,
) -> dict:
    """Faz requisicoes HTTP ao Juice Shop sem seguir redirecionamentos."""
    try:
        hdrs = dict(headers) if isinstance(headers, dict) else {}
        method_up = method.upper().strip()

        if isinstance(body, (dict, list)):
            data = json.dumps(body, ensure_ascii=False)
            if not content_type:
                content_type = "application/json"
        else:
            data = body
            if body is not None and not content_type and method_up in {"POST", "PUT", "PATCH"}:
                content_type = "application/json"

        if content_type and "content-type" not in {k.lower() for k in hdrs}:
            hdrs["Content-Type"] = content_type

        warnings = []
        parsed_u = urlparse(url)
        if parsed_u.fragment:
            warnings.append(
                "A URL contem fragmento '#...': clientes HTTP nao enviam fragmentos ao servidor, "
                "entao a resposta reflete apenas o HTML estatico da SPA (DOM-based XSS exige navegador)."
            )

        resp = requests.request(
            method=method_up,
            url=url,
            headers=hdrs,
            data=data,
            timeout=30,
            allow_redirects=False,  # redirect poderia sair do escopo
        )
        resp_body = resp.text[:5000]
        res = {
            "tool": "http_request",
            "success": True,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp_body,
            "body_length": len(resp.text),
            "body_truncated": len(resp.text) > 5000,
        }
        if 300 <= resp.status_code < 400 and "Location" in resp.headers:
            res["redirect_location"] = resp.headers["Location"]
        if warnings:
            res["warnings"] = warnings
        return res
    except Exception as e:
        return {"tool": "http_request", "success": False, "error": str(e)}


def dir_bruteforce(base_url: str, wordlist: Optional[list] = None) -> dict:
    """Descobre endpoints reais filtrando o fallback HTML da SPA Angular."""
    if wordlist is None:
        wordlist = [
            "admin", "api", "rest", "login", "register", "users", "products",
            "search", "redirect", "file", "assets", "public", "private",
            "backup", "config", "debug", "test", "metrics", "health",
            "swagger", "docs", "api-docs", "socket.io", "ftp", "encryptionkeys",
            "robots.txt", "security.txt", ".well-known", "promotion",
            "profile", "basket", "address", "payment", "wallet", "order",
            "delivery", "recycle", "complaint", "chatbot", "track",
            "accounting", "b2b", "dataerasure", "rest/admin",
            "rest/user", "rest/products", "rest/basket",
            "api/SecurityQuestions", "api/Users", "api/Challenges",
            "api/Products", "api/Feedbacks", "api/Complaints",
            "api/Recycles", "api/SecurityAnswers", "api/Quantitys",
            "api/Cards", "api/Addresss", "api/Deliverys",
            "snippet", "rest/memories", "rest/chatbot",
        ]

    base = base_url.rstrip("/")

    # Detecta assinatura do fallback SPA (200 OK com index.html para rotas inexistentes)
    baseline_hash = None
    baseline_size = None
    try:
        base_resp = requests.get(
            f"{base}/__spa_baseline_nonexistent_404_check__",
            timeout=10,
            allow_redirects=False,
        )
        base_ctype = base_resp.headers.get("Content-Type", "").lower()
        if base_resp.status_code == 200 and "text/html" in base_ctype:
            baseline_hash = hashlib.sha256(
                base_resp.text.encode("utf-8", errors="replace")
            ).hexdigest()
            baseline_size = len(base_resp.text)
    except Exception:
        pass

    found = []
    errors = []
    spa_filtered = 0

    for path in wordlist:
        clean_path = str(path).lstrip("/")
        url = f"{base}/{clean_path}"
        try:
            resp = requests.get(url, timeout=10, allow_redirects=False)
            status = resp.status_code
            ctype = resp.headers.get("Content-Type", "").split(";")[0].strip()

            if status == 200 and baseline_hash is not None:
                body_hash = hashlib.sha256(
                    resp.text.encode("utf-8", errors="replace")
                ).hexdigest()
                if body_hash == baseline_hash:
                    spa_filtered += 1
                    continue

            if status < 400:
                ep = {"path": f"/{clean_path}", "status": status, "size": len(resp.text)}
                if ctype:
                    ep["content_type"] = ctype
                if 300 <= status < 400 and "Location" in resp.headers:
                    ep["location"] = resp.headers["Location"]
                found.append(ep)
            elif status in (401, 403):
                ep = {
                    "path": f"/{clean_path}",
                    "status": status,
                    "note": "exists but restricted",
                }
                if ctype:
                    ep["content_type"] = ctype
                found.append(ep)
        except Exception as e:
            errors.append({"path": f"/{clean_path}", "error": str(e)})

    return {
        "tool": "dir_bruteforce",
        "success": True,
        "found_endpoints": found,
        "total_tested": len(wordlist),
        "spa_fallback_filtered_count": spa_filtered,
        "spa_fallback_baseline_size": baseline_size,
        "errors_count": len(errors),
    }


TOOLS = {
    "nmap_scan": {
        "function": nmap_scan,
        "description": "Executa nmap contra o Juice Shop local (porta 3000)",
        "parameters": {
            "target_host": "Hostname local permitido ('localhost' ou '127.0.0.1')",
            "ports": "Porta alvo estrita ('3000')",
            "extra_args": "Flags permitidas do nmap (ex: '-sV')",
        },
    },
    "http_request": {
        "function": http_request,
        "description": "Faz requisicoes HTTP (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS) ao Juice Shop",
        "parameters": {
            "method": "Metodo HTTP permitido",
            "url": "URL completa em http://localhost:3000/...",
            "headers": "Headers adicionais (dict, opcional)",
            "body": "Corpo da requisicao (string ou objeto JSON, opcional)",
            "content_type": "Content-Type (opcional; default application/json apenas quando ha body)",
        },
    },
    "dir_bruteforce": {
        "function": dir_bruteforce,
        "description": "Descobre endpoints reais filtrando rotas SPA genericas",
        "parameters": {
            "base_url": "URL base do alvo (http://localhost:3000)",
            "wordlist": "Lista de caminhos relativos para testar (opcional, usa default)",
        },
    },
}

# ============================================================
# Logger
# ============================================================

class InvestigationLogger:
    def __init__(
        self,
        investigation_name: str,
        objective: str = "",
        mode: str = "supervised",
        max_steps: int = 10,
    ):
        self.investigation_name = investigation_name
        self.objective = objective
        self.mode = mode
        self.max_steps = max_steps
        self.entries = []
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename = os.path.join(LOG_DIR, f"{investigation_name}_{ts}.json")

    def log(
        self,
        action_proposed: str,
        tool: str,
        parameters: dict,
        authorization: str,
        result: dict,
        llm_interpretation: str,
        reasoning: str = "",
        proposed_parameters: Optional[dict] = None,
        rejection_reason: str = "",
        operator_note: str = "",
    ):
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "llm_interpretation": llm_interpretation,
            "action_proposed": action_proposed,
            "reasoning": reasoning,
            "tool": tool,
            "proposed_parameters": (
                proposed_parameters if proposed_parameters is not None else parameters
            ),
            "parameters": parameters,
            "authorization_decision": authorization,
            "rejection_reason": rejection_reason,
            "result": _truncate_result(result),
            "operator_note": operator_note,
        }
        self.entries.append(entry)
        self.save(quiet=True)  # salva a cada passo: Ctrl+C nao perde o log

    def save(self, quiet: bool = False):
        data = {
            "investigation": self.investigation_name,
            "objective": self.objective,
            "model": MODEL,
            "target": TARGET,
            "mode": self.mode,
            "max_steps": self.max_steps,
            "total_actions": len(self.entries),
            "start_time": self.entries[0]["timestamp"] if self.entries else None,
            "end_time": self.entries[-1]["timestamp"] if self.entries else None,
            "entries": self.entries,
        }
        with open(self.filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        if not quiet:
            print(f"\n[LOG] Salvo em: {self.filename}")
        return self.filename


def _truncate_result(result: dict, max_len: int = 3000, max_list_items: int = 60) -> dict:
    """Trunca campos longos do resultado preservando listas de endpoints relevantes."""
    truncated = {}
    for k, v in result.items():
        if isinstance(v, str) and len(v) > max_len:
            truncated[k] = v[:max_len] + "... [TRUNCATED]"
        elif isinstance(v, dict):
            truncated[k] = _truncate_result(v, max_len, max_list_items)
        elif isinstance(v, list):
            truncated[k] = v[:max_list_items] if len(v) > max_list_items else v
        else:
            truncated[k] = v
    return truncated


# ============================================================
# LLM Interface
# ============================================================

SYSTEM_PROMPT = (
    "You are a security investigation agent supervised by a human operator.\n"
    "Reply ONLY with a single valid JSON object (no markdown, no extra text).\n"
    "To propose a tool call, return JSON with keys:\n"
    '  "interpretation": factual reading of the previous result (or initial state),\n'
    '  "action": concise description of the proposed step,\n'
    '  "tool": MUST be one of "nmap_scan", "http_request", or "dir_bruteforce",\n'
    '  "parameters": dict matching the chosen tool,\n'
    '  "reasoning": technical justification for this step.\n'
    "When finished, return JSON with keys:\n"
    '  "interpretation", "action": "DONE", "conclusion", "findings": [list].\n'
    "Tools:\n"
    "- nmap_scan(target_host, ports, extra_args): target_host must be 'localhost' or '127.0.0.1' (never include ':port'); ports must be '3000'; allowed extra_args: -sV -sT -Pn -n -F -T3 -T4 --open.\n"
    "- http_request(method, url, headers, body, content_type): url must start with http://localhost:3000 or http://127.0.0.1:3000. HTTP clients NEVER send URL '#fragment' to the server; test backend APIs directly and report DOM-only limits honestly.\n"
    "- dir_bruteforce(base_url, wordlist): base_url must be http://localhost:3000; filters generic SPA HTML fallback automatically.\n"
    "Rules: Never repeat the exact same tool call and parameters twice. Base every claim strictly on observed evidence; a rejected hypothesis backed by evidence is a valid result."
)


def build_messages(objective: str, history: list = None) -> list:
    """Build messages with few-shot examples to guide JSON output."""
    msgs = [
        {"role": "system", "content": SYSTEM_PROMPT},
        # Few-shot: ensina apenas o FORMATO e escopo, sem antecipar ataques das investigacoes
        {"role": "user", "content": "Objective: check if the local web target is listening."},
        {
            "role": "assistant",
            "content": (
                '{"interpretation":"no results yet","action":"scan target port","tool":"nmap_scan",'
                '"parameters":{"target_host":"localhost","ports":"3000","extra_args":"-sV"},'
                '"reasoning":"verify whether port 3000 is open and inspect service banner"}'
            ),
        },
        {
            "role": "user",
            "content": "Result of nmap_scan: 3000/tcp open http. Propose next action as JSON, or DONE.",
        },
        {
            "role": "assistant",
            "content": (
                '{"interpretation":"port 3000 is open serving HTTP","action":"fetch home page","tool":"http_request",'
                '"parameters":{"method":"GET","url":"http://localhost:3000/"},'
                '"reasoning":"inspect headers and HTML returned by the application"}'
            ),
        },
        {
            "role": "user",
            "content": "Result of http_request: status 404 for every tested path. Propose next action as JSON, or DONE.",
        },
        {
            "role": "assistant",
            "content": (
                '{"interpretation":"all tested paths returned 404, no evidence of exposed resources",'
                '"action":"DONE","conclusion":"Hypothesis not confirmed: no exposed resources found among tested paths","findings":[]}'
            ),
        },
        {"role": "user", "content": f"Objective: {objective}\nPropose first action as JSON."},
    ]
    if history:
        msgs.extend(history)
    return msgs


def query_llm(messages: list, retries: int = 3) -> str:
    """Consulta o LLM via Ollama API."""
    payload = {
        "model": MODEL,
        "messages": messages,
        "stream": False,
        "think": False,
        "format": "json",
        "options": {
            "temperature": 0.25,
            "num_predict": 700,
            "num_ctx": 8192,  # default do Ollama trunca o historico em silencio
        },
    }

    for attempt in range(retries):
        try:
            resp = requests.post(OLLAMA_URL, json=payload, timeout=180)
            resp.raise_for_status()
            data = resp.json()
            msg = data.get("message", {})
            content = msg.get("content", "")
            # qwen3 pode colocar a resposta em thinking se content vier vazio
            if not content.strip() and msg.get("thinking"):
                content = msg["thinking"]
            return content
        except Exception as e:
            print(f"[LLM] Tentativa {attempt + 1} falhou: {e}", flush=True)
            if attempt < retries - 1:
                time.sleep(3)
    return '{"action": "DONE", "conclusion": "Erro: LLM indisponivel", "findings": []}'


def parse_llm_response(raw: str) -> dict:
    """Extrai objeto JSON da resposta do LLM, tolerando texto extra e truncamento."""
    raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()

    # Direct parse
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass

    # Markdown code block
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if match:
        try:
            obj = json.loads(match.group(1))
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

    # First complete JSON object using brace counting
    start = raw.find("{")
    if start >= 0:
        depth = 0
        in_string = False
        escape = False
        for i in range(start, len(raw)):
            c = raw[i]
            if escape:
                escape = False
                continue
            if c == "\\" and in_string:
                escape = True
                continue
            if c == '"' and not escape:
                in_string = not in_string
                continue
            if not in_string:
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            obj = json.loads(raw[start : i + 1])
                            if isinstance(obj, dict):
                                return obj
                        except json.JSONDecodeError:
                            break

    # Repair truncated JSON fragment
    if start >= 0:
        fragment = raw[start:]
        for suffix in ['"}}', '"}', "}}", '"}]}', '"}],"findings":[]}', "}"]:
            try:
                obj = json.loads(fragment + suffix)
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                continue

    # Regex fallback
    tool_match = re.search(r'"tool"\s*:\s*"(\w+)"', raw)
    action_match = re.search(r'"action"\s*:\s*"([^"]+)"', raw)
    if tool_match:
        params = {}
        for pm in re.finditer(r'"(\w+)"\s*:\s*"([^"]*)"', raw):
            params[pm.group(1)] = pm.group(2)
        return {
            "interpretation": "Extracted from truncated response",
            "action": action_match.group(1) if action_match else "use tool",
            "tool": tool_match.group(1),
            "parameters": {
                k: v
                for k, v in params.items()
                if k not in ("tool", "action", "thinking", "interpretation", "reasoning")
            },
            "reasoning": "Reconstructed from partial LLM output",
        }

    return {
        "action": "DONE",
        "conclusion": f"Nao foi possivel parsear resposta do LLM: {raw[:500]}",
        "findings": ["Erro de parse na resposta do LLM"],
    }


# ============================================================
# Agent Loop
# ============================================================

def ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        return ""


def run_investigation(
    objective: str,
    investigation_name: str,
    max_steps: int = 10,
    auto_approve: bool = False,
) -> str:
    """Executa uma investigacao de seguranca supervisionada."""
    mode = "auto" if auto_approve else "supervised"
    print(f"\n{'=' * 60}")
    print(f"INVESTIGACAO: {investigation_name}")
    print(f"OBJETIVO: {objective}")
    print(f"MODO: {'AUTOMATICO (sem supervisao)' if auto_approve else 'SUPERVISIONADO'}")
    print(f"{'=' * 60}\n")

    logger = InvestigationLogger(
        investigation_name, objective=objective, mode=mode, max_steps=max_steps
    )
    history = []
    executed_steps = 0
    max_iterations = max(max_steps * 2, 20)
    iteration = 0
    completed = False
    operator_stopped = False

    try:
        while executed_steps < max_steps and iteration < max_iterations:
            iteration += 1
            print(f"\n--- Execucao {executed_steps + 1}/{max_steps} (ciclo {iteration}) ---")

            # 1. Query LLM (ultimas 16 mensagens = 8 turnos)
            print("[LLM] Consultando modelo...")
            raw_response = query_llm(build_messages(objective, history[-16:]))
            parsed = parse_llm_response(raw_response)
            interpretation = parsed.get("interpretation", "")
            if interpretation:
                print(f"[LLM] Interpretacao: {interpretation}")

            # Check if done
            if parsed.get("action") == "DONE":
                print(f"\n[DONE] Conclusao do modelo: {parsed.get('conclusion', 'N/A')}")
                findings = parsed.get("findings", [])
                for i, f in enumerate(findings, 1):
                    print(f"  [{i}] {f}")
                note = (
                    ""
                    if auto_approve
                    else ask("\n[OPERADOR] Avaliacao da conclusao (concorda? ha evidencia?) > ")
                )
                logger.log(
                    action_proposed="DONE - Investigacao concluida",
                    tool="none",
                    parameters={},
                    authorization="N/A",
                    result={"conclusion": parsed.get("conclusion", ""), "findings": findings},
                    llm_interpretation=interpretation,
                    operator_note=note,
                )
                completed = True
                break

            tool_name = parsed.get("tool", "")
            parameters = parsed.get("parameters", {})
            if not isinstance(parameters, dict):
                parameters = {}
            proposed = dict(parameters)
            action_desc = parsed.get("action", "Acao nao descrita")
            reasoning = parsed.get("reasoning", "")

            if tool_name not in TOOLS:
                print(f"[ERRO] Ferramenta desconhecida: {tool_name}")
                history.append({"role": "assistant", "content": raw_response})
                history.append(
                    {
                        "role": "user",
                        "content": (
                            f"Tool '{tool_name}' does not exist. "
                            f"Available: {list(TOOLS.keys())}. Try again with JSON."
                        ),
                    }
                )
                logger.log(
                    action_desc,
                    tool_name,
                    parameters,
                    "rejected - ferramenta invalida",
                    {"error": f"Ferramenta '{tool_name}' nao existe"},
                    interpretation,
                    reasoning=reasoning,
                    proposed_parameters=proposed,
                )
                continue

            # 2. Authorization (explicita: s / n / m / q)
            print(f"\n[PROPOSTA] {action_desc}")
            print(f"[FERRAMENTA] {tool_name}")
            print(f"[PARAMETROS] {json.dumps(parameters, ensure_ascii=False)}")
            print(f"[RAZAO] {reasoning}")

            rejection_reason = ""
            authorization = ""
            action_outcome = "execute"

            if auto_approve:
                authorization = "approved (auto)"
                print("[AUTH] Auto-aprovado")
            else:
                while True:
                    print("\n[AUTH] Autorizar? (s=sim / n=nao / m=modificar / q=encerrar)")
                    choice = ask("> ").lower()
                    if choice == "q":
                        op_reason = ask("[OPERADOR] Motivo do encerramento > ")
                        logger.log(
                            action_desc,
                            tool_name,
                            parameters,
                            "stopped by operator",
                            {"status": "investigacao encerrada pelo operador"},
                            interpretation,
                            reasoning=reasoning,
                            proposed_parameters=proposed,
                            operator_note=op_reason,
                        )
                        action_outcome = "quit"
                        break
                    if choice == "n":
                        rejection_reason = ask(
                            "[OPERADOR] Motivo da rejeicao (vai para o modelo) > "
                        )
                        print("[AUTH] Acao rejeitada pelo operador")
                        history.append({"role": "assistant", "content": raw_response})
                        history.append(
                            {
                                "role": "user",
                                "content": (
                                    f"Action rejected by operator. "
                                    f"Reason: {rejection_reason or 'not given'}. "
                                    "Propose an alternative as JSON."
                                ),
                            }
                        )
                        logger.log(
                            action_desc,
                            tool_name,
                            parameters,
                            "rejected",
                            {"status": "rejected"},
                            interpretation,
                            reasoning=reasoning,
                            proposed_parameters=proposed,
                            rejection_reason=rejection_reason,
                        )
                        action_outcome = "rejected"
                        break
                    if choice == "m":
                        print(
                            "Novos parametros em JSON (copie e edite a linha [PARAMETROS]; "
                            "Enter vazio cancela):"
                        )
                        cancelled_mod = False
                        while True:
                            raw_mod = ask("> ")
                            if not raw_mod:
                                cancelled_mod = True
                                break
                            try:
                                new_params = json.loads(raw_mod)
                                if not isinstance(new_params, dict):
                                    raise ValueError("JSON deve ser um objeto")
                                parameters = new_params
                                authorization = "modified"
                                break
                            except (json.JSONDecodeError, ValueError) as e:
                                print(f"[AUTH] JSON invalido ({e}). Tente novamente ou Enter para voltar.")
                        if cancelled_mod:
                            continue
                        break
                    if choice == "s":
                        authorization = "approved"
                        break
                    print("[AUTH] Opcao invalida. Digite s, n, m ou q.")

            if action_outcome == "quit":
                operator_stopped = True
                break
            if action_outcome == "rejected":
                continue

            # 3. Scope check (vale tambem para parametros modificados pelo operador)
            blocked = check_scope(tool_name, parameters)
            if blocked:
                print(f"[BLOQUEADO] {blocked}")
                history.append({"role": "assistant", "content": raw_response})
                history.append(
                    {
                        "role": "user",
                        "content": (
                            f"Action blocked by scope guard: {blocked}. "
                            "Propose an in-scope action as JSON."
                        ),
                    }
                )
                logger.log(
                    action_desc,
                    tool_name,
                    parameters,
                    f"blocked - {blocked}",
                    {"status": "blocked"},
                    interpretation,
                    reasoning=reasoning,
                    proposed_parameters=proposed,
                )
                continue

            # 4. Execute tool
            print(f"\n[EXEC] Executando {tool_name}...")
            tool_func = TOOLS[tool_name]["function"]
            try:
                result = tool_func(**parameters)
            except TypeError as e:
                print(f"[ERRO] Parametros invalidos: {e}")
                result = {"tool": tool_name, "success": False, "error": f"Parametros invalidos: {e}"}

            executed_steps += 1
            success = result.get("success", False)
            print(f"[RESULTADO] {'Sucesso' if success else 'Falha'}")

            if tool_name == "nmap_scan" and result.get("stdout"):
                print(result["stdout"][:800])
            elif tool_name == "http_request":
                print(f"  Status: {result.get('status_code', 'N/A')}")
                if result.get("redirect_location"):
                    print(f"  Redirect: {result['redirect_location']}")
                body = result.get("body", "")
                if body:
                    print(f"  Body (preview): {body[:300]}")
            elif tool_name == "dir_bruteforce":
                found = result.get("found_endpoints", [])
                filtered = result.get("spa_fallback_filtered_count", 0)
                print(f"  Endpoints encontrados: {len(found)} (SPA fallback filtrados: {filtered})")
                for ep in found[:25]:
                    extra = f" [{ep['content_type']}]" if ep.get("content_type") else ""
                    print(f"    {ep['path']} -> {ep['status']} (size {ep.get('size', '-')}{extra})")
            for w in result.get("warnings", []):
                print(f"  [AVISO] {w}")
            if result.get("error"):
                print(f"  Erro: {result['error']}")

            # 5. Operator note: decisao do grupo apos ver o resultado
            note = (
                ""
                if auto_approve
                else ask("\n[OPERADOR] Nota sobre o resultado (Enter = sem nota) > ")
            )

            result_summary = json.dumps(
                _truncate_result(result, max_len=1800, max_list_items=60),
                ensure_ascii=False,
            )
            if len(result_summary) > 3500:
                result_summary = result_summary[:3500] + "...[TRUNCATED]"

            feedback = ""
            if authorization == "modified":
                feedback += (
                    "Operator modified parameters before execution. "
                    f"Actually executed parameters: {json.dumps(parameters, ensure_ascii=False)}\n"
                )
            feedback += f"Result of {tool_name}: {result_summary}\n"
            if note:
                feedback += f"Operator note: {note}\n"

            history.append({"role": "assistant", "content": json.dumps(parsed, ensure_ascii=False)})
            history.append(
                {
                    "role": "user",
                    "content": feedback + "\nInterpret the result and propose next action as JSON, or DONE.",
                }
            )

            logger.log(
                action_desc,
                tool_name,
                parameters,
                authorization,
                result,
                interpretation,
                reasoning=reasoning,
                proposed_parameters=proposed,
                operator_note=note,
            )

        if not completed and not operator_stopped:
            print("\n[INFO] Limite de passos atingido sem conclusao final. Solicitando sintese ao modelo...")
            wrap_history = list(history[-16:])
            wrap_history.append(
                {
                    "role": "user",
                    "content": (
                        "Step limit reached. Summarize ONLY what was observed in actual tool results "
                        "above and return final DONE JSON with interpretation, action='DONE', conclusion, findings."
                    ),
                }
            )
            raw_wrap = query_llm(build_messages(objective, wrap_history))
            parsed_wrap = parse_llm_response(raw_wrap)
            if parsed_wrap.get("action") != "DONE":
                conclusion_text = (
                    parsed_wrap.get("interpretation")
                    or "Limite de passos atingido sem conclusao definitiva; consultar registros."
                )
                findings = parsed_wrap.get("findings", [])
                if not isinstance(findings, list):
                    findings = []
            else:
                conclusion_text = parsed_wrap.get("conclusion", "Limite de passos atingido.")
                findings = parsed_wrap.get("findings", [])

            print(f"\n[DONE - LIMITE] Conclusao do modelo: {conclusion_text}")
            for i, f in enumerate(findings, 1):
                print(f"  [{i}] {f}")
            note = (
                ""
                if auto_approve
                else ask("\n[OPERADOR] Avaliacao da conclusao final (concorda? ha evidencia?) > ")
            )
            logger.log(
                action_proposed="DONE - Investigacao concluida (limite de passos)",
                tool="none",
                parameters={},
                authorization="N/A",
                result={"conclusion": conclusion_text, "findings": findings},
                llm_interpretation=parsed_wrap.get("interpretation", conclusion_text),
                operator_note=note,
            )

    except KeyboardInterrupt:
        print("\n[!] Interrompido (Ctrl+C)")
        logger.log(
            "interrupted",
            "none",
            {},
            "stopped by operator",
            {"status": "Ctrl+C"},
            "",
        )

    return logger.save()


# ============================================================
# Investigacoes Pre-definidas
# Objetivos abertos: hipotese + escopo. O caminho fica por conta do modelo.
# ============================================================

INVESTIGATIONS = {
    "recon": {
        "name": "reconhecimento_enumeracao",
        "objective": (
            "Hypothesis: the OWASP Juice Shop at http://localhost:3000 exposes services, "
            "endpoints or files that reveal sensitive information. "
            "Map the attack surface and confirm or reject the hypothesis with evidence."
        ),
        "max_steps": 10,
    },
    "sqli": {
        "name": "autenticacao",
        "objective": (
            "Hypothesis: the authentication mechanism of the OWASP Juice Shop at "
            "http://localhost:3000 can be bypassed, allowing access to another user's account "
            "without knowing the password. Find how login works and test the hypothesis."
        ),
        "max_steps": 10,
    },
    "xss": {
        "name": "tratamento_de_entradas",
        "objective": (
            "Hypothesis: the OWASP Juice Shop at http://localhost:3000 does not properly "
            "sanitize user input (search, feedback or other parameters), allowing injection. "
            "Identify input points and test the hypothesis. Note that only HTTP requests are "
            "available (no browser)."
        ),
        "max_steps": 10,
    },
}


def main():
    if len(sys.argv) < 2:
        print("Uso: python3 agent.py <investigacao> [--auto]")
        print(f"Investigacoes disponiveis: {list(INVESTIGATIONS.keys())}")
        print('  python3 agent.py custom "objetivo livre"   (objetivo definido pelo operador)')
        print("  --auto: aprova tudo sem perguntar (NAO usar nas investigacoes avaliadas)")
        print("  --all: executa todas as investigacoes")
        sys.exit(1)

    auto_approve = "--auto" in sys.argv

    if sys.argv[1] == "custom":
        if len(sys.argv) < 3 or sys.argv[2].startswith("--"):
            print('Uso: python3 agent.py custom "objetivo"')
            sys.exit(1)
        logfile = run_investigation(sys.argv[2], "custom", 10, auto_approve)
        print(f"\nArquivo de log: {logfile}")
        return

    targets = list(INVESTIGATIONS.keys()) if "--all" in sys.argv else [sys.argv[1]]

    for target in targets:
        if target.startswith("--"):
            continue
        if target not in INVESTIGATIONS:
            print(f"Investigacao '{target}' nao encontrada.")
            print(f"Disponiveis: {list(INVESTIGATIONS.keys())}")
            sys.exit(1)

        inv = INVESTIGATIONS[target]
        logfile = run_investigation(
            objective=inv["objective"],
            investigation_name=inv["name"],
            max_steps=inv["max_steps"],
            auto_approve=auto_approve,
        )
        print(f"\nArquivo de log: {logfile}")
        print()


if __name__ == "__main__":
    main()
