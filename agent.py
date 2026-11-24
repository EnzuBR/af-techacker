#!/usr/bin/env python3
"""
Agente Supervisionado de Seguranca - Tecnologias Hackers (Insper)
Integra LLM local (Ollama/qwen3:4b) com ferramentas de seguranca
para investigacoes controladas no OWASP Juice Shop.
"""

import json
import subprocess
import sys
import os
import re
import time
import datetime
import requests
from typing import Optional
from urllib.parse import urlparse

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
# Flags de nmap permitidas (sem --script, -iL, -o*, etc.)
ALLOWED_NMAP_FLAGS = {"-sV", "-sT", "-Pn", "-n", "-F", "-T3", "-T4", "--open"}


def check_scope(tool: str, params: dict) -> Optional[str]:
    """Retorna motivo do bloqueio se a acao sair do escopo, ou None se ok."""
    if tool in ("http_request", "dir_bruteforce"):
        url = params.get("url") if tool == "http_request" else params.get("base_url", TARGET)
        try:
            u = urlparse(str(url))
            port = u.port
        except ValueError:
            return f"URL invalida: {url}"
        if u.scheme != "http" or u.hostname not in ALLOWED_HOSTS or port != ALLOWED_PORT:
            return f"URL fora do escopo: {url} (permitido: http://localhost:{ALLOWED_PORT})"
    elif tool == "nmap_scan":
        host = str(params.get("target_host", ""))
        if host not in ALLOWED_HOSTS:
            return f"Host fora do escopo: {host} (permitido: {sorted(ALLOWED_HOSTS)})"
        if not re.fullmatch(r"[0-9,\-]+", str(params.get("ports", "1-10000"))):
            return f"Portas invalidas: {params.get('ports')}"
        bad = [a for a in str(params.get("extra_args", "")).split() if a not in ALLOWED_NMAP_FLAGS]
        if bad:
            return f"Flags de nmap nao permitidas: {bad} (permitidas: {sorted(ALLOWED_NMAP_FLAGS)})"
    return None

# ============================================================
# Ferramentas
# ============================================================

def nmap_scan(target_host: str, ports: str = "1-10000", extra_args: str = "-sV") -> dict:
    """Executa nmap contra o alvo para descobrir portas e servicos."""
    cmd = ["nmap", extra_args, "-p", ports, target_host]
    # flatten args that may contain spaces
    cmd_flat = []
    for c in cmd:
        cmd_flat.extend(c.split())
    try:
        result = subprocess.run(
            cmd_flat,
            capture_output=True, text=True, timeout=120
        )
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


def http_request(method: str, url: str, headers: Optional[dict] = None,
                 body: Optional[str] = None, content_type: str = "application/json") -> dict:
    """Faz requisicoes HTTP ao Juice Shop."""
    try:
        hdrs = headers or {}
        if content_type and "content-type" not in {k.lower() for k in hdrs}:
            hdrs["Content-Type"] = content_type

        resp = requests.request(
            method=method.upper(),
            url=url,
            headers=hdrs,
            data=body,
            timeout=30,
            allow_redirects=False  # redirect poderia sair do escopo
        )
        # Truncate large responses
        resp_body = resp.text[:5000]
        return {
            "tool": "http_request",
            "success": True,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp_body,
        }
    except Exception as e:
        return {"tool": "http_request", "success": False, "error": str(e)}


def dir_bruteforce(base_url: str, wordlist: Optional[list] = None) -> dict:
    """Descobre diretorios/endpoints ocultos via forca bruta."""
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

    found = []
    errors = []
    for path in wordlist:
        url = f"{base_url}/{path}"
        try:
            resp = requests.get(url, timeout=10, allow_redirects=False)
            status = resp.status_code
            if status < 400:
                found.append({"path": f"/{path}", "status": status,
                              "size": len(resp.text)})
            elif status in (401, 403):
                found.append({"path": f"/{path}", "status": status,
                              "note": "exists but restricted"})
        except Exception as e:
            errors.append({"path": f"/{path}", "error": str(e)})

    return {
        "tool": "dir_bruteforce",
        "success": True,
        "found_endpoints": found,
        "total_tested": len(wordlist),
        "errors_count": len(errors),
    }


TOOLS = {
    "nmap_scan": {
        "function": nmap_scan,
        "description": "Executa nmap para descobrir portas e servicos no alvo",
        "parameters": {
            "target_host": "IP ou hostname do alvo (ex: localhost)",
            "ports": "Range de portas (ex: '1-10000')",
            "extra_args": "Argumentos extras do nmap (ex: '-sV')"
        }
    },
    "http_request": {
        "function": http_request,
        "description": "Faz requisicoes HTTP (GET, POST, PUT, DELETE) ao Juice Shop",
        "parameters": {
            "method": "Metodo HTTP (GET, POST, PUT, DELETE)",
            "url": "URL completa do endpoint",
            "headers": "Headers adicionais (dict, opcional)",
            "body": "Corpo da requisicao (string, opcional)",
            "content_type": "Content-Type (default: application/json)"
        }
    },
    "dir_bruteforce": {
        "function": dir_bruteforce,
        "description": "Descobre diretorios e endpoints ocultos via forca bruta de paths",
        "parameters": {
            "base_url": "URL base do alvo (ex: http://localhost:3000)",
            "wordlist": "Lista de paths para testar (opcional, usa default)"
        }
    }
}

# ============================================================
# Logger
# ============================================================

class InvestigationLogger:
    def __init__(self, investigation_name: str):
        self.investigation_name = investigation_name
        self.entries = []
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename = os.path.join(LOG_DIR, f"{investigation_name}_{ts}.json")

    def log(self, action_proposed: str, tool: str, parameters: dict,
            authorization: str, result: dict, llm_interpretation: str,
            reasoning: str = "", proposed_parameters: Optional[dict] = None,
            rejection_reason: str = "", operator_note: str = ""):
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "llm_interpretation": llm_interpretation,  # leitura do modelo sobre o resultado anterior
            "action_proposed": action_proposed,
            "reasoning": reasoning,
            "tool": tool,
            "proposed_parameters": proposed_parameters if proposed_parameters is not None else parameters,
            "parameters": parameters,  # parametros efetivamente executados
            "authorization_decision": authorization,
            "rejection_reason": rejection_reason,
            "result": _truncate_result(result),
            "operator_note": operator_note,  # decisao do grupo apos ver o resultado
        }
        self.entries.append(entry)
        self.save(quiet=True)  # salva a cada passo: Ctrl+C nao perde o log

    def save(self, quiet: bool = False):
        data = {
            "investigation": self.investigation_name,
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


def _truncate_result(result: dict, max_len: int = 3000) -> dict:
    """Trunca campos longos do resultado para manter logs gerenciaveis."""
    truncated = {}
    for k, v in result.items():
        if isinstance(v, str) and len(v) > max_len:
            truncated[k] = v[:max_len] + "... [TRUNCATED]"
        elif isinstance(v, dict):
            truncated[k] = _truncate_result(v, max_len)
        elif isinstance(v, list) and len(str(v)) > max_len:
            truncated[k] = v[:20]  # keep first 20 items
        else:
            truncated[k] = v
    return truncated

# ============================================================
# LLM Interface
# ============================================================

SYSTEM_PROMPT = """You are a security agent supervised by a human operator. Reply ONLY with JSON: {"interpretation":"what the last result shows (evidence only)","action":"short description","tool":"name","parameters":{},"reasoning":"why this next step"}. Tools: nmap_scan(target_host,ports,extra_args), http_request(method,url,body,content_type,headers), dir_bruteforce(base_url). Scope: ONLY http://localhost:3000; nmap target_host is always "localhost" (never include port); allowed nmap extra_args: -sV -sT -Pn -n -F -T3 -T4 --open. Base every claim on actual results; a rejected hypothesis is a valid result. When investigation is complete: {"interpretation":"...","action":"DONE","conclusion":"text","findings":[]}"""


def build_messages(objective: str, history: list = None) -> list:
    """Build messages with few-shot examples to guide JSON output."""
    msgs = [
        {"role": "system", "content": SYSTEM_PROMPT},
        # Few-shot: so ensinam o FORMATO, sem antecipar ataques/payloads das investigacoes
        {"role": "user", "content": "Objective: check which services are running."},
        {"role": "assistant", "content": '{"interpretation":"no results yet","action":"port scan","tool":"nmap_scan","parameters":{"target_host":"localhost","ports":"1-10000","extra_args":"-sV"},"reasoning":"find open ports before anything else"}'},
        {"role": "user", "content": "Result of nmap_scan: 3000/tcp open http. Propose next action as JSON, or DONE."},
        {"role": "assistant", "content": '{"interpretation":"only port 3000 is open, serving HTTP","action":"fetch home page","tool":"http_request","parameters":{"method":"GET","url":"http://localhost:3000/"},"reasoning":"identify the application behind port 3000"}'},
        {"role": "user", "content": "Result of http_request: status 404 for every tested path. Propose next action as JSON, or DONE."},
        {"role": "assistant", "content": '{"interpretation":"all tested paths returned 404, no evidence of exposed resources","action":"DONE","conclusion":"Hypothesis not confirmed: no exposed resources found among tested paths","findings":[]}'},
        # Actual objective
        {"role": "user", "content": f"Objective: {objective}\nPropose first action as JSON."}
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
            "temperature": 0.7,
            "num_predict": 500,
            "num_ctx": 8192,  # default do Ollama trunca o historico em silencio
        }
    }

    for attempt in range(retries):
        try:
            resp = requests.post(OLLAMA_URL, json=payload, timeout=180)
            resp.raise_for_status()
            data = resp.json()
            msg = data.get("message", {})
            content = msg.get("content", "")
            # qwen3 may put actual content in thinking field when content is empty
            if not content.strip() and msg.get("thinking"):
                content = msg["thinking"]
            return content
        except Exception as e:
            print(f"[LLM] Tentativa {attempt+1} falhou: {e}", flush=True)
            if attempt < retries - 1:
                time.sleep(3)
    return '{"action": "DONE", "conclusion": "Erro: LLM indisponivel", "findings": []}'


def parse_llm_response(raw: str) -> dict:
    """Extrai JSON da resposta do LLM, tolerando texto extra e truncamento."""
    # Remove think tags if present (qwen3 uses <think>...</think>)
    raw = re.sub(r'<think>.*?</think>', '', raw, flags=re.DOTALL)
    raw = raw.strip()

    # Try direct parse
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # Try to find JSON in markdown code block
    match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Try to find any complete JSON object using brace counting
    start = raw.find('{')
    if start >= 0:
        depth = 0
        in_string = False
        escape = False
        for i in range(start, len(raw)):
            c = raw[i]
            if escape:
                escape = False
                continue
            if c == '\\' and in_string:
                escape = True
                continue
            if c == '"' and not escape:
                in_string = not in_string
                continue
            if not in_string:
                if c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(raw[start:i+1])
                        except json.JSONDecodeError:
                            break

    # Try to repair truncated JSON by closing brackets
    if start is not None and start >= 0:
        fragment = raw[start:]
        # Try adding closing braces/brackets
        for suffix in ['"}', '"}]}', '"}],"findings":[]}', '"}', '}']:
            try:
                return json.loads(fragment + suffix)
            except json.JSONDecodeError:
                continue

    # Extract what we can with regex
    tool_match = re.search(r'"tool"\s*:\s*"(\w+)"', raw)
    action_match = re.search(r'"action"\s*:\s*"([^"]+)"', raw)
    if tool_match:
        # Try to extract parameters
        params = {}
        for pm in re.finditer(r'"(\w+)"\s*:\s*"([^"]*)"', raw):
            params[pm.group(1)] = pm.group(2)
        return {
            "thinking": "Extracted from truncated response",
            "action": action_match.group(1) if action_match else "use tool",
            "tool": tool_match.group(1),
            "parameters": {k: v for k, v in params.items() if k not in ("tool", "action", "thinking", "reasoning")},
            "reasoning": "Reconstructed from partial LLM output"
        }

    # Fallback
    return {
        "action": "DONE",
        "conclusion": f"Nao foi possivel parsear resposta do LLM: {raw[:500]}",
        "findings": ["Erro de parse na resposta do LLM"]
    }


# ============================================================
# Agent Loop
# ============================================================

def ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        return ""


def run_investigation(objective: str, investigation_name: str,
                      max_steps: int = 10, auto_approve: bool = False) -> str:
    """Executa uma investigacao de seguranca supervisionada."""
    print(f"\n{'='*60}")
    print(f"INVESTIGACAO: {investigation_name}")
    print(f"OBJETIVO: {objective}")
    print(f"MODO: {'AUTOMATICO (sem supervisao)' if auto_approve else 'SUPERVISIONADO'}")
    print(f"{'='*60}\n")

    logger = InvestigationLogger(investigation_name)
    history = []  # conversation history after few-shot examples

    try:
        for step in range(1, max_steps + 1):
            print(f"\n--- Passo {step}/{max_steps} ---")

            # 1. Query LLM (so as ultimas 8 mensagens do historico p/ caber no contexto)
            print("[LLM] Consultando modelo...")
            raw_response = query_llm(build_messages(objective, history[-8:]))
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
                note = "" if auto_approve else ask(
                    "\n[OPERADOR] Avaliacao da conclusao (concorda? ha evidencia?) > ")
                logger.log(
                    action_proposed="DONE - Investigacao concluida",
                    tool="none", parameters={}, authorization="N/A",
                    result={"conclusion": parsed.get("conclusion", ""), "findings": findings},
                    llm_interpretation=interpretation,
                    operator_note=note,
                )
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
                history.append({"role": "user", "content":
                    f"Tool '{tool_name}' does not exist. Available: {list(TOOLS.keys())}. Try again with JSON."})
                logger.log(action_desc, tool_name, parameters, "rejected - ferramenta invalida",
                           {"error": f"Ferramenta '{tool_name}' nao existe"}, interpretation,
                           reasoning=reasoning)
                continue

            # 2. Authorization
            print(f"\n[PROPOSTA] {action_desc}")
            print(f"[FERRAMENTA] {tool_name}")
            print(f"[PARAMETROS] {json.dumps(parameters, ensure_ascii=False)}")
            print(f"[RAZAO] {reasoning}")

            rejection_reason = ""
            if auto_approve:
                authorization = "approved (auto)"
                print("[AUTH] Auto-aprovado")
            else:
                print("\n[AUTH] Autorizar? (s=sim / n=nao / m=modificar / q=encerrar)")
                choice = ask("> ").lower()
                if choice == "q":
                    logger.log(action_desc, tool_name, parameters, "stopped by operator",
                               {"status": "investigacao encerrada pelo operador"}, interpretation,
                               reasoning=reasoning, operator_note=ask("[OPERADOR] Motivo > "))
                    break
                if choice == "n":
                    rejection_reason = ask("[OPERADOR] Motivo da rejeicao (vai para o modelo) > ")
                    print("[AUTH] Acao rejeitada pelo operador")
                    history.append({"role": "assistant", "content": raw_response})
                    history.append({"role": "user", "content":
                        f"Action rejected by operator. Reason: {rejection_reason or 'not given'}. "
                        "Propose an alternative as JSON."})
                    logger.log(action_desc, tool_name, parameters, "rejected",
                               {"status": "rejected"}, interpretation,
                               reasoning=reasoning, rejection_reason=rejection_reason)
                    continue
                if choice == "m":
                    print("Novos parametros em JSON (copie e edite a linha [PARAMETROS] acima):")
                    try:
                        new_params = json.loads(ask("> "))
                        if not isinstance(new_params, dict):
                            raise ValueError
                        parameters = new_params
                        authorization = "modified"
                    except (json.JSONDecodeError, ValueError):
                        print("JSON invalido, usando parametros originais")
                        authorization = "approved (params invalidos, usando originais)"
                else:
                    authorization = "approved"

            # 3. Scope check (vale tambem para parametros modificados pelo operador)
            blocked = check_scope(tool_name, parameters)
            if blocked:
                print(f"[BLOQUEADO] {blocked}")
                history.append({"role": "assistant", "content": raw_response})
                history.append({"role": "user", "content":
                    f"Action blocked by scope guard: {blocked}. Propose an in-scope action as JSON."})
                logger.log(action_desc, tool_name, parameters, f"blocked - {blocked}",
                           {"status": "blocked"}, interpretation,
                           reasoning=reasoning, proposed_parameters=proposed)
                continue

            # 4. Execute tool
            print(f"\n[EXEC] Executando {tool_name}...")
            tool_func = TOOLS[tool_name]["function"]
            try:
                result = tool_func(**parameters)
            except TypeError as e:
                print(f"[ERRO] Parametros invalidos: {e}")
                result = {"tool": tool_name, "success": False, "error": f"Parametros invalidos: {e}"}

            success = result.get("success", False)
            print(f"[RESULTADO] {'Sucesso' if success else 'Falha'}")

            if tool_name == "nmap_scan" and result.get("stdout"):
                print(result["stdout"][:800])
            elif tool_name == "http_request":
                print(f"  Status: {result.get('status_code', 'N/A')}")
                body = result.get("body", "")
                if body:
                    print(f"  Body (preview): {body[:300]}")
            elif tool_name == "dir_bruteforce":
                found = result.get("found_endpoints", [])
                print(f"  Endpoints encontrados: {len(found)}")
                for ep in found[:15]:
                    print(f"    {ep['path']} -> {ep['status']} (size {ep.get('size', '-')})")
            if result.get("error"):
                print(f"  Erro: {result['error']}")

            # 5. Operator note: decisao do grupo apos ver o resultado (opcional, vai p/ o modelo)
            note = "" if auto_approve else ask(
                "\n[OPERADOR] Nota sobre o resultado (Enter = sem nota) > ")

            result_summary = json.dumps(_truncate_result(result, max_len=1500), ensure_ascii=False)
            if len(result_summary) > 2000:
                result_summary = result_summary[:2000] + "...[TRUNCATED]"
            feedback = f"Result of {tool_name}: {result_summary}\n"
            if note:
                feedback += f"Operator note: {note}\n"
            history.append({"role": "assistant", "content": json.dumps(parsed, ensure_ascii=False)})
            history.append({"role": "user", "content":
                feedback + "\nInterpret the result and propose next action as JSON, or DONE."})

            logger.log(action_desc, tool_name, parameters, authorization, result, interpretation,
                       reasoning=reasoning, proposed_parameters=proposed, operator_note=note)
    except KeyboardInterrupt:
        print("\n[!] Interrompido (Ctrl+C)")
        logger.log("interrupted", "none", {}, "stopped by operator",
                   {"status": "Ctrl+C"}, "")

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
        "max_steps": 10
    },
    "sqli": {
        "name": "autenticacao",
        "objective": (
            "Hypothesis: the authentication mechanism of the OWASP Juice Shop at "
            "http://localhost:3000 can be bypassed, allowing access to another user's account "
            "without knowing the password. Find how login works and test the hypothesis."
        ),
        "max_steps": 10
    },
    "xss": {
        "name": "tratamento_de_entradas",
        "objective": (
            "Hypothesis: the OWASP Juice Shop at http://localhost:3000 does not properly "
            "sanitize user input (search, feedback or other parameters), allowing injection. "
            "Identify input points and test the hypothesis. Note that only HTTP requests are "
            "available (no browser)."
        ),
        "max_steps": 10
    }
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
            auto_approve=auto_approve
        )
        print(f"\nArquivo de log: {logfile}")
        print()


if __name__ == "__main__":
    main()
