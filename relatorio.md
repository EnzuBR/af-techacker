# Relatório Técnico — Testes de Segurança Ofensivos Supervisionados com LLM Local

**Instituição / Disciplina:** Insper — Tecnologias Hackers (Avaliação Final, Prof. Rodolfo Avelino)  
**Integrantes do Grupo:** Enzo Ristori, Gabriel Nasser, Greta Faria  
**Ambiente Isolado:** Kit `kit08` (Ubuntu 22.04.5 LTS · rede loopback `localhost`)  
**Data:** 24/11/2026  
**Repositório e registros completos:** `https://github.com/EnzuBR/af-techacker` (pasta [`logs/`](logs/))  
**Versão formatada em PDF (6 páginas):** `relatorio_tecnico_af_techacker.pdf`

---

## Resumo Executivo

Este relatório documenta o desenvolvimento, a execução supervisionada e a análise crítica de um agente de segurança em Python ([`agent.py`](agent.py)) que integra o modelo de linguagem local **`qwen3:4b`** (Ollama) a três ferramentas limitadas sobre uma instância Docker isolada do **OWASP Juice Shop** (`http://localhost:3000`). Em ciclo *human-in-the-loop*, o modelo interpreta resultados anteriores e propõe ferramenta e parâmetros em JSON, dependendo de decisão explícita do grupo (`s/n/m/q`) validada pelo guard de escopo `check_scope()`.

As três frentes investigadas produziram resultados tecnicamente distintos e sustentados por registros completos (31 entradas distribuídas em 5 sessões supervisionadas v2):
1. **Reconhecimento:** confirmada exposição sem autenticação de `/metrics` (`26.394 B`), `/robots.txt`, listagem `/ftp` e `/api-docs/`, enquanto o filtro SHA-256 eliminou `30` fallbacks SPA e o guard bloqueou uma tentativa externa para `http://google.com/`.
2. **Autenticação:** duas execuções independentes após restauração do container comprovaram contorno por SQL Injection no campo `email` de `POST /rest/user/login` (`401 → 200`, emitindo JWT administrativo para `admin@juice-sh.op`).
3. **Tratamento de entradas:** XSS refletido não foi confirmado, DOM-based XSS permaneceu fora do alcance HTTP sem navegador, e um payload com aspas simples disparou `500 SQLITE_ERROR` expondo `Express ^4.22.1`.

Nas 26 propostas de ferramenta das 5 sessões supervisionadas v2, **12 propostas (46,2%)** exigiram modificação (`5`), rejeição (`6`) ou bloqueio pelo guard (`1`), evidenciando o papel indispensável da supervisão humana.

---

## 1. Arquitetura do Laboratório e do Agente Supervisionado

Todos os experimentos foram conduzidos exclusivamente em interface de *loopback* no kit `kit08` (Ubuntu 22.04.5 LTS), sem comunicação com serviços externos ou equipamentos de outros grupos. A restauração para um estado conhecido antes de cada bateria ocorre via `docker restart juice-shop` (ou recriação do container). Instruções completas de instalação e reprodução estão em [`README.md`](README.md).

| Componente | Especificação Verificada no Kit `kit08` | Papel Arquitetural e Controles |
|---|---|---|
| **Alvo controlado** | OWASP Juice Shop (`bkimminich/juice-shop` em Docker), porta `3000` local, HTTP `200 OK` | Alvo único isolado; estado restaurado com `docker restart juice-shop` entre testes |
| **LLM local** | Ollama (`http://localhost:11434/api/chat`), `qwen3:4b` (4.0B, GGUF `Q4_K_M`, 2,50 GB) | `format="json"`, `think=False`, `temperature=0.25`, `num_predict=700`, `num_ctx=8192`, janela `history[-16:]` |
| **Agente (`agent.py`)** | Python 3.10.12 (`requests>=2.25.0`), teto de `10` ações executadas / `20` ciclos | Recebe objetivo aberto, exige decisão (`s/n/m/q`), coleta `operator_note` e salva JSON incremental em `logs/` |
| **`nmap_scan`** | Nmap 7.80 via `subprocess.run` sem shell (timeout 120 s) | Restrito a `localhost`/`127.0.0.1`, porta estrita `3000` e whitelist de flags (`-sV -sT -Pn -n -F -T3 -T4 --open`) |
| **`http_request`** | `requests.request` (timeout 30 s, `allow_redirects=False`, corte de corpo em 5.000 chars) | Restrito a `http://localhost:3000` / `127.0.0.1:3000` sem credenciais; emite aviso ao detectar fragmentos `#` |
| **`dir_bruteforce`** | Wordlist padrão de 62 rotas (teto 200); bloqueia `://`, `@`, `..`, `?`, `#` e espaços | Calcula SHA-256 do fallback `index.html` da SPA Angular (`9.984 B`) para filtrar falsos positivos |
| **Validação unitária** | `python3 test_scope.py` executado antes das sessões avaliadas | `OK: 6 permitidos, 24 bloqueados, 6 casos de parse` |

Cada passo é salvo incrementalmente por `InvestigationLogger` nos 6 campos exigidos pela Seção 5 do roteiro: `action_proposed`/`reasoning`, `tool`/`proposed_parameters`/`parameters`, `authorization_decision`/`rejection_reason`, `result`, `llm_interpretation` e `operator_note`.

---

## 2. Estratégia e Planejamento de Testes

Seguindo a Seção 3 do roteiro, o grupo definiu primeiro toda a estratégia **sem apoio do LLM** em [`plano_de_testes.md`](plano_de_testes.md) (Seção 4), cobrindo três frentes: reconhecimento/enumeração, autenticação/autorização e tratamento de entradas. As sessões encerram por `action="DONE"` validado, comando `q`/`Ctrl+C`, ou limite de 10 ações executadas; a flag de depuração `--auto` não foi utilizada em nenhuma investigação avaliada.

### 2.1 Revisão do Planejamento pelo LLM Local (`qwen3:4b`)

Submetida a Seção 4 de [`plano_de_testes.md`](plano_de_testes.md) ao `qwen3:4b` ([`logs/revisao_plano_llm_20261124_210227.json`](logs/revisao_plano_llm_20261124_210227.json), `67,92 s`, `1.562` tokens de entrada e `650` gerados), a resposta truncou no último item de `tratamento_de_entradas` (`response_parsed: null`), evidenciando limite de orçamento estruturado do modelo 4B. As sugestões legíveis foram decididas tecnicamente:

| Investigação | Sugestão / alerta do `qwen3:4b` | Decisão do grupo | Justificativa técnica |
|---|---|---|---|
| 1. Reconhecimento | Testar endpoints de métricas/saúde, inspecionar headers e alertar sobre falsos positivos `200 OK` da SPA | **Aceita** | Reforçou prioridade em `/metrics` e filtro SHA-256 contra `index.html` (`9.984 B`) no `dir_bruteforce()`. |
| 1. Reconhecimento | Buscar arquivos genéricos como `config.json` e `app.js` no brute force | **Modificada** | Mantida a wordlist curada de 62 rotas voltadas ao Juice Shop, evitando desperdício do teto de 200 itens. |
| 2. Autenticação | Inspecionar propriedades do JWT emitido (papel, assinatura, expiração) e tokens/cookies expostos | **Aceita** | Incluída leitura das claims no JSON de login (com redação `[REDACTED_JWT]` nas cópias públicas). |
| 2. Autenticação | Realizar ataques de força bruta de senhas comuns em `/rest/user/login` | **Rejeitada** | Desvia da hipótese de SQLi e esgotaria o limite supervisionado de 10 ações com tráfego ruidoso. |
| 2. Autenticação | Tratar retornos `401`/`403` como possíveis falsos positivos de controle de acesso | **Modificada** | Adotado `401 Invalid email or password.` como baseline de controle para comprovar a transição `401 → 200`. |
| 3. Entradas | Testar SQLi e caracteres especiais em query strings (`?q=...`) de rotas não autenticadas | **Aceita** | Confirmou `GET /rest/products/search?q=...` como alvo read-only principal para payloads SQLi/HTML. |
| 3. Entradas | Testar SQLi em comentários/descrições persistentes (item final truncado na resposta) | **Rejeitada** | Rotas como `POST /api/Feedbacks` exigem CAPTCHA e alteram estado persistente; priorizada a API de busca. |

---

## 3. Resultados das Investigações

### 3.1 Investigação 1 — Reconhecimento e Enumeração (`recon`)

**Registro completo:** [`logs/reconhecimento_enumeracao_20261124_113950.json`](logs/reconhecimento_enumeracao_20261124_113950.json) (10 registros: 6 `approved`, 1 `modified`, 1 `rejected`, 1 `blocked`, 1 `DONE`).

1. **Hipótese inicial:** o Juice Shop local (`http://localhost:3000`) expõe serviços, arquivos informativos ou APIs REST sem autenticação que revelam detalhes da arquitetura e da superfície de ataque.
2. **Estratégia proposta pelo grupo:** validar porta `3000` via `nmap_scan`, inspecionar headers e HTML de `GET /`, enumerar rotas com `dir_bruteforce` (com filtro SPA SHA-256) e inspecionar individualmente os endpoints críticos via `http_request`.
3. **Contribuição do agente:** o `qwen3:4b` encadeou corretamente a sequência tática (`nmap_scan → GET / → dir_bruteforce → /metrics → /robots.txt → /ftp → /api-docs`), aproveitando os retornos e as notas do operador no `reasoning`. Entretanto, no passo `#03` alucinou um arquivo inexistente (`"owasp_juice_shop_wordlist.txt"`), no passo `#09` não ajustou o `301` de `/api-docs` e manteve `llm_interpretation` congelado na porta `3000` a partir do passo `#03`.
4. **Execução e evidências obtidas:**
   - `#01` `nmap_scan` (`approved`): `3000/tcp open`; fingerprint HTTP `200 OK` (`9.984 B`), título *OWASP Juice Shop* e header `X-Recruiting: /#/jobs`.
   - `#02` `GET /` (`approved`): HTTP `200 OK` (`text/html`, `9.984 B`), confirmando SPA Angular.
   - `#03` `dir_bruteforce` com `wordlist: "owasp_juice_shop_wordlist.txt"` (`rejected`): rejeitado pelo operador (`n`).
   - `#04` `dir_bruteforce` padrão (`approved`): **62 rotas testadas → 30 fallbacks SPA (`9.984 B`) filtrados por SHA-256 → 23 endpoints reais** (`15` HTTP `200`, `2` HTTP `301`, `6` HTTP `401`, e `9` rotas descartadas `>= 400`).
   - `#05` `GET /metrics` (`approved`): HTTP `200 OK` (`26.394 B`, `text/plain`) sem autenticação, expondo métricas Prometheus internas (CPU, memória RSS `245 MB`, tempos de startup e contadores HTTP).
   - `#06` Teste controlado do guard via `m` → `GET http://google.com/` (`blocked`): bloqueado por `check_scope()` (`URL fora do escopo`).
   - `#07` `GET /robots.txt` (`approved`): HTTP `200 OK` (`28 B`), `User-agent: *` / `Disallow: /ftp`.
   - `#08` `GET /ftp` (`approved`): HTTP `200 OK` (`11.308 B`, `text/html`), `<title>listing directory /ftp</title>` pública via HTTP.
   - `#09` `GET /api-docs` → modificado para `GET /api-docs/` (`modified`): HTTP `200 OK` (`3.106 B`), `<title>Swagger UI</title>` acessível sem autenticação.
   - `#10` `DONE` (após 1 timeout de 180 s no Ollama recuperado na 2ª tentativa): hipótese confirmada pelo modelo e validada com ressalvas pelo operador.
5. **Intervenção humana:** rejeição `n` da wordlist fictícia (`#03`), teste deliberado do guard com `http://google.com/` (`#06`), modificação `m` de `/api-docs` para `/api-docs/` superando `301` (`#09`), notas direcionais e registro crítico do congelamento de `llm_interpretation`.
6. **Conclusão e limitações:** **hipótese confirmada** por evidência direta em `/metrics`, `/robots.txt`, `/ftp` e `/api-docs/`, além de rotas como `/api/Challenges` (`69.056 B`) e `/encryptionkeys` (`7.951 B`). **Limitações:** 6 rotas `401` (`/api/Users`, `/rest/basket`, `/api/Complaints`, `/api/SecurityAnswers`, `/api/Cards`, `/api/Addresss`) permaneceram protegidas e arquivos internos de `/ftp` não foram baixados.

---

### 3.2 Investigação 2 — Mecanismos de Autenticação e Autorização (`sqli`)

**Registros completos (2 sessões pós-restart):** Execução 2A em [`logs/autenticacao_20261124_211752.json`](logs/autenticacao_20261124_211752.json) (6 registros, JWT redigido) e Replicação 2B em [`logs/sqli_20261124_220316.json`](logs/sqli_20261124_220316.json) (7 registros, JWT redigido).

1. **Hipótese inicial:** `POST /rest/user/login` concatena parâmetros sem sanitização no SQLite, permitindo contornar a autenticação no campo `email` sem conhecer a senha e obter JWT administrativo.
2. **Estratégia proposta pelo grupo:** estabelecer baseline com credenciais inválidas (`401`), testar payloads SQLi no campo `email`, comparar a transição de status e inspecionar claims emitidos sem alegar validações não executadas.
3. **Contribuição do agente:** direcionado ao endpoint correto, o `qwen3:4b` interpretou o `401` inicial e formulou autonomamente dois payloads SQLi eficazes (`npipe@example.com' OR 1=1 --` em 2A e `a' OR 1=1--` em 2B), identificando a conta `admin@juice-sh.op`. Em contrapartida, insistiu em `GET /login` (rota SPA), sugeriu a credencial fictícia `npipe@example.com`, usou a chave errada `"username"` em JSON stringificado (2B `#03`) e entrou em loop propondo repetir ações já executadas.
4. **Execução e evidências obtidas:**
   - **Baseline (2A `#03` e 2B `#03`, ambos `modified`):** `POST /rest/user/login` com `{"email": "invalid@example.com", "password": "invalid"}` → HTTP `401` (`26 B`, `Invalid email or password.`).
   - **Desvio intermediário (2A `#04`, `approved`):** `npipe@example.com` / `npipe` → HTTP `401` (`26 B`).
   - **Bypass 2A (`#05`, `approved`):** `email: "npipe@example.com' OR 1=1 --"`, `password: "npipe"` → **HTTP `200 OK`** (`application/json`, `784 B`), emitindo JWT RS256 (`[REDACTED_JWT]`) com `umail: "admin@juice-sh.op"`, `bid: 1` e claim `role: "admin"`.
   - **Bypass 2B (`#05`, `approved`):** `email: "a' OR 1=1--"`, `password: "invalid"` → **HTTP `200 OK`** (`784 B`), `authentication.token` (`[REDACTED_JWT]`), `bid: 1`, `umail: "admin@juice-sh.op"`.
   - **Repetições bloqueadas em 2B:** 2× `nmap_scan` (`#01–02`), repetição do baseline `401` (`#04`) e repetição do payload SQLi (`#06`), todas rejeitadas via `n`.
5. **Intervenção humana:** correção de `GET /login` e `"username"` via `m`, 4 rejeições em 6 propostas na 2B para conter loops, ressalva final delimitando o escopo provado e redação do JWT (`[REDACTED_JWT]`) nas cópias públicas.
6. **Conclusão e limitações:** **hipótese de bypass de autenticação por SQL Injection confirmada de forma reprodutível** em duas sessões independentes (`401 → 200` com JWT administrativo sem senha válida). **Limitação explícita:** nenhuma requisição autenticada foi feita contra rotas protegidas (ex.: `/api/Users` ou `/rest/basket`); portanto, o acesso pós-autenticação a recursos restritos permanece não demonstrado.

---

### 3.3 Investigação 3 — Tratamento de Entradas, Requisições e Acesso a Recursos (`xss`)

**Registros completos (2 sessões pós-restart):** Execução 3A em [`logs/tratamento_de_entradas_20261124_212632.json`](logs/tratamento_de_entradas_20261124_212632.json) (5 registros) e Replicação 3B em [`logs/xss_20261124_220720.json`](logs/xss_20261124_220720.json) (3 registros), contrastados com a fronteira HTTP observada em [`logs/v1_auto_approve/cross_site_scripting_20261119_100055.json`](logs/v1_auto_approve/cross_site_scripting_20261119_100055.json).

1. **Hipótese inicial:** parâmetros de consulta e payloads enviados a APIs de busca/feedback não recebem sanitização ou parametrização adequada, gerando erros no backend ou reflexão insegura em HTTP (ciente da ausência de navegador).
2. **Estratégia proposta pelo grupo:** coletar baseline em `GET /rest/products/search?q=apple` (`200 JSON`), enviar variações com aspas simples e tags HTML em `q`, comparar respostas e distinguir erros SQLite de DOM-based XSS.
3. **Contribuição do agente:** após redirecionamento para `/rest/products/search`, o modelo propôs payloads SQL-like e HTML progressivos e reconheceu na 3B o erro `SQLITE_ERROR: near "XSS"` no retorno `500`. Porém, cometeu três falhas: (a) em 3A `#02`, contaminado pelo *few-shot* do prompt, afirmou falsamente que `GET /` retornara `404`; (b) em 3B `#02`, confundiu a âncora estática `<a href="/#recycle">` da descrição de *Apple Pomace* com possível vetor XSS; e (c) saltou para conclusões extremas opostas (*"properly sanitizes"* em 3A vs. *"SQL injection"* confirmado em 3B).
4. **Execução e evidências obtidas:**
   - **Baseline (3A `#02` e 3B `#01`, ambos `modified` de `GET /api` e `GET /`):** `GET /rest/products/search?q=apple` → HTTP `200 OK` (`application/json`, `1.617 B`, 3 produtos).
   - **3A `#03` (`approved`):** `q=apple%27%27%20OR%201%3D1` (aspas simples dobradas `''`, escape válido de literal em SQLite) → HTTP `200 OK` (`{"status":"success","data":[]}`, `30 B`).
   - **3A `#04` (`approved`):** `q=apple%3Cscript%3Ealert(1)%3C/script%3E` (sem aspas simples) → HTTP `200 OK` (`{"status":"success","data":[]}`, `30 B`, sem reflexão HTML).
   - **3B `#02` (`approved`):** `q=<script>alert('XSS')</script>` (aspas simples não escapadas em `'XSS'`) → **HTTP `500 Internal Server Error`** (`text/html`, `978 B`), `<title>Error: SQLITE_ERROR: near &quot;XSS&quot;: syntax error</title>` e banner `OWASP Juice Shop (Express ^4.22.1)`.
   - **Referências históricas v1 (`#04` e `#05–06`):** `POST /api/Feedbacks` sem CAPTCHA retornou `500` (`WHERE parameter "captchaId" has invalid "undefined" value`, vazando stack trace Sequelize/SQLite), e `GET /#/track-result?id=<script>...` retornou apenas o `index.html` estático (`9.984 B`), pois fragmentos `#` não são enviados ao servidor HTTP (RFC 3986).
5. **Intervenção humana:** edição via `m` das rotas genéricas iniciais (`/api` e `/`) para `/rest/products/search?q=apple` e calibração rigorosa das duas conclusões finais (recusando tanto "sanitização correta" em 3A quanto "SQLi confirmado" a partir de um único 500 em 3B).
6. **Conclusão e limitações:** **XSS refletido não confirmado** (nenhuma marcação executável refletida no corpo HTTP); **DOM-based XSS inconclusivo** pela ausência de navegador/execução JS; **achado parcial de backend em 3B**, onde as aspas simples de `'XSS'` quebraram a string SQL concatenada (`500 SQLITE_ERROR` + vazamento de `Express ^4.22.1`), sem prova completa de extração SQLi; `POST /api/Feedbacks` não integrou a bateria final v2.

---

## 4. Análise Crítica da Utilização da IA

### 4.1 Avaliação dos 7 Critérios do Roteiro

- **Sugestões tecnicamente adequadas:** sequência `nmap → GET / → dir_bruteforce → /metrics → /robots.txt → /ftp` em `recon`; formulação de `' OR 1=1 --` após `401` em `autenticacao`; identificação de `SQLITE_ERROR: near "XSS"` em `xss`.
- **Coerência na seleção de ferramentas:** alternou corretamente `nmap_scan`, `dir_bruteforce` e `http_request`, mas confundiu rotas SPA com APIs (`GET /login`, `/#/track-result`) e sugeriu arquivo externo inexistente em `dir_bruteforce`.
- **Influência dos resultados anteriores:** parcial — `X-Recruiting`, `Disallow: /ftp` e `401` orientaram passos seguintes, mas em `sqli_20261124_220316.json` o modelo ignorou rejeições e o histórico recente, repetindo ações já concluídas.
- **Interpretações incorretas / conclusões sem evidência:** alucinação de XSS em `/#/track-result` (v1), falso positivo SPA `/private` (`103905.json`), afirmação falsa de `404` em `GET /` (`212632.json #02`) e conclusões absolutas opostas entre `212632.json` e `220720.json`.
- **Ações repetitivas ou inadequadas:** `GET /metrics` duplicado (`103905.json #04–05`), tool inexistente `"name"` (`103905.json #07`), 2× `nmap_scan` rejeitados + repetições de baseline e SQLi (`220316.json`), e envio do payload `"apple; --"` no `body` de um `GET` ([`logs/tratamento_de_entradas_20261124_212616.json`](logs/tratamento_de_entradas_20261124_212616.json), passo `#03`).
- **Necessidade de intervenção humana:** nas **26 propostas de ferramenta** das 5 sessões supervisionadas v2, **14 foram aprovadas (53,8%)**, **5 modificadas via `m` (19,2%)**, **6 rejeitadas via `n` (23,1%)** e **1 bloqueada por `check_scope()` (3,8%)** — totalizando **12/26 (46,2%)** de correção humana ou bloqueio.
- **Limitações do modelo e integração:** `qwen3:4b` (`4B Q4_K_M`) congela `llm_interpretation` (`113950`, `220316`), trunca JSON longo (`210227`, 650 tokens) e sofreu timeout de `180 s` (`113950 #10`); sem navegador headless, o agente HTTP não testa DOM XSS.

### 4.2 Exemplos Concretos de Limitação, Erro e Correção

1. **Esgotamento de tokens, placeholder `"tool": "name"` e JSON truncado (`103905.json` e `210227.json`):** em execuções iniciais, `<think>` consumia o orçamento antes do JSON; em `103905 #07`, o modelo copiou o placeholder literal `"tool": "name"` com `temperature=0.7`, e em `210227` truncou a revisão em `650` tokens. **Mitigação:** `think=False`, `format="json"`, `temperature=0.25`, `num_ctx=8192`, remoção de placeholders literais do `SYSTEM_PROMPT` e parser tolerante validado em [`test_scope.py`](test_scope.py).
2. **Falsos positivos de SPA e erro de protocolo em fragmentos `#` (`103905.json` e `v1_auto_approve`):** rotas inexistentes respondiam `200 OK` (`9.984 B`), levando o modelo a interpretar `/private` como área sensível; na v1, `/#/track-result` gerou falsa afirmação de XSS refletido. **Mitigação:** baseline SHA-256 em `dir_bruteforce()` (eliminou `30/62` falsos positivos em `113950.json`) e alerta explícito para URLs com `#` em `http_request()`.
3. **Erros sintáticos de API, loops e saltos conclusivos (`212616.json`, `220316.json`, `220720.json`):** envio de payload no `body` de um `GET` (`212616 #03`), repetições após rejeições (`220316`) e salto de erro `500` para SQLi confirmado (`220720`). **Mitigação:** edição (`m`), bloqueio de repetições (`n`) e delimitação das conclusões via `operator_note`.

### 4.3 Comparação: Estratégia Inicial do Grupo vs. Decisões do Agente

| Frente | Estratégia inicial do grupo | Comportamento observado no agente | Balanço crítico |
|---|---|---|---|
| Reconhecimento | Nmap `:3000`, headers, brute force com filtro SPA e inspeção seletiva | Encadeou descoberta, mas alucinou wordlist, falhou no `301` e congelou `llm_interpretation` | Acelerou triagem de `/metrics` e `/ftp`; dependeu de filtro SHA-256 e ajuste `/api-docs/` |
| Autenticação | Baseline `401`, SQLi em `email` e verificação estrita do escopo do JWT | Propôs `GET /login` e chave `username`, mas gerou SQLi válido e leu o JWT admin | Útil para formular payloads pós-baseline; exigiu 4 rejeições em 2B para não repetir passos |
| Entradas | Baseline em `/rest/products/search`, separando API backend de DOM XSS | Detectou `SQLITE_ERROR` em `220720`, mas confundiu `<a href>` estático e generalizou extremos | Critério do grupo evitou declarar tanto sanitização total quanto XSS/SQLi sem prova |

---

## 5. Conclusões

- **Laboratório isolado e reproduzível:** testes no `kit08` mantidos estritamente em `localhost:3000`, com restauração via container e guard `check_scope()` validado em testes unitários (`6/24/6`) e em execução real (bloqueio de `http://google.com/`).
- **Evidências consistentes nas três frentes:** o reconhecimento confirmou exposição sem autenticação de `/metrics`, `/robots.txt`, `/ftp` e `/api-docs/`; a autenticação confirmou bypass SQLi com emissão de JWT administrativo; e a busca descartou XSS refletido, expôs erro `500 SQLITE_ERROR` sob aspas simples e manteve DOM-based XSS inconclusivo sem navegador.
- **Papel e limites da IA local:** o `qwen3:4b` contribuiu na seleção de ferramentas e formulação de payloads, mas apresentou repetições, confusão SPA/API e conclusões sem evidência suficiente; a supervisão humana (`46,2%` de intervenção/bloqueio nas propostas v2) mostrou-se indispensável para a validade técnica e segurança dos testes.
