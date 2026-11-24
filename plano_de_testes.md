# Plano de Testes — OWASP Juice Shop com Agente Supervisionado

## 1. Escopo

Este documento define o planejamento das investigações de segurança contra a instância local controlada do **OWASP Juice Shop** (`http://localhost:3000`), utilizando o agente supervisionado [`agent.py`](agent.py) integrado ao modelo de linguagem local `qwen3:4b` via Ollama.

Conforme os requisitos da Avaliação Final, todos os testes permanecem estritamente restritos à instância local do Juice Shop, sendo proibido executar ações contra serviços externos ou equipamentos de outros grupos.

## 2. Objetivo Geral

Avaliar de forma controlada três frentes distintas de segurança da aplicação, investigando em quais situações o modelo local contribui na formulação de próximos passos e interpretação de resultados, onde apresenta limitações ou erros, e em quais momentos a intervenção humana é indispensável.

> Uma hipótese rejeitada com base em evidências verificáveis também constitui resultado técnico válido.

## 3. Ambiente de Testes

| Componente | Especificação |
|---|---|
| Alvo | OWASP Juice Shop (`bkimminich/juice-shop` em Docker, `http://localhost:3000`) |
| Modelo local (LLM) | `qwen3:4b` (Q4_K_M) via Ollama (`http://localhost:11434`) |
| Ferramentas integradas | `nmap_scan` (porta `3000`), `http_request`, `dir_bruteforce` (com filtro SPA) |
| Ambiente de execução | Kit Ubuntu 22.04.5 (`kit08`), Python 3.10+, execução estritamente local |
| Restauração de estado | `docker restart juice-shop` (ou recriação do container) antes de cada experimento |

---

## 4. Planejamento Inicial do Grupo (sem apoio do LLM)

Seguindo a Seção 3 do roteiro, esta estratégia inicial foi definida pelo grupo **antes** de consultar o modelo local.

### 4.1 Investigação 1 — Reconhecimento e Enumeração da Aplicação

- **Aspectos da aplicação investigados:** superfície de ataque HTTP em `localhost:3000`, cabeçalhos de resposta, rotas administrativas, arquivos informativos e endpoints REST expostos sem autenticação.
- **Hipótese inicial:** o Juice Shop expõe endpoints, arquivos ou APIs internas acessíveis sem autenticação que revelam informações sensíveis sobre a arquitetura, desafios ou dados da aplicação.
- **Estratégia proposta e ferramentas:**
  1. Confirmar disponibilidade e banner do serviço na porta `3000` com `nmap_scan` (`target_host="localhost"`, `ports="3000"`, `-sV`).
  2. Inspecionar cabeçalhos e HTML inicial com `http_request` (`GET /`).
  3. Enumerar rotas e APIs com `dir_bruteforce`, filtrando o fallback `index.html` da SPA Angular para distinguir rotas reais de rotas falsas retornando `200 OK`.
  4. Consultar individualmente com `http_request` os endpoints não triviais retornados (ex.: `/metrics`, `/ftp`, `/api-docs`, `/robots.txt`, `/api/Challenges`, `/rest/memories`, `/api/SecurityQuestions`) e verificar quais exigem autenticação (`401`/`403`).
- **Evidências necessárias:** saída do `nmap_scan` na porta `3000`; lista de endpoints filtrados por `status_code`, `size` e `content_type`; trechos reais do corpo e cabeçalhos HTTP dos endpoints acessados sem credenciais.

### 4.2 Investigação 2 — Mecanismos de Autenticação e Autorização

- **Aspectos da aplicação investigados:** endpoint de autenticação (`/rest/user/login`), tratamento de erro com credenciais inválidas, resistência a SQL Injection e controle de autorização em endpoints protegidos.
- **Hipótese inicial:** o mecanismo de login não sanitiza adequadamente os parâmetros enviados ao banco SQLite, permitindo contornar a autenticação sem conhecer a senha e acessar recursos restritos com o token obtido.
- **Estratégia proposta e ferramentas:**
  1. Estabelecer baseline funcional via `http_request` (`POST /rest/user/login` com credenciais inválidas, verificando código `401` e mensagem padrão).
  2. Testar variações simples de SQL Injection no campo `email` (ex.: `' OR 1=1--`, `admin@juice-sh.op'--`, `' OR '1'='1'--`) observando diferenças de status HTTP, mensagens de erro SQL ou emissão de token JWT.
  3. Caso um token seja emitido, inspecionar os dados retornados e validar se o token realmente concede acesso a um endpoint autenticado (ex.: `/rest/user/whoami` ou `/api/Users`) via `http_request` com header `Authorization: Bearer ...`.
- **Evidências necessárias:** resposta HTTP da linha de base (`401`); requisição e resposta completa de qualquer payload que altere o comportamento ou retorne JWT; prova de acesso a recurso protegido utilizando o token obtido (ou prova de bloqueio caso a hipótese não se confirme).

### 4.3 Investigação 3 — Tratamento de Entradas, Requisições e Acesso a Recursos

- **Aspectos da aplicação investigados:** tratamento de entradas de usuário em endpoints de API (`GET /rest/products/search?q=...`, `POST /api/Feedbacks`, `GET /rest/track-order/...`) e distinção entre validação/erros de backend versus execução client-side (DOM).
- **Hipótese inicial:** entradas enviadas via parâmetros de consulta e payloads JSON não passam por validação ou escapamento adequado, permitindo identificar injeção no backend ou reflexão insegura nas respostas HTTP (respeitando a fronteira de que o agente não executa JavaScript em navegador).
- **Estratégia proposta e ferramentas:**
  1. Estabelecer baseline em `/rest/products/search?q=apple` com `http_request` (`200 OK`, `application/json`).
  2. Testar caracteres especiais e payloads de injeção/HTML no parâmetro `q` (`<script>...`, `'`, `"`) observando se há reflexão sem escapamento em resposta HTML/JSON ou vazamento de erros SQL/stack traces (`500`).
  3. Investigar o comportamento de `POST /api/Feedbacks` (incluindo obtenção prévia de `/rest/captcha` se necessário) e a consulta direta à API `/rest/track-order/{id}` para testar controle de acesso/tratamento de entrada sem confundir com rotas com fragmento `#` (como `/#/track-result`, que não trafegam em requisições HTTP).
- **Evidências necessárias:** status HTTP, `Content-Type` e corpo das respostas comparando entradas benignas e malformadas; registro explícito da impossibilidade de validar execução real de DOM XSS apenas via `http_request` (sem browser).

---

## 5. Revisão do Planejamento com Apoio do LLM Local (`qwen3:4b`)

*[Seção a ser executada e preenchida na etapa seguinte, submetendo a Seção 4 ao `qwen3:4b` via Ollama para revisar o plano.]*

### 5.1 Prompt utilizado na revisão

> `[Preencher com o prompt enviado ao qwen3:4b após o plano inicial do grupo]`

### 5.2 Decisões do grupo sobre as sugestões do modelo

| Investigação | Sugestão do `qwen3:4b` | Decisão | Justificativa técnica do grupo |
|---|---|---|---|
| Reconhecimento | `[A preencher]` | `[Aceita / Modificada / Rejeitada]` | `[A preencher]` |
| Autenticação | `[A preencher]` | `[Aceita / Modificada / Rejeitada]` | `[A preencher]` |
| Tratamento de entradas | `[A preencher]` | `[Aceita / Modificada / Rejeitada]` | `[A preencher]` |

---

## 6. Metodologia do Agente Supervisionado e Critérios de Parada

Para cada investigação, o agente executa o ciclo interativo:
1. O objetivo aberto (hipótese + escopo) é passado ao `agent.py`.
2. O LLM analisa o histórico recente (até 8 turnos) e propõe uma ação em JSON (`interpretation`, `action`, `tool`, `parameters`, `reasoning`).
3. O operador decide explicitamente: `s` (aprovar), `n` (rejeitar informando o motivo ao LLM), `m` (modificar parâmetros em JSON) ou `q` (encerrar). Entradas inválidas não aprovam ações automaticamente.
4. O guard `check_scope()` valida novamente a ação (mesmo após `m`) contra o escopo estrito de `http://localhost:3000`.
5. Quando autorizada e dentro do escopo, a ferramenta executa e o operador pode registrar uma nota (`operator_note`), que retorna ao modelo junto ao resultado.

**Critérios de parada:**
- O modelo retorna `"action": "DONE"` com conclusão fundamentada em evidências observadas e avaliação final do operador;
- O operador encerra manualmente com `q` (ou `Ctrl+C`);
- Limite de **10 ações executadas** por investigação (com síntese final obrigatória baseada apenas nas evidências já coletadas).

## 7. Esquema de Registro das Execuções

Todos os logs em `logs/<investigacao>_<timestamp>.json` armazenam, para cada passo:
- Ação proposta e justificativa (`action_proposed`, `reasoning`);
- Ferramenta e parâmetros propostos vs. executados (`tool`, `proposed_parameters`, `parameters`);
- Decisão de supervisão ou bloqueio (`authorization_decision`, `rejection_reason`);
- Resultado real da ferramenta (`result`);
- Interpretação do modelo (`llm_interpretation`);
- Análise/decisão do grupo após observar o resultado (`operator_note`).
