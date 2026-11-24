# Relatório Técnico — Testes de Segurança Supervisionados com LLM Local

**Disciplina:** Tecnologias Hackers — Avaliação Final (Prof. Rodolfo Avelino)  
**Grupo / Kit:** Kit `kit08` — Integrantes: `[Preencher nomes completos]`  
**Data:** `[Preencher após execução final]`  
**Repositório e logs completos:** `https://github.com/EnzuBR/af-techacker` (pasta `logs/`)

---

## 1. Arquitetura do Laboratório e Agente Supervisionado

O ambiente foi montado localmente no kit de laboratório (`kit08`, Ubuntu 22.04.5 LTS) de forma isolada, sem acesso a serviços externos ou máquinas de outros grupos:

- **Alvo:** instância local do **OWASP Juice Shop** (`bkimminich/juice-shop`) em container Docker exposto em `http://localhost:3000`. A restauração entre testes ocorre via `docker restart juice-shop` (ou recriação do container).
- **Modelo de linguagem local:** **`qwen3:4b`** (quantização Q4_K_M) servido via Ollama em `http://localhost:11434/api/chat`, configurado com `format: "json"`, `think: false`, `temperature: 0.25`, `num_predict: 700` e `num_ctx: 8192`.
- **Agente supervisionado (`agent.py`):** orquestrador em Python 3.10 que recebe um objetivo aberto (hipótese + escopo), consulta o modelo com janela de até 8 turnos (`history[-16:]`), exibe a proposta ao operador e exige autorização explícita (`s` aprovar, `n` rejeitar com justificativa enviada ao modelo, `m` modificar parâmetros em JSON, `q` encerrar). Após cada execução, o grupo pode registrar uma nota (`operator_note`) que alimenta o passo seguinte.
- **Ferramentas integradas e limites (`check_scope`):**
  - `nmap_scan`: restrito a `localhost`/`127.0.0.1`, porta estrita `3000` e flags seguras (`-sV -sT -Pn -n -F -T3 -T4 --open`, bloqueando `--script`, `-iL`, `-o*`).
  - `http_request`: restrito a `http://localhost:3000` / `http://127.0.0.1:3000`, `allow_redirects=False` (impede redirecionamentos fora do escopo) e alerta explícito quando há fragmentos `#` na URL.
  - `dir_bruteforce`: restrito a `localhost:3000` com validação de wordlist e detecção automática de baseline da SPA Angular (filtra respostas `200 OK` idênticas ao `index.html` para eliminar falsos positivos).
- **Registro de execuções:** cada investigação salva incrementalmente em `logs/*.json` os 6 campos exigidos: ação proposta, ferramenta e parâmetros (propostos e executados), decisão de autorização/rejeição/bloqueio, resultado bruto truncado de forma segura, interpretação do modelo e nota/decisão do operador.

*(Instruções completas de instalação e reprodução estão em `README.md`.)*

---

## 2. Estratégia e Planejamento de Testes

Seguindo o método exigido, o grupo elaborou primeiro um **plano de testes sem apoio do LLM** em `plano_de_testes.md`, definindo hipóteses, ferramentas e evidências necessárias para três frentes distintas: (1) reconhecimento e enumeração da aplicação, (2) mecanismos de autenticação e autorização, e (3) tratamento de entradas, requisições e acesso a recursos.

### 2.1 Revisão do Planejamento pelo LLM Local (`qwen3:4b`)

*[A preencher após submeter `plano_de_testes.md` (Seção 4) ao `qwen3:4b` e registrar as decisões técnicas do grupo.]*

| Investigação | Sugestão do modelo | Decisão do grupo | Justificativa técnica |
|---|---|---|---|
| 1. Reconhecimento | `[A preencher]` | `[Aceita / Modificada / Rejeitada]` | `[A preencher]` |
| 2. Autenticação | `[A preencher]` | `[Aceita / Modificada / Rejeitada]` | `[A preencher]` |
| 3. Entradas / Recursos | `[A preencher]` | `[Aceita / Modificada / Rejeitada]` | `[A preencher]` |

---

## 3. Resultados das Investigações

*[Nota: Esta seção deverá ser preenchida exclusivamente com as evidências das novas execuções supervisionadas (v2) registradas em `logs/`. Os logs preliminares da v1 (`logs/v1_auto_approve/`) e a execução parcial de 24/11 são referenciados na Seção 4 apenas para análise crítica de falhas.]*

### 3.1 Investigação 1 — Reconhecimento e Enumeração (`recon`)

1. **Hipótese inicial:** `[Confirmar texto de plano_de_testes.md após revisão]`
2. **Estratégia proposta pelo grupo:** `[Resumir estratégia planejada sem IA e ajustes após revisão]`
3. **Contribuição do agente:** `[Quais ações, parâmetros e interpretações o qwen3:4b propôs a partir de cada retorno]`
4. **Execução e evidências obtidas:** `[Listar ações executadas, códigos HTTP/tamanhos reais, endpoints efetivos como /metrics, /ftp, /api-docs, /robots.txt, /api/Challenges e respostas 401 como /api/Users — citando o arquivo de log]`
5. **Intervenção humana:** `[Detalhar aprovações, rejeições (n), modificações (m), testes de escopo e notas do operador]`
6. **Conclusão e limitações:** `[Hipótese confirmada/rejeitada estritamente com base nas evidências + limitações observadas]`

### 3.2 Investigação 2 — Mecanismos de Autenticação e Autorização (`sqli`)

1. **Hipótese inicial:** `[Confirmar texto de plano_de_testes.md após revisão]`
2. **Estratégia proposta pelo grupo:** `[Baseline de login + teste de payloads + validação do token em rota protegida]`
3. **Contribuição do agente:** `[Ações propostas e interpretação das respostas 401/200/500]`
4. **Execução e evidências obtidas:** `[Respostas reais de /rest/user/login e comprovação de autorização/acesso com token se aplicável — citando o log]`
5. **Intervenção humana:** `[Aprovações, rejeições, modificações e notas do operador registradas]`
6. **Conclusão e limitações:** `[O que os dados provam e o que não pôde ser verificado]`

### 3.3 Investigação 3 — Tratamento de Entradas e Acesso a Recursos (`xss`)

1. **Hipótese inicial:** `[Confirmar texto de plano_de_testes.md após revisão]`
2. **Estratégia proposta pelo grupo:** `[Baseline em APIs de busca/feedback/rastreamento e verificação de sanitização ou vazamento de erros]`
3. **Contribuição do agente:** `[Adaptação do modelo diante de respostas 200 JSON e 500 HTML/SQLite]`
4. **Execução e evidências obtidas:** `[Respostas observadas em /rest/products/search, /api/Feedbacks, etc. — distinguindo erro SQLite de XSS refletido e citando o log]`
5. **Intervenção humana:** `[Aprovações, rejeições, modificações e notas do operador registradas]`
6. **Conclusão e limitações:** `[Conclusão sustentada por evidência + fronteira arquitetural: DOM XSS não é verificável sem execução de JavaScript em navegador]`

---

## 4. Análise Crítica da Utilização da IA

### 4.1 Resposta aos Pontos de Análise

- **Sugestões tecnicamente adequadas:** `[Preencher com exemplos dos logs v2 — ex.: escolha de baseline antes de payload em autenticação e priorização de endpoints após enumeração]`
- **Coerência na seleção de ferramentas:** `[Avaliar uso de nmap_scan, dir_bruteforce e http_request conforme o objetivo]`
- **Influência dos resultados anteriores nas decisões seguintes:** `[Demonstrar com passos reais do log se o modelo reagiu a respostas 401/500 ou se ignorou evidências]`
- **Interpretações incorretas ou conclusões sem evidência:** Nas iterações preliminares do projeto foram observadas falhas graves do `qwen3:4b`:
  - *Alucinação de vulnerabilidade:* em `logs/v1_auto_approve/cross_site_scripting_20261119_100055.json` (passo 6), o modelo concluiu que `<script>alert('xss')</script>` foi refletido no HTML de `/#/track-result`, quando a resposta HTTP retornou apenas o `index.html` estático da SPA (fragmentos `#` nem sequer são enviados ao servidor).
  - *Falso positivo de SPA:* na execução supervisionada parcial `logs/reconhecimento_enumeracao_20261124_103905.json` (passo 6), sem filtro de baseline, o modelo interpretou `/private` (`200 OK`, `9984` bytes) como área de dados privados, quando era apenas o fallback SPA.
  - `[Complementar com observações das novas execuções supervisionadas v2]`
- **Ações repetitivas, desnecessárias ou inadequadas:** Em `logs/reconhecimento_enumeracao_20261124_103905.json`, o modelo propôs `GET http://localhost:3000/metrics` duas vezes seguidas (passos 4 e 5) com os mesmos parâmetros, e no passo 7 colapsou para o placeholder literal `"tool": "name"`, gerando ferramenta inexistente. `[Complementar com as execuções finais]`
- **Situações em que a intervenção humana foi necessária:** A supervisão mostrou-se essencial para corrigir parâmetros (`m`), barrar ações redundantes ou fora de foco (`n`), exigir validação real em vez de aceitar conclusões apressadas e orientar o modelo via `operator_note` diante de limitações de protocolo (como rotas `#` de SPA ou erros `500` de SQLite vs. XSS).
- **Limitações do modelo e da integração:** Modelo pequeno (4B) sensível a janela de contexto e instruções ambíguas; ausência de navegador impede confirmar DOM-based XSS; truncamento de respostas longas pode ocultar evidências sem pré-filtragem (motivo pelo qual foi implementado o filtro de fallback SPA e aumento de limites na v2).

### 4.2 Exemplos Concretos de Limitação, Erro e Correção

1. **Esgotamento de tokens e colapso de formato no `qwen3:4b`:**
   - *Problema observado:* sem `format: "json"` e com modo de raciocínio ativo, o `qwen3:4b` consumia o orçamento de geração em `<think>...</think>` sem entregar JSON válido; mesmo após ativar JSON mode, na execução de 24/11 (`reconhecimento_enumeracao_20261124_103905.json`, passo 7) o modelo copiou literalmente o placeholder `"tool": "name"` do prompt de sistema quando `temperature` estava em `0.7`.
   - *Como lidamos:* desabilitamos `think` (`think: false`), forçamos `format: "json"`, removemos placeholders literais ambíguos do `SYSTEM_PROMPT`, reduzimos `temperature` para `0.25`, ampliamos a janela para 8 turnos (`history[-16:]`) e adicionamos parser tolerante com fallback seguro.
2. **Falsos positivos de SPA induzindo o modelo e o operador:**
   - *Problema observado:* o Juice Shop responde `200 OK` (`index.html`, ~9984 bytes) para qualquer rota desconhecida, fazendo o `dir_bruteforce` listar dezenas de rotas fictícias (como `/private`, `/backup`, `/admin`) que, somadas ao corte de lista em 20 itens, ocultavam endpoints reais (`/metrics`, `/ftp`, `/api/Users`) do contexto do modelo.
   - *Como lidamos:* implementamos detecção automática de baseline SPA por hash SHA-256 em `dir_bruteforce()` e ampliamos o limite de itens preservados no resumo enviado ao LLM.
3. `[Adicionar exemplo concreto de intervenção humana (n/m) registrado nos logs v2 finais]`

### 4.3 Comparação: Estratégia Inicial do Grupo vs. Decisões do Agente

| Dimensão | Estratégia inicial do grupo | Comportamento observado no agente | Balanço crítico |
|---|---|---|---|
| Reconhecimento | Enumerar serviço, filtrar rotas SPA e inspecionar APIs reais | `[Preencher após log v2]` | `[Preencher]` |
| Autenticação | Baseline 401, SQLi e verificação de privilégio do token | `[Preencher após log v2]` | `[Preencher]` |
| Entradas / Recursos | Testar APIs backend e separar erro SQL de XSS / DOM | `[Preencher após log v2]` | `[Preencher]` |

---

## 5. Conclusões

*[A finalizar após as três execuções supervisionadas completas, sintetizando com base nas evidências onde o `qwen3:4b` acelerou a investigação, onde induziu a erro e por que o operador humano permaneceu indispensável na condução e validação técnica.]*
