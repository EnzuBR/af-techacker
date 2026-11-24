# Relatorio Tecnico - Agente Supervisionado de Seguranca

## Tecnologias Hackers - Insper

---

## 1. Arquitetura do Laboratorio

### 1.1 Visao Geral

O laboratorio consiste em um ambiente local com os seguintes componentes:

- **OWASP Juice Shop**: Aplicacao web deliberadamente vulneravel, executada em container Docker na porta 3000
- **Ollama + qwen3:4b**: LLM local (modelo quantizado de 4 bilhoes de parametros) para tomada de decisoes do agente
- **agent.py**: Programa Python que orquestra o agente supervisionado, integrando o LLM com ferramentas de seguranca
- **Ferramentas de seguranca**: nmap (varredura de portas), requests/curl (requisicoes HTTP), bruteforce de diretorios

### 1.2 Fluxo de Operacao

```
Operador -> Define Objetivo -> LLM Analisa -> Propoe Acao (JSON)
    -> Operador Autoriza/Rejeita/Modifica -> Ferramenta Executa
    -> Resultado -> LLM Interpreta -> Propoe Proxima Acao -> (ciclo)
```

O agente opera em ciclo iterativo onde:
1. O operador humano define um objetivo de investigacao
2. O LLM (qwen3:4b) analisa o contexto e propoe uma acao em formato JSON
3. O operador pode autorizar, modificar ou rejeitar a proposta
4. Quando autorizada, a ferramenta correspondente executa
5. O resultado e alimentado de volta ao LLM para interpretacao
6. O LLM pode propor uma nova acao ou concluir a investigacao

### 1.3 Ferramentas Integradas

| Ferramenta | Descricao | Tipo de Interacao |
|---|---|---|
| `nmap_scan` | Varredura de portas via nmap | Rede (TCP/UDP) |
| `http_request` | Requisicoes HTTP arbitrarias | Direta (HTTP/HTTPS) |
| `dir_bruteforce` | Forca bruta de endpoints | Direta (HTTP) |

### 1.4 Sistema de Logging

Todas as acoes sao registradas em JSON com: timestamp, acao proposta, ferramenta e parametros, decisao de autorizacao, resultado da execucao e interpretacao do LLM.

---

## 2. Estrategia de Testes

A estrategia segue a metodologia classica de pentest em tres fases:

1. **Reconhecimento**: Mapeamento da superficie de ataque (portas, servicos, endpoints)
2. **Exploracao de Autenticacao**: Teste de SQL Injection no mecanismo de login
3. **Exploracao de Entrada**: Teste de Cross-Site Scripting em campos de entrada

Cada investigacao foi executada com o agente em modo automatico (auto-approve), com limite de 6 passos por investigacao.

---

## 3. Resultados das Investigacoes

### 3.1 Investigacao 1: Reconhecimento e Enumeracao

**Hipotese**: O Juice Shop expoe servicos e endpoints desnecessarios.

**Estrategia do Agente**:
1. Varredura nmap nas portas 1-10000
2. Forca bruta de diretorios
3. Acesso a endpoints sensiveis descobertos

**Resultados**:

*Portas Abertas Descobertas (nmap):*
| Porta | Servico | Versao |
|---|---|---|
| 22 | SSH | OpenSSH 8.9p1 |
| 80 | HTTP | Apache 2.4.52 |
| 631 | IPP | CUPS 2.4 |
| 3000 | HTTP | Juice Shop (Node.js) |
| 3306 | MySQL | MariaDB 10.6.23 |
| 8000 | HTTP | Apache 2.4.52 |

*Endpoints Descobertos (dir_bruteforce):*
O agente descobriu **53 endpoints acessiveis**, incluindo:
- `/admin` (200) - Painel administrativo acessivel sem autenticacao
- `/api/Users`, `/api/Products`, `/api/Feedbacks` - APIs REST expostas
- `/metrics` (200) - Metricas Prometheus com informacoes internas
- `/swagger` (200) - Documentacao da API (Swagger UI)
- `/ftp` - Servidor FTP integrado
- `/rest/admin` - Endpoints administrativos REST
- `/api/Challenges` - Lista de desafios (meta-informacao)

*Achados Importantes*:
- O endpoint `/metrics` expoe metricas internas da aplicacao em formato Prometheus, incluindo contadores de tokens LLM, informacoes de requisicoes HTTP e metricas de sistema
- O endpoint `/admin` retorna a pagina SPA completa, indicando que a protecao de acesso ao painel administrativo depende apenas do frontend
- O endpoint `/swagger` expoe toda a documentacao da API, facilitando o mapeamento de ataques

**Contribuicao do Agente**: O LLM soube priorizar corretamente os endpoints a investigar apos a fase de forca bruta, escolhendo `/admin`, `/metrics` e `/swagger` como alvos de maior interesse - uma decisao razoavel e alinhada com praticas de pentest.

**Conclusao**: A hipotese foi confirmada. O Juice Shop expoe multiplos servicos e endpoints desnecessarios que fornecem informacoes sensiveis a atacantes.

---

### 3.2 Investigacao 2: Bypass de Autenticacao via SQL Injection

**Hipotese**: O formulario de login e vulneravel a SQL Injection.

**Estrategia do Agente**:
1. GET na pagina principal para entender a aplicacao
2. Tentativa de login com credenciais invalidas (baseline)
3. Teste de payloads SQL Injection
4. Analise das respostas

**Resultados**:

| Passo | Acao | Resultado |
|---|---|---|
| 1 | GET / | 200 - Pagina carregada normalmente |
| 2 | POST login (test@test.com / test) | 401 - "Invalid email or password" |
| 3 | POST login (' OR 1=1-- / a) | **200 - Token JWT retornado!** |

*Detalhes do Bypass*:
- Payload utilizado: `' OR 1=1--` no campo email
- O servidor retornou um token JWT de autenticacao valido
- O token decodificado revelou: `email: admin@juice-sh.op`, `role: admin`
- O atacante obteve acesso como **administrador** sem conhecer credenciais

**Contribuicao do Agente**: O LLM seguiu uma progressao logica (entender app -> testar normal -> testar SQLi) e escolheu o payload classico `' OR 1=1--` como primeira tentativa, que foi suficiente para o bypass. A decisao de concluir apos o primeiro sucesso foi correta.

**Intervencao Humana**: Nenhuma intervencao foi necessaria. O agente operou em modo automatico e todas as decisoes foram adequadas.

**Conclusao**: A hipotese foi confirmada. O login do Juice Shop e diretamente vulneravel a SQL Injection, permitindo bypass completo de autenticacao e acesso administrativo.

---

### 3.3 Investigacao 3: Cross-Site Scripting (XSS)

**Hipotese**: Campos de entrada sao vulneraveis a XSS.

**Estrategia do Agente**:
1. Identificar campos de entrada via endpoint de busca
2. Testar payloads XSS no parametro de busca
3. Testar XSS na API de feedback
4. Testar XSS no endpoint de tracking

**Resultados**:

| Passo | Acao | Resultado |
|---|---|---|
| 1 | GET /rest/products/search?q=test | 200 - Busca funcionando, HTML em descricoes |
| 2 | GET search?q=\<script\>alert('xss')\</script\> | 500 - Erro SQLite revelado |
| 3 | GET search?q=\<img onerror=alert('xss')\> | 500 - Erro SQLite revelado |
| 4 | POST /api/Feedbacks com XSS no comment | 500 - Erro de captchaId |
| 5 | GET /#/track-result?id=\<script\> | 200 - Pagina SPA retornada |

*Achados Importantes*:
1. **Erro de SQL exposto**: Os payloads XSS no parametro de busca geraram erros SQLite que sao exibidos na resposta HTTP, revelando a mensagem `SQLITE_ERROR: near "xss": syntax error`. Isso indica que o parametro de busca e passado diretamente para uma query SQL sem sanitizacao, confirmando uma **vulnerabilidade de SQL Injection secundaria** alem do XSS.

2. **Descricoes de produtos com HTML**: O endpoint de busca retorna descricoes de produtos que contem tags HTML (links `<a href>`), indicando que conteudo HTML e renderizado sem escapamento - potencial vetor de **Stored XSS** se um atacante conseguir modificar descricoes.

3. **API de Feedback**: O POST falhou por falta do parametro `captchaId`, nao por sanitizacao do payload XSS. Isso sugere que, com o captcha correto, o payload XSS seria aceito e possivelmente armazenado (Stored XSS).

4. **Endpoint de Tracking**: Retornou a pagina SPA, indicando que o processamento do payload XSS ocorre no lado do cliente (DOM-based XSS), nao verificavel apenas por requisicoes HTTP.

**Contribuicao do Agente**: O LLM demonstrou boa capacidade de adaptacao, testando diferentes payloads e endpoints quando o primeiro falhou. Porem, a interpretacao dos resultados foi limitada - o modelo nao identificou espontaneamente que os erros SQL expostos representam uma vulnerabilidade separada.

**Limitacao do Agente**: O agente baseado em HTTP requests nao consegue verificar DOM-based XSS, que requer execucao de JavaScript no navegador. Esta e uma limitacao fundamental da abordagem de testes via API.

**Conclusao**: A hipotese foi parcialmente confirmada. Embora XSS refletido classico nao tenha sido diretamente demonstrado via API (o payload e processado pelo backend SQL antes de ser refletido), foram encontradas evidencias de:
- Potencial Stored XSS em descricoes de produtos (HTML renderizado)
- Potencial Stored XSS na API de feedback (limitado por captcha, nao por sanitizacao)
- SQL Injection no parametro de busca (descoberta colateral)
- Potencial DOM-based XSS no tracking (nao verificavel por API)

---

## 4. Analise Critica da IA

### 4.1 Quando a IA Ajudou

1. **Priorizacao de alvos**: Na investigacao de reconhecimento, o LLM soube priorizar endpoints sensiveis (/admin, /metrics, /swagger) apos a enumeracao, demonstrando conhecimento sobre padroes comuns de aplicacoes web.

2. **Progressao logica**: Na investigacao de SQLi, o LLM seguiu uma progressao metodologica correta (reconhecer -> baseline -> atacar -> concluir), sem pular etapas.

3. **Selecao de payloads**: O LLM escolheu payloads classicos e eficazes. O `' OR 1=1--` foi suficiente para o bypass na primeira tentativa.

4. **Adaptabilidade**: Na investigacao de XSS, quando o primeiro payload falhou, o LLM adaptou sua abordagem, testando diferentes payloads e endpoints.

### 4.2 Quando a IA Falhou

1. **Interpretacao superficial de erros**: Na investigacao XSS, o LLM nao identificou que os erros SQLite expostos representam uma vulnerabilidade de SQL Injection separada. Um pentester humano teria imediatamente reconhecido isso como uma descoberta significativa.

2. **Incapacidade de testar DOM-based XSS**: O agente nao conseguiu verificar XSS baseado em DOM porque opera apenas via HTTP requests, sem capacidade de executar JavaScript. O LLM nao sinalizou esta limitacao proativamente.

3. **Parametros incorretos em chamadas iniciais**: Em testes iniciais (antes de ajustes), o LLM enviou "localhost:3000" como target_host para nmap (incluindo a porta no hostname), o que causou falha na varredura. Este e um exemplo concreto de erro da IA.

### 4.3 Exemplo Concreto de Limitacao da IA

**Problema com formato de resposta do qwen3:4b**: O modelo qwen3:4b, quando operando sem o modo `format: "json"` forcado, gastava todos os tokens de resposta em "pensamento em voz alta" (chain-of-thought) antes de produzir o JSON solicitado, frequentemente excedendo o limite de tokens sem nunca gerar a resposta estruturada. Isso necessitou:

1. Ativacao do modo `format: "json"` do Ollama para forcar output JSON
2. Desativacao do modo de pensamento (`think: false`) para evitar tokens gastos em raciocinio interno
3. Adicao de exemplos few-shot para guiar o formato de resposta
4. Parser robusto para extrair JSON de respostas mistas (texto + JSON)

Mesmo com essas mitigacoes, o modelo ocasionalmente produzia respostas que necessitavam de parsing tolerante a falhas. Isso demonstra que **modelos pequenos (4B parametros) tem dificuldade significativa em seguir instrucoes de formato estrito**, sendo mais adequados quando o formato de saida e forcado pela infraestrutura (como o modo JSON do Ollama).

### 4.4 Limitacoes Gerais

1. **Dependencia de ferramentas**: O agente so pode descobrir vulnerabilidades que suas ferramentas conseguem detectar. XSS baseado em DOM, por exemplo, esta fora do alcance.

2. **Conhecimento generico**: O LLM usa conhecimento generico sobre vulnerabilidades web, nao sendo capaz de desenvolver novas tecnicas de ataque ou combinar vulnerabilidades de forma criativa.

3. **Profundidade limitada**: O modelo de 4B parametros tem capacidade de raciocinio limitada. Modelos maiores provavelmente teriam identificado a vulnerabilidade SQLi colateral na investigacao de XSS.

4. **Contexto limitado**: O agente trabalha com um historico de conversa limitado para manter o desempenho, podendo perder informacoes relevantes de passos anteriores.

---

## 5. Conclusoes

O agente supervisionado demonstrou ser uma ferramenta util para investigacoes de seguranca basicas, com as seguintes capacidades:

- **Reconhecimento eficaz**: Identificou 53 endpoints e multiplos servicos expostos
- **Exploracao de SQLi**: Bypass de autenticacao em 4 passos, obtendo acesso administrativo
- **Exploracoes de XSS**: Identificacao de vetores potenciais e descoberta colateral de SQLi

Porem, o agente tem limitacoes claras que requerem supervisao humana:
- Interpretacao superficial de resultados complexos
- Incapacidade de testar vulnerabilidades client-side
- Dificuldade do modelo pequeno em seguir instrucoes de formato
- Necessidade de orquestracao cuidadosa para compensar limitacoes do LLM

A supervisao humana continua sendo essencial, nao apenas por questoes eticas e de seguranca, mas porque o agente frequentemente precisa de direcao para explorar caminhos que nao identificaria sozinho.
