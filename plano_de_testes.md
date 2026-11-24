# Plano de Testes - OWASP Juice Shop

## 1. Escopo

Este plano de testes define as investigacoes de seguranca a serem realizadas contra uma instancia local do OWASP Juice Shop (http://localhost:3000), utilizando um agente supervisionado integrado com LLM local (qwen3:4b via Ollama).

## 2. Objetivo Geral

Avaliar a postura de seguranca do Juice Shop atraves de tres investigacoes distintas, documentando o processo de decisao do agente de IA e a intervencao humana necessaria.

## 3. Ambiente de Testes

| Componente | Detalhes |
|---|---|
| Alvo | OWASP Juice Shop (Docker: bkimminich/juice-shop) |
| Endereco | http://localhost:3000 |
| LLM | qwen3:4b via Ollama (localhost:11434) |
| Ferramentas | nmap, requests (Python), dir_bruteforce customizado |
| SO | Ubuntu Linux |
| Isolamento | Todos os testes sao exclusivamente locais |

## 4. Investigacoes Planejadas

### 4.1 Investigacao 1: Reconhecimento e Enumeracao

**Hipotese**: O Juice Shop expoe servicos e endpoints desnecessarios que podem ser descobertos por atacantes.

**Estrategia**:
1. Executar nmap contra localhost para identificar todas as portas abertas e servicos
2. Realizar forca bruta de diretorios para descobrir endpoints ocultos
3. Acessar endpoints descobertos para avaliar informacoes expostas

**Ferramentas**:
- `nmap_scan`: Varredura de portas e deteccao de servicos
- `dir_bruteforce`: Descoberta de endpoints ocultos
- `http_request`: Acesso e analise de endpoints encontrados

**Evidencias Necessarias**:
- Lista completa de portas abertas e servicos
- Endpoints acessiveis que nao deveriam ser publicos
- Informacoes sensiveis expostas (APIs administrativas, dados de debug, etc.)

**Criterios de Sucesso**:
- Identificar pelo menos 3 endpoints nao obvios
- Encontrar pelo menos 1 endpoint com informacoes sensiveis

### 4.2 Investigacao 2: Bypass de Autenticacao via SQL Injection

**Hipotese**: O formulario de login do Juice Shop e vulneravel a SQL Injection, permitindo bypass de autenticacao.

**Estrategia**:
1. Compreender o mecanismo de login (endpoint, formato de dados)
2. Testar login com credenciais invalidas para observar comportamento normal
3. Testar payloads classicos de SQL Injection no campo de email
4. Verificar se a injecao permite acesso nao autorizado

**Ferramentas**:
- `http_request`: Envio de requisicoes POST com payloads de SQLi

**Payloads Planejados**:
- `' OR 1=1--`
- `' OR '1'='1`
- `admin'--`
- `' UNION SELECT * FROM Users--`

**Evidencias Necessarias**:
- Resposta de erro normal (credenciais invalidas)
- Resposta diferente com payload SQLi (indicando vulnerabilidade)
- Token de autenticacao retornado sem credenciais validas

**Criterios de Sucesso**:
- Demonstrar que SQL Injection e possivel no campo de login
- Obter acesso como administrador sem conhecer a senha

### 4.3 Investigacao 3: Cross-Site Scripting (XSS)

**Hipotese**: Campos de entrada do Juice Shop sao vulneraveis a XSS, permitindo injecao de scripts maliciosos.

**Estrategia**:
1. Identificar campos de entrada (busca, feedback, tracking)
2. Testar payloads XSS basicos nos campos identificados
3. Verificar se os payloads sao refletidos sem sanitizacao
4. Documentar quais campos sao vulneraveis e quais tipos de XSS

**Ferramentas**:
- `http_request`: Envio de payloads XSS via GET e POST

**Payloads Planejados**:
- `<script>alert('xss')</script>`
- `<img src=x onerror=alert('xss')>`
- `<iframe src="javascript:alert('xss')">`
- `<svg onload=alert('xss')>`

**Endpoints Alvo**:
- `/rest/products/search?q=PAYLOAD` (busca de produtos)
- `/api/Feedbacks` (formulario de feedback)
- `/#/track-result?id=PAYLOAD` (rastreamento de pedidos)

**Evidencias Necessarias**:
- Payload XSS refletido sem escapamento na resposta
- Payload armazenado em campo persistente (Stored XSS)

**Criterios de Sucesso**:
- Encontrar pelo menos 1 endpoint vulneravel a XSS
- Demonstrar reflected e/ou stored XSS

## 5. Metodologia do Agente

Para cada investigacao:
1. O objetivo e passado ao agente
2. O LLM analisa o contexto e propoe uma acao
3. A acao e autorizada (modo automatico ou manual)
4. A ferramenta executa e retorna resultados
5. O LLM interpreta os resultados e decide o proximo passo
6. O ciclo continua ate a conclusao ou limite de passos

## 6. Criterios de Parada

- Investigacao concluida: evidencias suficientes coletadas
- Limite de passos atingido (8 passos por investigacao)
- LLM determina que nao ha mais acoes produtivas

## 7. Registro e Documentacao

Todas as acoes sao registradas em JSON com:
- Timestamp
- Acao proposta pelo agente
- Ferramenta e parametros
- Decisao de autorizacao
- Resultado da execucao
- Interpretacao do LLM
