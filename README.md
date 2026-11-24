# Agente Supervisionado de Segurança — Tecnologias Hackers

## Descrição

Agente de segurança supervisionado que integra um modelo de linguagem local (`qwen3:4b` via Ollama) a ferramentas de investigação de rede e HTTP para realizar testes controlados sobre o **OWASP Juice Shop**.

Desenvolvido para a Avaliação Final da disciplina **Tecnologias Hackers** (Insper).

## Arquitetura e Topologia do Laboratório

Nos testes executados no kit `kit08` (Ubuntu 22.04.5), o Juice Shop roda em container Docker local na porta `3000` (`http://localhost:3000`), enquanto o Ollama (`localhost:11434`), o `nmap` e o agente (`agent.py`) executam no mesmo ambiente em rede loopback — mantendo todo o tráfego isolado e estritamente local (sem acesso a serviços externos ou kits de outros grupos).

```
+-------------------+     +------------------+     +-------------------+
|  Operador Humano  |<--->|     agent.py     |<--->|   Ollama (LLM)    |
|   (supervisão)    |     |  (orquestrador)  |     |     qwen3:4b      |
+-------------------+     +--------+---------+     +-------------------+
                                   |
                    +--------------+--------------+
                    |              |              |
             +------+-----+ +------+-----+ +------+--------+
             | nmap_scan  | | http_req   | | dir_brute     |
             +------------+ +------------+ +---------------+
                    |              |              |
                    +--------------+--------------+
                                   |
                          +--------+--------+
                          |  OWASP Juice    |
                          |  Shop (Docker)  |
                          |  localhost:3000 |
                          +-----------------+
```

## Pré-requisitos

- Ubuntu Linux 22.04+ (ou Kali Linux no kit de laboratório)
- Python 3.10+
- Docker
- Ollama (`qwen3:4b`)
- `nmap`

## Instalação

### 1. Instalar dependências do sistema

```bash
sudo apt-get update
sudo apt-get install -y nmap curl docker.io python3-pip
```

### 2. Instalar Ollama e baixar o modelo local

```bash
curl -fsSL https://ollama.com/install.sh | sudo bash
sudo systemctl start ollama
ollama pull qwen3:4b
```

### 3. Iniciar o OWASP Juice Shop

```bash
docker run -d --name juice-shop -p 3000:3000 --restart unless-stopped bkimminich/juice-shop
```

*(Caso o usuário não pertença ao grupo `docker`, utilize `sudo docker ...`.)*

Verificar se está respondendo:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3000
# Deve retornar 200
```

### 4. Instalar dependências Python

```bash
pip3 install -r requirements.txt
```

## Uso

### Executar uma investigação (modo supervisionado por padrão)

```bash
python3 agent.py recon          # Reconhecimento e enumeração
python3 agent.py sqli           # Autenticação e autorização
python3 agent.py xss            # Tratamento de entradas
python3 agent.py custom "objetivo livre definido pelo operador"
```

Os objetivos definem apenas a hipótese e o escopo; o agente decide os próximos passos com base nas respostas recebidas e na supervisão do grupo.

Em cada proposta do modelo, o operador deve escolher explicitamente:
- `s` — Aprovar e executar
- `n` — Rejeitar e informar o motivo (enviado ao LLM para propor alternativa)
- `m` — Modificar parâmetros via JSON editado (Enter vazio cancela; JSON inválido solicita correção)
- `q` — Encerrar a investigação registrando o motivo

Após cada execução, o operador pode registrar uma **nota sobre o resultado** (`operator_note`), enviada de volta ao LLM e salva no log. Ao final (`DONE` ou limite de 10 ações executadas), o operador registra sua avaliação da conclusão.

> **Aviso:** `--auto` aprova todas as ações sem interação humana e existe apenas para depuração; **não deve ser utilizado** nas investigações avaliadas.

### Limites do agente (guard de escopo)

Antes de executar qualquer ferramenta (inclusive após edição manual com `m`), `check_scope()` valida e bloqueia:
- `http_request`: métodos fora de `GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS` ou URLs fora de `http://localhost:3000` / `http://127.0.0.1:3000` (credenciais na URL também são bloqueadas; `allow_redirects=False` impede redirecionamento externo).
- `dir_bruteforce`: `base_url` fora de `http://localhost:3000` / `http://127.0.0.1:3000` (ou com query/fragment) e entradas de `wordlist` contendo `://`, `@`, `..`, `?`, `#`, `//` ou espaços. Além disso, a ferramenta detecta automaticamente a página fallback `200 OK` da SPA Angular para reduzir falsos positivos.
- `nmap_scan`: `target_host` diferente de `localhost`/`127.0.0.1`, `ports` diferente de `3000` e flags fora de `-sV -sT -Pn -n -F -T3 -T4 --open` (bloqueando `--script`, `-iL`, `-o*`, etc.).
- URLs com fragmento `#` em `http_request` geram aviso explícito, pois fragmentos não são enviados ao servidor em requisições HTTP.

Validar localmente antes de rodar experimentos:

```bash
python3 test_scope.py
```

### Registros das execuções (`logs/`)

Cada execução grava incrementalmente um arquivo JSON em `logs/` contendo metadados da investigação e a lista de `entries` com todos os 6 elementos exigidos pelo roteiro:
1. `action_proposed` e `reasoning` (ação proposta pelo agente);
2. `tool`, `proposed_parameters` e `parameters` (ferramenta e parâmetros propostos vs. executados);
3. `authorization_decision` e `rejection_reason` (aprovação, modificação, rejeição ou bloqueio);
4. `result` (resultado produzido pela ferramenta);
5. `llm_interpretation` (interpretação apresentada pelo modelo);
6. `operator_note` (decisão/observação do grupo após analisar o resultado).

## Restauração do Ambiente

Para restaurar o Juice Shop ao estado inicial conhecido entre experimentos:

```bash
docker restart juice-shop
```

Para recriar o container do zero:

```bash
docker rm -f juice-shop
docker run -d --name juice-shop -p 3000:3000 --restart unless-stopped bkimminich/juice-shop
```

## Estrutura do Projeto

```
af-techacker/
  README.md                 # Documentação e instruções de reprodução do laboratório
  requirements.txt          # Dependências Python
  agent.py                  # Agente supervisionado e guard de escopo
  test_scope.py             # Testes unitários do guard de escopo e parser JSON
  plano_de_testes.md        # Planejamento inicial do grupo + revisão com LLM
  relatorio.md              # Relatório técnico (base para exportação em PDF de 4–6 págs)
  logs/                     # Registros JSON das investigações supervisionadas
    v1_auto_approve/        # Execuções preliminares v1 arquivadas para comparação crítica
```

## Ferramentas Integradas

| Ferramenta | Descrição | Interação com o Juice Shop |
|---|---|---|
| `nmap_scan` | Verificação de serviço e banner na porta `3000` | Rede (TCP local) |
| `http_request` | Requisições HTTP sem redirecionamento automático | Direta (API / endpoints) |
| `dir_bruteforce` | Enumeração de rotas/APIs com filtro de fallback SPA | Direta (HTTP) |

## Notas de Segurança

- Todos os testes são executados **exclusivamente** contra a instância local do OWASP Juice Shop (`localhost:3000`).
- Ações fora do escopo são bloqueadas por `check_scope()` e registradas no arquivo de log.
- O OWASP Juice Shop é uma aplicação intencionalmente vulnerável para fins educacionais; nunca utilize este agente contra sistemas externos ou em produção.
