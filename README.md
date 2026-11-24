# Agente Supervisionado de Seguranca - Tecnologias Hackers

## Descricao

Agente de seguranca supervisionado que integra um LLM local (qwen3:4b via Ollama) com ferramentas de seguranca para realizar investigacoes controladas no OWASP Juice Shop.

Desenvolvido como atividade da disciplina **Tecnologias Hackers** do Insper.

## Arquitetura

```
+-------------------+     +------------------+     +-------------------+
|   Operador Humano |<--->|   agent.py       |<--->|  Ollama (LLM)     |
|   (supervisao)    |     |  (orquestrador)  |     |  qwen3:4b         |
+-------------------+     +--------+---------+     +-------------------+
                                   |
                    +--------------+--------------+
                    |              |              |
              +-----+----+  +-----+-----+  +----+--------+
              | nmap_scan |  | http_req  |  | dir_brute   |
              +----------+  +-----------+  +-------------+
                    |              |              |
                    +--------------+--------------+
                                   |
                          +--------+--------+
                          |  OWASP Juice    |
                          |  Shop (Docker)  |
                          |  localhost:3000  |
                          +-----------------+
```

## Pre-requisitos

- Ubuntu Linux (testado em 22.04)
- Python 3.10+
- Docker
- Ollama
- nmap

## Instalacao

### 1. Instalar dependencias do sistema

```bash
sudo apt-get update
sudo apt-get install -y nmap curl docker.io python3-pip
```

### 2. Instalar Ollama e o modelo

```bash
curl -fsSL https://ollama.com/install.sh | sudo bash
sudo systemctl start ollama
ollama pull qwen3:4b
```

### 3. Iniciar o Juice Shop

```bash
sudo docker run -d --name juice-shop -p 3000:3000 --restart unless-stopped bkimminich/juice-shop
```

(`--restart unless-stopped` faz o Juice Shop voltar sozinho depois de reboot do kit.)

Verificar se esta rodando:
```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000
# Deve retornar 200
```

### 4. Instalar dependencias Python

```bash
pip3 install requests
```

## Uso

### Executar uma investigacao (modo supervisionado, padrao)

```bash
python3 agent.py recon          # Reconhecimento e enumeracao
python3 agent.py sqli           # Autenticacao / autorizacao
python3 agent.py xss            # Tratamento de entradas
python3 agent.py custom "objetivo livre definido pelo operador"
```

Os objetivos sao abertos (hipotese + escopo): o modelo decide o caminho a partir dos resultados.

Cada acao proposta pelo LLM requer decisao do operador:
- `s` - Aprovar
- `n` - Rejeitar (o motivo digitado e enviado ao modelo, que propoe alternativa)
- `m` - Modificar parametros (colar JSON editado)
- `q` - Encerrar a investigacao

Depois de cada execucao o operador pode registrar uma **nota sobre o resultado** (enviada ao modelo e gravada no log). Na conclusao, o operador registra se concorda e se ha evidencia.

`--auto` aprova tudo sem perguntar (apenas para depuracao; nao usar nas investigacoes avaliadas).

### Limites do agente (guard de escopo)

Antes de executar qualquer acao (inclusive as modificadas pelo operador), `check_scope()` bloqueia:
- HTTP / dir_bruteforce fora de `http://localhost:3000` ou `http://127.0.0.1:3000`
- nmap com host diferente de `localhost`/`127.0.0.1`, portas invalidas ou flags fora da lista `-sV -sT -Pn -n -F -T3 -T4 --open` (sem `--script`, `-iL`, `-o*`)
- redirects HTTP nao sao seguidos

Teste: `python3 test_scope.py`

### Logs

Um JSON por investigacao em `logs/`, salvo a cada passo. Cada entrada tem: `llm_interpretation` (leitura do modelo sobre o resultado anterior), `action_proposed`, `reasoning`, `tool`, `proposed_parameters`, `parameters` (executados), `authorization_decision` (approved / modified / rejected / blocked), `rejection_reason`, `result` e `operator_note` (decisao do grupo apos ver o resultado).

## Restauracao do Ambiente

Para resetar o Juice Shop ao estado limpo:

```bash
sudo docker restart juice-shop
```

Ou para uma reinstalacao completa:

```bash
sudo docker rm -f juice-shop
sudo docker run -d --name juice-shop -p 3000:3000 --restart unless-stopped bkimminich/juice-shop
```

## Estrutura do Projeto

```
af-techacker/
  README.md                 # Este arquivo
  agent.py                  # Agente supervisionado
  plano_de_testes.md        # Plano de testes
  relatorio.md              # Relatorio tecnico
  logs/                     # Logs das investigacoes (JSON)
```

## Ferramentas Integradas

| Ferramenta | Descricao | Interacao com Juice Shop |
|---|---|---|
| `nmap_scan` | Varredura de portas e servicos | Indireta (rede) |
| `http_request` | Requisicoes HTTP (GET, POST, etc.) | Direta (API/endpoints) |
| `dir_bruteforce` | Descoberta de endpoints ocultos | Direta (HTTP) |

## Notas de Seguranca

- Todos os testes sao realizados EXCLUSIVAMENTE contra a instancia local do Juice Shop
- O agente so executa acoes contra `localhost:3000` (ver "Limites do agente"); acoes fora do escopo sao bloqueadas e registradas
- O Juice Shop e uma aplicacao deliberadamente vulneravel para fins educacionais
- Nenhum teste deve ser executado contra sistemas em producao
