# Descrição

Scripts utilizados na Talk `Automatizando coletas de CTI e potêncializando com IA`, que foi feita na **Bsides São Paulo**, em 2025.

Nesta palestra, apresento como potencializar operações de Threat Intelligence (CTI) através da automação e inteligência artificial, utilizando o MCP (Malware Configuration Parser) como uma peça-chave na coleta e análise de informações sobre ameaças cibernéticas.

Demonstro, na prática, como automatizar fluxos de coleta de indicadores e configurações maliciosas, integrando fontes como MISP, relatórios técnicos e OSINT, reduzindo o esforço manual e acelerando o ciclo de inteligência. Além disso, mostro como aplicar recursos de IA para enriquecer os dados coletados, identificar padrões, cruzar informações e gerar insights que elevam a maturidade da CTI.

Ao final, os participantes aprendem a montar pipelines automatizados e inteligentes, que ajudam a transformar grandes volumes de dados brutos em inteligência acionável, otimizando a resposta a ameaças emergentes.

## Como utilizar

Dentro de cada pasta, como por exemplo `security`, execute as seguintes linhas de comando.

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

```

Configure o MCP no seu char prefeiro como `Cursor` ou `Claude`.

```
{
  "mcpServers": {
    "threat_intelligence_mcp": {
      "command": "/Library/Frameworks/Python.framework/Versions/3.11/bin/uv",
      "args": [
        "--directory",
        "/Users/root/Developer/MCP/security",
        "run",
        "main.py"
      ],
      "env": {
        "MISP_URL": "https://localhost",
        "MISP_KEY": "",
        "URLSCANIO_API": "",
        "VT_API_KEY": "",
        "ABUSEIPDB_API": ""
      }
    },

    "osint_mcp": {
      "command": "/Library/Frameworks/Python.framework/Versions/3.11/bin/uv",
      "args": [
        "--directory",
        "/Users/root/Developer/MCP/sherlockeye",
        "run",
        "main.py"
      ],
      "env": {
        "SHERLOCK_EYE_API_KEY": ""
      }
    },

    "orkl": {
      "command": "/Library/Frameworks/Python.framework/Versions/3.11/bin/uv",
      "args": [
        "--directory",
        "/Users/root/Developer/MCP/orkl",
        "run",
        "main.py"
      ]
    }
  }
}
```