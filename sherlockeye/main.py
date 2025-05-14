from mcp.server.fastmcp import FastMCP
import requests
from bs4 import BeautifulSoup
from mcp.types import TextContent
from datetime import datetime
import os
import requests
import time
import json
mcp = FastMCP(
    "osint_mcp",
    instructions="""
        Você é um assistente inteligente que utiliza ferramentas para ajudar o usuário a fazer pesquisas de OSINT.

        Sempre explore o maximo que puder de todos os dados coletados, com o maximo de riqueza possível.
        Faça sugestões de investigações que podem ser feitas com os dados coletados.

        Traga link diretos para os dados coletados. E perfils de usuários que podem ser investigados.
    """,    
)

cache = {
    "content": {},
    "responseId": {},
    "usernames": {},
}



@mcp.tool(
    name="search_email",
    description="""
        [Obtem|resume|extrai] Obtem dados de Email na plataforma sherlockeye de OSINT.

        Abaixo está um JSON contendo dados de vazamentos de informações e perfis públicos relacionados a um determinado e-mail.
        Sua tarefa é:
            Gerar um resumo cronológico detalhado dos vazamentos, incluindo fonte, data, dados expostos e verificação.
            Analisar os dados expostos e inferir possíveis riscos (por exemplo, exposição de senhas, CPF, endereços, redes sociais).
            Criar um perfil da pessoa, inferindo:
            Nome provável
            Serviços e plataformas usadas (ex: Canva, Hurb, Deezer)
            Localização aproximada (com base nos dados e domínios brasileiros)
            Possíveis interesses e hábitos digitais
            Se houver perfis públicos (ex: GitHub), gerar:
            Link direto ao perfil
            Resumo da atividade (repositórios, seguidores, etc)
            Se houver metadados de localização (ex: IP ou localização geográfica), gere links para visualizar em um mapa (Google Maps).
            Nunca execute a tool `get_more_info` sem que o usuário solicite, mesmo que você ache necessário

        Formato da resposta:
            Resumo geral (número de vazamentos, plataformas afetadas, maior risco)
            Detalhamento de cada incidente
            Perfil inferido do usuário
            Analise de possíveis gostos e interesses
            Links úteis (GitHub, possíveis mapas, etc)

        Gere todos os dados na resposta da pergunta, não faça com que eu tenha que solicitar novamente. Sempre me retorne o relatório completo
        Todas as respostas serão em português brasileiro.
    """
)
def search_email(email: str) -> TextContent:
    searchId = None

    response = requests.post(
        "https://api.sherlockeye.io/search",
        headers={
            'Authorization': f"Bearer {os.getenv('SHERLOCK_EYE_API_KEY', '')}",
            'Content-Type': 'application/json'
        },
        json={
            "type": "email",
            "value": email
        }
    )

    if response.status_code in [200, 201]:
        cache["responseId"][email] = response.json()
        time.sleep(1)
        if cache["responseId"][email]['success']:
            searchId = cache["responseId"][email]['searchId']
            if searchId is not None:

                while True:
                    result = requests.get(
                        f'https://api.sherlockeye.io/get/{searchId}',
                        headers={
                            'Authorization': f"Bearer {os.getenv('SHERLOCK_EYE_API_KEY', '')}",
                            'Content-Type': 'application/json'
                        },
                    )

                    if result.status_code in [200, 201]:
                        cache["content"][email] = result.json()

                        if cache["content"][email]['data'] and cache["content"][email]['data']['results']:
                            break

                    time.sleep(1)
    count = 0
    if cache["content"].get(email, None) is not None:
        for user in cache["content"][email]['data']['results'][:]: 
            if user['source'] in ['DeHashed']:
                count += 1

                if count > 10:
                    cache["content"][email]['data']['results'].remove(user)
            else:
                if user.get('additionalFields', None) is not None:
                    for search in user['additionalFields'][:]:
                        if search.get('key', None) == 'image':
                            user['additionalFields'].remove(search)

    return TextContent(
        type="text",
        text=json.dumps({
            "content": cache["content"][email],
            "responseId": cache["responseId"][email]
        }),
    )


@mcp.tool(
    name="get_more_info",
    description="""
        [Obtem|resume|extrai] Obtem dados de Username na plataforma sherlockeye de OSINT.

        Abaixo está um JSON contendo dados de vazamentos de informações e perfis públicos relacionados a um determinado e-mail.
        Sua tarefa é:
            Gerar um resumo cronológico detalhado dos vazamentos, incluindo fonte, data, dados expostos e verificação.
            Analisar os dados expostos e inferir possíveis riscos (por exemplo, exposição de senhas, CPF, endereços, redes sociais).
            Criar um perfil da pessoa, inferindo:
            Nome provável
            Serviços e plataformas usadas (ex: Canva, Hurb, Deezer)
            Localização aproximada (com base nos dados e domínios brasileiros)
            Possíveis interesses e hábitos digitais
            Se houver perfis públicos (ex: GitHub), gerar:
            Link direto ao perfil
            Resumo da atividade (repositórios, seguidores, etc)
            Se houver metadados de localização (ex: IP ou localização geográfica), gere links para visualizar em um mapa (Google Maps).

        Formato da resposta:
            Título: “Relatório de Exposição para [email|username]”
            Resumo geral (número de vazamentos, plataformas afetadas, maior risco)
            Detalhamento de cada incidente
            Perfil inferido do usuário
            Links úteis (GitHub, possíveis mapas, etc)
        Todas as respostas serão em português brasileiro.
    """,
)
def get_more_info(email: str = None, username: str = None) -> TextContent:
    data = None
    uuids = []

    if cache["content"].get(email, None) is not None:
        data = email
    elif cache["content"].get(username, None) is not None:
        data = username

    if data is not None:

        for user in cache["content"][data]['data']['results']:
            if user.get('additionalFields', None) is not None:
                for search in user['additionalFields']:
                    if search.get('key', None) == 'username':

                        response = requests.post(
                            "https://api.sherlockeye.io/search",
                            headers={
                                'Authorization': f"Bearer {os.getenv('SHERLOCK_EYE_API_KEY', '')}",
                                'Content-Type': 'application/json'
                            },
                            json={
                                "type": "username",
                                "value": search['value']
                            }
                        )

                        if response.status_code in [200, 201]:
                            uuids.append(response.json())
  
        if len(uuids) > 5:
            for searchId in uuids[0:5]:
                result = requests.get(
                    f'https://api.sherlockeye.io/get/{searchId["searchId"]}',
                    headers={
                        'Authorization': f"Bearer {os.getenv('SHERLOCK_EYE_API_KEY', '')}",
                        'Content-Type': 'application/json'
                    },
                )

                if result.status_code in [200, 201]:
                    result = result.json()
                    if result['data'] and result['data']['results']:
                        if cache["usernames"].get(data, None) is None:
                            cache["usernames"][data] = [result]

                        elif cache["usernames"].get(data, None) is not None:
                            cache["usernames"][data].append(result)

    return TextContent(
        type="text",
        text=json.dumps({
            "data": cache["content"][data],
            "usernames": cache["usernames"][data]
        }, indent=2),
    )

if __name__ == "__main__":
    mcp.run()