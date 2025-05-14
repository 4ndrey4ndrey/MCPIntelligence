from mcp.server.fastmcp import FastMCP
import requests
from bs4 import BeautifulSoup
from mcp.types import TextContent
import json
from tools.observables import Observables, Malicious, Galaxys, Stix
from tools.misp import Misp



observables = Observables()
malicious = Malicious()
misp = Misp()
galaxys = Galaxys()
stix = Stix()
mcp = FastMCP(
    "threat_intelligence_mcp",
    instructions="""
        Você é um assistente inteligente que utiliza ferramentas para ajudar o usuário.

        Regras importantes:
        1. Sempre que a tool `get_content_from_url` for chamada, **não chame nenhuma outra ferramenta** depois dela, mesmo que pareça necessário.
        3. Sempre que executar a tool `get_content_from_url`, **deve-se dar um resumo** detalhado do que está no site.
        4. Após `get_content_from_url`, **aguarde uma nova mensagem do usuário antes de continuar** qualquer outra ação.
        5. Quando a tool check_malicious_iocs for executada é necessário dar um resumo detalhado das informações coletadas. Antes de executar qualquer outra tool, mesmo que pareça necessário.
        6. Siga rigorosamente as instruções descritas na `description` de cada tool.
        7. Sempre responda em português brasileiro.
    """,    
)

cache = {
    "content": {},
    "iocs": {},
    "malicious": {},
    "misp_event": {},
    "misp": {},
    "matchs": {},
    "title": {},
    "stix": {}
}



@mcp.tool(
    name="get_content_from_url",
    description="""
        [Obtem|resume|extrai] todo o content de uma página web,
        baseado na url fornecida na pergunta pelo usuário.
        Todas as informações coletadas serão armazenadas na cache.
        Se a url já foi coletada, a função retornará o content armazenado na cache.

        Faça um resumo simples com no maximo 500 caracteres.

        Todas as respostas serão em português brasileiro.
    """,
)
def get_content_from_url(url: str) -> TextContent:
    def fetch_content(url):
        try:
            response = requests.get(url, verify=False, timeout=10,
                headers={
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                })
            return response
        except (requests.RequestException, requests.exceptions.InvalidURL) as e:
            print(f"Request error: {e}")
            return None
        
    response = fetch_content(url=url)
    if response and response.status_code in [200, 201, 202, 302, 304]:
        soup = BeautifulSoup(response.content, "lxml")

        title = f"MCP - Threat Intelligence - {soup.title.string}" if soup.title else "MCP - Threat Intelligence"
        cache['title'][url] = title
        for tag in soup(["script", "style"]):
            tag.decompose()
            
        cache["content"][url] = " ".join(soup.stripped_strings)

        return TextContent(
            type="text",
            text=cache["content"][url],
        )

@mcp.tool(
    name="get_iocs_from_content",
    description="""
    [Colete|extrai] os IOCs (Indicador de compromisso) do conteúdo de texto da página web fornecida na pergunta pelo usuário.
    
    Não execute mais tools, faça um resumo detalhado do que foi encontrado e aguarde mais perguntas.
    """,
)


def get_iocs_from_content(url: str) -> TextContent:
    """
    obtem os iocs do content da página web fornecida na pergunta pelo usuário.
    """
    cache['iocs'][url] = observables._iocs(raw=cache["content"][url])
    
    return TextContent(
        type="text",
        text=json.dumps(cache['iocs'][url], indent=2),
    )


@mcp.tool(
    name="check_malicious_iocs",
    description="[Colete|extrai] valida se os IOCs (Indicador de compromisso) coletados são maliciosos.",
)
def check_malicious_iocs(url: str) -> TextContent:
    """
    Classifica os IOCs (Indicador de compromisso) coletados como maliciosos ou não e retorne um resumo
    dos iocs classificados como maliciosos.
    
    Não execute mais tools, faça um resumo detalhado do que foi encontrado e aguarde mais perguntas.

    Todas as respostas serão em português brasileiro.
    """

    cache['malicious'][url] = {
        "hashes": {
            "md5": malicious.hashes(iocs=cache['iocs'][url], type="md5"),
            "sha256": malicious.hashes(iocs=cache['iocs'][url], type="sha256"),
            "sha1": malicious.hashes(iocs=cache['iocs'][url], type="sha1"),
        },
        "ipv4": malicious.abuseipdb(iocs=cache['iocs'][url]),
        "urls": malicious.urlscanio(iocs=cache['iocs'][url]),
        "cve": [],
        "domains": [],
        "tox": [],
        "email": [],
        "btc": [],
        "monero": [],
        "registry_keys": [],
        "asns": [],
    }
    
    return TextContent(
            type="text",
            text=json.dumps(cache['malicious'][url], indent=2)
    )

@mcp.tool(
    name="create_misp_event",
    description="""
        Processa a última resposta do chat gerada pela ferramenta.
        E gera um um enveto no misp com as informações coletadas.

        A resposta do chat deve conter as informações coletadas, e as informações do MISP,
        com um resumo do que foi feito e o que foi encontrado, o ID do evento e o link do evento.
        
        Todas as respostas serão em português brasileiro.
    """
)
def create_misp_event(chat_history: list, url: str) -> TextContent:
    """
    Antes de executar essa tarefa, você precisa me dizer quais são os IOCs maliciosos,
    porque são esses IOCs que vão ser enviados para o MISP, por tanto faça um resumo dos IOCs maliciosos.

    Usa a última resposta do chat para extrair informações úteis, como IOCs.
    """
    iocs = None
    if not chat_history:
        iocs = cache['iocs'][url]

    if cache['matchs'].get(url, None) is None:
        cache['matchs'][url] = galaxys.matchs(content=cache["content"][url])


    if iocs is None:
        iocs = observables._iocs(raw=chat_history[-2]["content"])
        iocs['lastest'] = chat_history[-2]["content"]

    cache['misp'][url] = {
        "hashes": {
            "md5": [],
            "sha256": [],
            "sha1": [],
        },
        "ipv4": [],
        "urls": [],
        "cve": [],
        "domains": [],
        "tox": [],
        "email": [],
        "btc": [],
        "monero": [],
        "registry_keys": [],
        "asns": [],
        "matchs": cache['matchs'][url]
    }

    if cache['malicious'].get(url, None) is not None:
        if iocs.get('ipv4'):
            for ipv4 in iocs.get('ipv4'):
                for item in cache['malicious'][url].get('ipv4'):
                    if ipv4 == item.get('data'):
                        cache['misp'][url]['ipv4'].append(item)

        if iocs.get('url'):
            for url in iocs.get('url'):
                for item in cache['malicious'][url].get('url'):
                    if url == item.get('data'):
                        cache['misp'][url]['url'].append(item)

        if iocs.get('hashes'):
            if iocs.get('hashes').get('md5'):

                for md5 in iocs.get('hashes').get('md5'):
                    for item in cache['malicious'][url].get('hashes').get('md5'):
                        if md5 == item.get('data'):
                            cache['misp'][url]['hashes']['md5'].append(item)

            if iocs.get('hashes').get('sha256'):
                for sha256 in iocs.get('hashes').get('sha256'):
                    for item in cache['malicious'][url].get('hashes').get('sha256'):
                        if sha256 == item.get('data'):
                            cache['misp'][url]['hashes']['sha256'].append(item)

            if iocs.get('hashes').get('sha1'):
                for sha1 in iocs.get('hashes').get('sha1'):
                    for item in cache['malicious'][url].get('hashes').get('sha1'):
                        if sha1 == item.get('data'):
                            cache['misp'][url]['hashes']['sha1'].append(item)



    if cache['misp_event'].get(url, None) is None:

        misp_event = misp.add_event(data={
            "info": cache['title'][url], 
            "published": False,
            "threat_level_id": 3,
            "distribution": 0,
            "analysis": 2,
            "tlp": "white",
        })


        cache['misp_event'][url] = misp_event

        if misp_event is not None:
        
            if cache['misp_event'].get(url, None) is not None and cache['matchs'].get(url, None) is not None:

                if cache['matchs'][url].get('ttps', None) is not None:
                    for item in cache['matchs'][url].get('ttps')['rules']:
                        if item.get('id', None) is not None:
                            misp.add_galaxy_to_event(
                                event_uuid=misp_event['Event']['uuid'],
                                cluster_uuid=item.get('id')
                            )
                if cache['matchs'][url].get('tools', None) is not None:
                    for item in cache['matchs'][url].get('tools')['rules']:
                        if item.get('id', None) is not None:
                            misp.add_galaxy_to_event(
                                event_uuid=misp_event['Event']['uuid'],
                                cluster_uuid=item.get('id')
                            )
                
                if cache['matchs'][url].get('actors', None) is not None:
                    for item in cache['matchs'][url].get('actors')['rules']:
                        if item.get('id', None) is not None:
                            misp.add_galaxy_to_event(
                                event_uuid=misp_event['Event']['uuid'],
                                cluster_uuid=item.get('id')
                        )

                if cache['matchs'][url].get('malware', None) is not None:
                    for item in cache['matchs'][url].get('malware')['rules']:
                        if item.get('id', None) is not None:
                            misp.add_galaxy_to_event(
                                event_uuid=misp_event['Event']['uuid'],
                                cluster_uuid=item.get('id')
                            )
                
            
            if cache['misp_event'].get(url, None) is not None:
                attribute = misp.add_attribute_event(
                    event=misp_event['Event']['uuid'],
                    data={
                        "comment": "URL de origem do evento | This is not an IOC", 
                        "value": url, 
                        "category":"Internal reference"
                    },
                    type="text"
                )

                misp.add_tag_event(
                    event=attribute['Attribute']['uuid'],
                    tag='source:url')
                
                if cache['malicious'].get(url, None) is not None:
                
                    if cache['malicious'][url].get('ipv4', None) is not None:
                        for item in cache['malicious'][url].get('ipv4'):
                            attribute = misp.add_attribute_event(
                                event=misp_event['Event']['uuid'],
                                data={
                                    "comment": "Indicador extraido do content da página web, classificado como maliciosos pelo MCP", 
                                    "value": item['data'], 
                                    "category":"Network activity"
                                },
                                type='ip'
                            )   
                            if attribute is not None:
                                misp.add_tag_event(
                                    event=attribute['Attribute']['uuid'],
                                    tag='mcp:malicious-content')
                                if item.get('results') and item.get('results').get('abuseipdb', None) is not None:
                                    if item["results"]["abuseipdb"]["data"].get("country", None) is not None:
                                        misp.add_tag_event(
                                        event=attribute['Attribute']['uuid'],
                                        tag=f'country:{item["results"]["abuseipdb"]["data"].get("country")}')
                                    
                                    if item["results"]["abuseipdb"]["data"].get("isp", None) is not None:
                                        misp.add_tag_event(
                                        event=attribute['Attribute']['uuid'],
                                        tag=f'isp:{item["results"]["abuseipdb"]["data"].get("isp")}')

                                    if item["results"]["abuseipdb"]["data"].get("domain", None) is not None:
                                        misp.add_tag_event(
                                        event=attribute['Attribute']['uuid'],
                                        tag=f'domain:{item["results"]["abuseipdb"]["data"].get("domain")}')

                                    if item["results"]["abuseipdb"]["data"].get("abuseConfidenceScore", None) is not None:
                                        misp.add_tag_event(
                                        event=attribute['Attribute']['uuid'],
                                        tag=f'abuseConfidenceScore:{item["results"]["abuseipdb"]["data"].get("abuseConfidenceScore")}')

                    if cache['malicious'][url].get('url', None) is not None:
                        for item in cache['malicious'][url].get('url'):
                            misp.add_attribute_event(
                                event=misp_event['Event']['uuid'],
                                data={
                                    "comment": "Indicador extraido do content da página web, classificado como maliciosos pelo MCP", 
                                    "value": item['data'], 
                                    "category":"Network activity"
                                },
                                type='url'
                            )

    return TextContent(
        type="text",
        text=json.dumps(cache['misp'][url], indent=2)
    )


if __name__ == "__main__":
    mcp.run()