from mcp.server.fastmcp import FastMCP
import httpx
from mcp.types import TextContent
from datetime import datetime
import os
import time
import json

ORKL_BASE_URL = "https://orkl.eu/api/v1"

mcp = FastMCP(
    "Orkl",
    instructions="""
        Você é um analista de inteligência de ameaças e deve utilizar todos os dados recebidos
        como contexto, para responder perguntas de forma mais eficiênte com foco, em inteligência
        contra ameaças.
    """,    
)

cache = {
    "threat_reports": {},
    "threat_actors": {},
    "sources": {}
}


@mcp.tool(
    name="fetch_latest_threat_reports",
    description="""
        [Obtem|resume|extrai] os ultimos 5 relatórios e faz um resumo
        com todo o conteúdo deles, trazendo os melhores pontos que devem
        ser levados em consideração visando a analise de ameaça
        Todas as respostas serão em português brasileiro.
    """,
)
async def fetch_latest_threat_reports() -> TextContent:
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{ORKL_BASE_URL}/library/entries?limit=5&order_by=created_at&order=desc")
        if response.status_code == 200:
            reports = response.json().get("data", [])
            for report in reports:
                cache["threat_reports"][report["id"]] = report

            return TextContent(
                type="text",
                text="\n".join([f"ID: {report['id']}, Título: {report['title']}, Conteudo: {report['plain_text'][0:500]}" for report in reports]))


@mcp.tool(
    name="fetch_threat_report_details",
    description="""
        [Obtem|resume|extrai] um único relaório que esta em report_id, e faz um resumo
        detalhado com todos os pontos importantes que devem ser considerados por um analista de ameaça.
    """,
)
async def fetch_threat_report_details(report_id: str) -> TextContent:
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{ORKL_BASE_URL}/library/entry/{report_id}")
        if response.status_code == 200:
            report_details = response.json().get("data", {})
            cache["threat_reports"][report_id] = report_details

            return TextContent(
                type="text",
                text="\n".join([f"ID: {report['id']}, Título: {report['title']}, Conteudo: {report['plain_text'][0:500]}" for report in reports]))

if __name__ == "__main__":
    mcp.run()
