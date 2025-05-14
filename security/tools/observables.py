import iocextract
import re
import requests
import os
import yara_tools
import yara
import exrex
from stix2.base import STIXJSONEncoder
import json
from stix2 import (
        AttackPattern,
        Identity,
        Indicator,
        Malware,
        Relationship,
        ThreatActor,
        Tool,
        Bundle,
        IPv4Address,
        URL,
        File
    )

class Malicious:
    
    def virus_total(self, target: str, type: str) -> list:
        """
        Valida URLs em VirusTotal
        """
        results = {}
        if type == "ipv4":
            response = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{target}",
                headers={
                    "accept": "application/json",
                    "x-apikey": os.getenv('VT_API_KEY', '')
                }
            )
            if response.status_code == 200:
                if response.json().get('data'):
                    if response.json().get('data').get('attributes'):
                        return {
                            "tags": response.json()['data']['attributes'].get('tags', []),
                            "last_analysis_stats": response.json()['data']['attributes'].get('last_analysis_stats', []),
                        }
        if type == "url":
            response = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{target}",
                headers={
                    "accept": "application/json",
                    "x-apikey": os.getenv('VT_API_KEY', '')
                }
            )

            if response.status_code == 200:
                if response.json().get('data'):
                    if response.json().get('data').get('attributes'):
                        return {
                            "tags": response.json()['data']['attributes'].get('tags', []),
                            "last_analysis_stats": response.json()['data']['attributes'].get('last_analysis_stats', []),
                        }
        if type == "hashe":
            response = requests.get(
                f"https://www.virustotal.com/api/v3/files/{target}",
                headers={
                    "accept": "application/json",
                    "x-apikey": os.getenv('VT_API_KEY', '')
                }
            )
            if response.status_code == 200:

                if response.json().get('data'):
                    if response.json().get('data').get('attributes'):
                        return {
                            "tags": response.json()['data']['attributes'].get('tags', []),
                            "last_analysis_stats": response.json()['data']['attributes'].get('last_analysis_stats', []),
                        }

        return results

    def abuseipdb(self, iocs: dict) -> list:
        """
        Valida IPs em AbuseIPDB
        """
        results = []
        if iocs.get('ipv4'):
            for ipv4 in iocs.get('ipv4'):
                response = requests.get(
                    f"https://api.abuseipdb.com/api/v2/check", 
                    headers={
                        "Accept": "application/json",
                        "Key": os.getenv('ABUSEIPDB_API', '')
                        },
                    params={
                        'ipAddress': ipv4,
                        'maxAgeInDays': '90'
                    })  
                if response.status_code == 200:
                    results.append({
                        "data": ipv4,
                        "results": {
                            "abuseipdb": response.json(),
                            "vt": self.virus_total(target=ipv4, type="ipv4")
                        }
                    })

        return results

    def urlscanio(self, iocs: dict) -> list:
        """
        Valida URLS em URLSCAN.IO
        """
        results = []
        if iocs.get('urls'):
            for url in iocs.get('urls'):
                pattern = r'(?:https?:\/\/)?(?:www\.)?([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,})'
                url = re.search(pattern, url)
                response = requests.get(
                    f"https://urlscan.io/api/v1/search/?q=page.domain:{url}&size=2",
                    headers={
                        "Content-Type": "application/json",
                        "API-Key": os.getenv('URLSCANIO_API', '')
                    })
                if response.status_code == 200:
                    results.append({
                        "data": url,
                        "results": {
                            "urlscan_io": response.json(),
                            "vt": self.virus_total(target=url, type="url")
                        }
                    })

        return results
    
    def hashes(self, iocs: dict, type: str ) -> list:
        """
        Valida HASHES em diferentes fontes
        """
        results = []

        if iocs.get('hashes'):
            if iocs.get('hashes').get(type):
                for item in iocs.get('hashes').get(type):
                    results.append({
                        "data": item,
                        "results": {
                            "vt": self.virus_total(target=item, type="hashe")
                        }
                    })

        return results

class Observables:
    def _hashes(self, **kwargs) -> list:
        """
        Extrair HASHES de um texto como MD5, SHA1 e SHA256
            
        Args:
            raw: string que deseja obter IOCs
        Returns:
            list: Lista com todas as hashes encontradas
        """
        
        raw = kwargs.get("raw", None)
        hashes = []


        try:
            content = re.findall(r"\b([0-9a-fA-F]{64})\b", raw)
            for match in content:
                if len(match) > 1:
                    if match not in hashes:
                        hashes.append(match)
        except (TypeError) as e:
            pass

        try:
            content = re.findall(r"\b([0-9a-fA-F]{40})\b", raw)
            for match in content:
                if len(match) > 1:
                    if match not in hashes:
                        hashes.append(match)
        except (TypeError) as e:
            pass
                
        try:
            content = re.findall(r"\b([0-9a-fA-F]{32})\b", raw)
            for match in content:
                if len(match) > 1:
                    if match not in hashes:
                        hashes.append(match)
        except (TypeError) as e:
            pass

        for h in hashes:
            for p in hashes:
                if h in p:
                    hashes.remove(p)

        
        
        return hashes
    

    def _urls(self, **kwargs) -> list:
        """
        Extrair todas as URLS de um texto
            
        Args:
            raw: string que deseja obter as URLS
        Returns:
            list: Lista com todas as urls encontradas
        """
        
        raw = kwargs.get("raw", None)
        results = []
                
        urls = re.findall(
            r"((http|ftp|https):\/\/([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:\/~+#-]*[\w@?^=%&\/~+#-])?)", raw, re.DOTALL)

        for url in urls:
            if len(url) > 0:
                if url[0] not in results:
                    results.append(url[0])
        
        return results
    
    def _domains(self, **kwargs) -> list:
        """
        Extrair todas as URLS de um texto
            
        Args:
            raw: string que deseja obter as URLS
        Returns:
            list: Lista com todas as urls encontradas
        """
        
        raw = kwargs.get("raw", None)
        results = []
                

        domains = re.findall(r"^(?:https?:\/\/|http?:\/\/|ftp?:\/\/)?(?:[^@\/\\n]+@)?(?:www\.)?", str(raw), re.DOTALL)
        
        for domain in domains:
            if len(domain) > 0:
                if domain not in results:
                    results.append(domain)
                    
        return results
    
    def _cve(self, **kwargs) -> list:
        """
        Extrair todas as URLS de um texto
            
        Args:
            raw: string que deseja obter as URLS
        Returns:
            list: Lista com todas as urls encontradas
        """
        
        raw = kwargs.get("raw", None)
        results = []
                
        cves = re.findall("((cve-[0-9]{4}-[0-9]{2,6})|(CVE-[0-9]{4}-[0-9]{2,6}))", raw, re.DOTALL)
        
        for cve in cves:
            if len(cve) > 0:
                if cve not in results:
                    results.append(cve)
                    
        return results
    
    def _asn(self, **kwargs) -> list:
        """
        Extrair todas as ASN de um texto
            
        Args:
            raw: string que deseja obter as ASN
        Returns:
            list: Lista com todas as ASN encontradas
        """
        
        raw = kwargs.get("raw", None)
        results = []
                
        cves = re.findall("((asn[0-9]{4,6})|(ASN[0-9]{4,6}))", raw, re.DOTALL)
        
        for cve in cves:
            if len(cve) > 0:
                if cve not in results:
                    results.append(cve)
                    
        return results
    
    def _registry_keys(self, **kwargs) -> list:
        """
        Extrair todas as registry keys de um texto
            
        Args:
            raw: string que deseja obter as registry keys
        Returns:
            list: Lista com todas as urls encontradas
        """
        
        raw = kwargs.get("raw", None)
        results = []
                
        contents = re.findall(r'HKLM:\\.*?(?=\.)', raw, re.DOTALL)
        
        for content in contents:
            if len(content) > 0:
                if content not in results:
                    results.append(content)
                    
        contents = re.findall(r'HKCU:\\.*?(?=\.)', raw, re.DOTALL)
        
        for content in contents:
            if len(content) > 0:
                if content not in results:
                    results.append(content)
                    
        contents = re.findall(r'HKCC:\\.*?(?=\.)', raw, re.DOTALL)
        
        for content in contents:
            if len(content) > 0:
                if content not in results:
                    results.append(content)
                    
        return results
    
    def _tox(self, **kwargs) -> list:
        """
        Extrair todos endereços TOX de um texto
            
        Args:
            raw: string que deseja obter os TOX
        Returns:
            list: Lista com todas os TOX encontradas
        """
        
        raw = kwargs.get("raw", None)
        results = []
                
        search = re.findall("([aA-zZ0-9]{76})", raw, re.DOTALL)
        
        for result in search:
            if len(result) > 0:
                if result not in results:
                    results.append(result)
                    
        return results
    
    def _email(self, **kwargs) -> list:
        """
        Extrair todos endereços TOX de um texto
            
        Args:
            raw: string que deseja obter os TOX
        Returns:
            list: Lista com todas os TOX encontradas
        """
        
        raw = kwargs.get("raw", None)
        results = []
                
        search = re.findall(r"([\w-]+(\.[\w-]+)*@[\w-]+(\.[\w-]+)*\.[a-zA-Z-]+[\w-])", raw, re.DOTALL)
        
        for result in search:
            if len(result) > 0:
                if result[0] not in results:
                    results.append(result[0])
                    
        return results
    
    def _btc(self, **kwargs) -> list:
        """
        Extrair todos endereços TOX de um texto
            
        Args:
            raw: string que deseja obter os TOX
        Returns:
            list: Lista com todas os TOX encontradas
        """
        
        raw = kwargs.get("raw", None)
        results = []
                
        search = re.findall("(^[13][a-km-zA-HJ-NP-Z0-9]{26,33}$)", raw, re.DOTALL)
        
        for result in search:
            if len(result) > 0:
                if result[0] not in results:
                    results.append(result[0])
                    
                if result[1] not in results:
                    results.append(result[1])
                    
        return results
    
    def _monero(self, **kwargs) -> list:
        """
        Extrair todos endereços TOX de um texto
            
        Args:
            raw: string que deseja obter os TOX
        Returns:
            list: Lista com todas os TOX encontradas
        """
        
        raw = kwargs.get("raw", None)
        results = []
                
        search = re.findall("(4[0-9AB][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{93})", raw, re.DOTALL)
                
        for result in search:
            if len(result) > 0:
                if result not in results:
                    results.append(result)
                    
        return results
    
    def _useragent(self, **kwargs) -> list:
        """
        Extrair todos endereços TOX de um texto
            
        Args:
            raw: string que deseja obter os TOX
        Returns:
            list: Lista com todas os TOX encontradas
        """
        
        raw = kwargs.get("raw", None)
        results = []
                
        search = re.findall(r"((MSIE|Trident|(?!Gecko.+)Firefox|(?!AppleWebKit.+Chrome.+)Safari(?!.+Edge)|(?!AppleWebKit.+)Chrome(?!.+Edge)|(?!AppleWebKit.+Chrome.+Safari.+)Edge|AppleWebKit(?!.+Chrome|.+Safari)|Gecko(?!.+Firefox))(?: |\/)([\d\.apre]+))", raw, re.DOTALL)
                
        for result in search:
            if len(result) > 0:
                if result[0] not in results:
                    results.append(result[0])
                    
        return results
    
    def _hashes(self, **kwargs) -> list:
        """
        Extrair HASHES de um texto como MD5, SHA1 e SHA256
            
        Args:
            raw: string que deseja obter IOCs
        Returns:
            list: Lista com todas as hashes encontradas
        """
        
        raw = kwargs.get("raw", None)
        hashes = []


        try:
            content = re.findall(r"\b([0-9a-fA-F]{64})\b", raw)
            for match in content:
                if len(match) > 1:
                    if match not in hashes:
                        hashes.append(match)
        except (TypeError) as e:
            pass

        try:
            content = re.findall(r"\b([0-9a-fA-F]{40})\b", raw)
            for match in content:
                if len(match) > 1:
                    if match not in hashes:
                        hashes.append(match)
        except (TypeError) as e:
            pass
                
        try:
            content = re.findall(r"\b([0-9a-fA-F]{32})\b", raw)
            for match in content:
                if len(match) > 1:
                    if match not in hashes:
                        hashes.append(match)
        except (TypeError) as e:
            pass

        for h in hashes:
            for p in hashes:
                if h in p:
                    hashes.remove(p)

        
        
        return hashes
    
    def _iocs(self, **kwargs) -> dict:
        """
        Extrair todos os indicadores de compromisso como IPV4 e Hashes
            
        Args:
            raw: string que deseja obter IOCs
        Returns:
            dict: indicadores extraidos como IPv4 Hashes e Domínios
        """
        raw = kwargs.get("raw", "")
                
        hashes = []
        urls = []
        ipv4s = []
        urls = []
        sha1 = []
        md5 = []
        sha256 = []
        domains = []
        cve = []
        toxs = []
        emails = []
        btcs = []
        moneros = []
        registry_keys = []
        asns = []
        
        _hashes = self._hashes(raw=raw)
            
        try:
            _ipv4s = iocextract.extract_ipv4s(raw)
        except (TypeError) as e:
            _ipv4s = None

        _urls = None
        
        try:
            if _hashes is not None:
                for extract_hashes in _hashes:
                    if extract_hashes not in hashes:
                        hashes.append(extract_hashes)
        except (TypeError) as e:
            pass
        
        if _urls is not None:
            for extract_urls in _urls:
                if extract_urls not in urls:
                    extract_urls = extract_urls.replace("hxxp", "http")
                    urls.append(extract_urls)
                    
        for asn in self._asn(raw=raw):
            try:
                if (asn.upper() not in asns):
                    asns.append(asn.upper())
            except (AttributeError) as e:
                if (asn[0].upper() not in asns):
                    asns.append(asn[0].upper())
                
        for email in self._email(raw=raw):
            if (email.lower() not in emails):
                emails.append(email.lower())
                
        for btc in self._btc(raw=raw):
            if (btc.upper() not in btcs):
                btcs.append(btc.upper())
                
        for btc in self._btc(raw=raw):
            if (btc.upper() not in btcs):
                btcs.append(btc.upper())
                
        for monero in self._monero(raw=raw):
            if (monero.upper() not in moneros):
                moneros.append(monero.upper())
                

        for cv in self._cve(raw=raw):
            if (cv[0] not in cve):
                cve.append(cv[0].upper())
                
        for hk in self._registry_keys(raw=raw):
            if (hk.upper() not in registry_keys):
                registry_keys.append(hk.upper())
        
        if _ipv4s is not None:
            for extract_ipv4s in _ipv4s:
                if (extract_ipv4s not in ['1.1.1.1', '1[.]1[.]1[.]1', '8.8.8.8', '8[.]8[.]8[.]8'] 
                        and '192.168' not in extract_ipv4s 
                        and '172.16' not in extract_ipv4s 
                        and '192[.]168' not in extract_ipv4s 
                        and '172[.]16' not in extract_ipv4s 
                        and 'http' not in extract_ipv4s):
                    
                    extract_ipv4s = extract_ipv4s.replace("[", "").replace("]", "")
                    ipv4s.append(extract_ipv4s)

        for hash in hashes:
            
            if len(hash) == 40:
                if hash.upper() not in sha1:
                    if len(toxs) > 0:
                        for check in toxs:
                            if hash.upper() not in check.upper():
                                sha1.append(hash.upper())
                    else:
                        sha1.append(hash.upper())
            elif len(hash) == 32:
                if hash.upper() not in md5:
                    if len(toxs) > 0:
                        for check in toxs:
                            if hash.upper() not in check.upper():
                                md5.append(hash.upper())
                    else:
                        md5.append(hash.upper())
                            
            elif len(hash) == 64:
                if hash.upper() not in sha256:
                    if len(toxs) > 0:
                        for check in toxs:
                            if hash.upper() not in check.upper():
                                sha256.append(hash.upper())
                    else:
                        sha256.append(hash.upper())
   
        for hash in _hashes:
            if len(hash) == 40:
                if hash.upper() not in sha1:
                    if len(toxs) > 0:
                        for check in toxs:
                            if hash.upper() not in check.upper():
                                sha1.append(hash.upper())
                    else:
                        sha1.append(hash.upper())
            elif len(hash) == 32:
                if hash.upper() not in md5:
                    if len(toxs) > 0:
                        for check in toxs:
                            if hash.upper() not in check.upper():
                                md5.append(hash.upper())
                    else:
                        md5.append(hash.upper())
            elif len(hash) == 64:
                if hash.upper() not in sha256:
                    if len(toxs) > 0:
                        for check in toxs:
                            if hash.upper() not in check.upper():
                                sha256.append(hash.upper())
                    else:
                        sha256.append(hash.upper())
                    
        for url in self._urls(raw=raw):
            if url not in urls:
                url = url.replace("hxxp", "http")
                urls.append(url)

        return {
            "hashes": {
                "md5": list(set(md5)) if len(md5) > 0 else [],
                "sha256": list(set(sha256)) if len(sha256) > 0 else [],
                "sha1": list(set(sha1)) if len(sha1) > 0 else [],
            },
            "ipv4": list(set(ipv4s)) if len(ipv4s) > 0 else [],
            "urls": list(set(urls)) if len(urls) > 0 else [],
            "cve": list(set(cve)) if len(cve) > 0 else [],
            "domains": list(set(domains)) if len(domains) > 0 else [],
            "tox": [],
            "email": list(set(emails)) if len(emails) > 0 else [],
            "btc": list(set(btcs)) if len(btcs) > 0 else [],
            "monero": list(set(moneros)) if len(moneros) > 0 else [],
            "registry_keys": list(set(registry_keys)) if len(registry_keys) > 0 else [],
            "asns": list(set(asns)) if len(asns) > 0 else [],
        }
    

class Galaxys:
    url_threat_actor: str = "https://raw.githubusercontent.com/MISP/misp-galaxy/refs/heads/main/clusters/threat-actor.json"
    url_ttps: str = "https://raw.githubusercontent.com/MISP/misp-galaxy/refs/heads/main/clusters/mitre-attack-pattern.json"
    url_malware: str = "https://raw.githubusercontent.com/MISP/misp-galaxy/refs/heads/main/clusters/mitre-malware.json"
    url_tool: str = "https://raw.githubusercontent.com/MISP/misp-galaxy/refs/heads/main/clusters/tool.json"

    def yara_single(self, raw: str, yaradir: str = None, yararaw: str = None) -> dict:
        """
       Valide uma unica yara, podendo ser um diretório de arquivos
       ou uma yara em texto
            
        Args:
            raw: string com os dados que será avaliada com uma yararule
            yaradir: diretório da yararule caso esteja em um arquivo
            yararaw: yararule caso ela seja uma string
        Returns:
            dict: todos os dados que deram match com a yararule
        """
        
        if raw is not None:
            try:
                if yaradir is not None:
                    yararaw = ''
                    for root, dirs, files in os.walk(yaradir):
                        for file in files:
                            if file.endswith(".yara"):
                                filepath = os.path.join(root, file)
                                with open(filepath, 'r') as file:
                                    yararaw+=f'{"".join(file.readlines())}\n'
                    
                    rules = yara.compile(source=yararaw)

                    
                elif yararaw is not None:
                    rules = yara.compile(source=yararaw)
                
                full_match_keywords = rules.match(data=raw)
                
                names = []
                strings_keywords = []
                
                if len(full_match_keywords) == 0:
                    full_match_keywords = []
                    score_keywords = 0
                else:
                    cont = 1
                    score_keywords = 0

                    while cont <= int(len(full_match_keywords)):
                        for string in full_match_keywords[cont-1].strings:

                            for instance in string.instances:
                                if str(instance).lower() not in strings_keywords:
                                    strings_keywords.append(str(instance).lower())

                        if full_match_keywords[cont-1].meta not in names:
                            names.append(
                                full_match_keywords[cont-1].meta)

                        score_keywords += int(full_match_keywords[cont-1].meta['score'])

                        cont += 1

                if len(full_match_keywords) == 0:
                    full_match_keywords = []

                return {
                    "rules": names,
                    "score": score_keywords,
                    "strings": strings_keywords[0:50]
                }
            
            except (yara.Error) as e:
                if 'internal error: 30' in str(e):
                    self.logger.error("Aparentemente sua yara está dando math com muitos dados. Isso pode ser um problema")
                else:
                    self.logger.error(f"Um erro desconhecido ocorreu na yararule [{yaradir}] - {str(e)}")

        return {
            "rules": None,
            "score": 0,
            "strings": None
        }

    def create_rule(self, name: str, items: list) -> str:

        """
        Gera uma yara para cada item da lista

        O padrão deve ser [{"name": "nome", "synonyms": ["nome1", "nome2"], "uuid": "uuid"}]

        Args:
            name: nome da yara
            items: lista de itens a serem gerados
        Returns:
            str: yara gerada

        """
         
        _yaras = ''
        for item in items:
            rname = exrex.getone('[a-z]{20}')
            rule = yara_tools.create_rule(name=f"MitreData{name}_{rname}")
            rule.add_meta(key="name", value=item['name'])
            rule.add_meta(key="score", value=10)
            rule.add_meta(key="id", value=item['uuid'])


            rule.add_strings(strings=f" {item['name']}",
                            modifiers=["nocase", "fullword"],
                            condition="any of them")
            rule.add_strings(strings=f"{item['name']}",
                            modifiers=["nocase", "fullword"],
                            condition="any of them")

            if item.get('synonyms'):
                for synonym in item['synonyms']:
                    rule.add_strings(strings=f" {synonym}",
                                    modifiers=["nocase", "fullword"],
                                    condition="any of them")
                    rule.add_strings(strings=f"{synonym}",
                                    modifiers=["nocase", "fullword"],
                                    condition="any of them")
            
            _yaras+=f"{rule.build_rule()}\n"

        return _yaras

    def matchs(self, content: str) -> dict:
        """
        Executa a função de gerar as yaras
        Retorna um dicionário com as yaras geradas
        """
        actors = requests.get(self.url_threat_actor)
        parsed_actors = []
        if actors.status_code == 200:
            actors = actors.json()
            for actor in actors['values']:
                parsed_actors.append({
                    "name": actor['value'],
                    "synonyms": actor.get('synonyms', []),
                    "uuid": actor['uuid'],
                })

        ttps = requests.get(self.url_ttps)
        parsed_ttps = []
        if ttps.status_code == 200:
            ttps = ttps.json()
            for item in ttps['values']:
                if item.get('meta'):

                    parsed_ttps.append({
                        "name": item['meta']['external_id'],
                        "uuid": item['uuid'],
                    })

        malwares = requests.get(self.url_ttps)
        parsed_malwares = []
        if malwares.status_code == 200:
            malwares = malwares.json()
            for item in malwares['values']:
                if item.get('meta'):
                    parsed_malwares.append({
                        "name": item['value'].split(" - ")[0],
                        "synonyms": [item['meta']['external_id']],
                        "uuid": item['uuid'],
                    })

        tools = requests.get(self.url_ttps)
        parsed_tools = []
        if tools.status_code == 200:
            tools = tools.json()
            for item in tools['values']:
                if item.get('meta'):
                    parsed_tools.append({
                        "name": item['value'].split(" - ")[0],
                        "synonyms": [item['meta']['external_id']],
                        "uuid": item['uuid'],
                    })

        yaras = {
            "actors": self.create_rule(name="actors", items=parsed_actors),
            "ttps": self.create_rule(name="ttps", items=parsed_ttps),
            "malwares": self.create_rule(name="malwares", items=parsed_malwares),
            "tools": self.create_rule(name="tools", items=parsed_tools),
        }

        matchs_yaras = {
            "actors": self.yara_single(raw=content, yararaw=yaras['actors']),
            "ttps": self.yara_single(raw=content, yararaw=yaras['ttps']),
            "malwares": self.yara_single(raw=content, yararaw=yaras['malwares']),
            "tools": self.yara_single(raw=content, yararaw=yaras['tools']),
        }

        if actors is not None and len(actors) > 0:
            for infos in matchs_yaras['actors']['rules']:
                for item in actors['values']:
                    if infos['name']  == item['value']:
                        infos['raw'] = item
        
        if ttps is not None and len(ttps) > 0:
            for infos in matchs_yaras['ttps']['rules']:
                for item in ttps['values']:
                    try:
                        if infos['name']  == item['meta']['external_id']:
                            infos['raw'] = item
                    except:
                        pass
        
        if tools is not None and len(tools) > 0:
            for infos in matchs_yaras['tools']['rules']:
                for item in tools['values']:
                    try:
                        if infos['name']  == item['value'].split(" - ")[0]:
                            infos['raw'] = item
                    except:
                        pass
        
        if malwares is not None and len(malwares) > 0:
            for infos in matchs_yaras['malwares']['rules']:
                for item in malwares['values']:
                    try:
                        if infos['name']  == item['value'].split(" - ")[0]:
                            infos['raw'] = item
                    except:
                        pass

        

        return matchs_yaras


class Stix:
    
    def create_stix(self, matchs: str,  title: str) -> dict:
        
        identity = Identity(
            name=title,
            identity_class="organization",
            description="Fonte dos dados"
        )

        stix_objects = [identity]

        if matchs.get('actors'):
            for actor in matchs['actors']['rules']:
                stix_objects.append(ThreatActor(
                    name=actor['name'],
                    description=actor['raw']['description'],
                    sophistication="advanced",
                    aliases=actor.get('synonyms', [])
                ))

        if matchs.get('malwares'):
            for malware in matchs['malwares']['rules']:
                stix_objects.append(Malware(
                    name=malware['name'],
                    description=malware['raw']['description'],
                    is_family=True
                ))

        if matchs.get('ttps'):
            for ttp in matchs['ttps']['rules']:
                stix_objects.append(AttackPattern(
                    name=ttp['name'],
                    description=ttp['raw']['description'],
                ))

        if matchs.get('tools'):
            for tool in matchs['tools']['rules']:
                stix_objects.append(Tool(
                    name=tool['name'],
                    description=tool['raw']['description'],
                ))

        for stix_object in stix_objects:
            if stix_object.get('type') == 'threat-actor':
                for item in stix_objects:
                    if item.get('type') == 'malware':
                        stix_objects.append(Relationship(stix_object, 'uses', item))

                    if item.get('type') == 'tool':
                        stix_objects.append(Relationship(stix_object, 'uses', item))

                    if item.get('type') == 'attack-pattern':
                        stix_objects.append(Relationship(stix_object, 'uses', item))

        bundle = Bundle(objects=stix_objects)

        
        return json.loads(json.dumps(bundle, cls=STIXJSONEncoder))