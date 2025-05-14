import requests
from pymisp import PyMISP
from typing import List, Dict, Union
import datetime
import os
class Misp:
    def __init__(self):
        self.misp_url = os.getenv('MISP_URL', 'https://localhost') 
        self.misp_key = os.getenv('MISP_KEY', '')  
        self.verify_cert = False
        try:
            self.misp = PyMISP(self.misp_url, self.misp_key, self.verify_cert)
        except:
            self.misp = None

        self.headers = {
            "Authorization": self.misp_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

    def get_attributes(self, attributes: List[str]) -> Dict[any, any]:
        match_attributes = []
        attributes_types_mapping = (
            "ip-src",
            "ip-src|port"
            "ip-dst|port",
            "ip-dst",
            "target-location",
            "domain-ip",
            "domain"
        )

        for attribute in attributes:
            if not attribute["type"] in attributes_types_mapping:
                continue

            match_attributes.append({"type": attribute["type"].replace("|", "-"), "data": attribute["value"]})

        return match_attributes

    def get_tag_id(self, tag_name: str) -> int:
        tags = self.misp.tags(pythonify=True)

        for tag in tags:
            if tag["name"] == tag_name:
                return tag["id"]

    def remove_tag_event(self, event_id: str, tag_id: Union[str, int]):
        """Remove a new tag to an event.

        Args:
            tag_name (str): tag to be a added.
            event_id (str): Misp event id

        Returns:
            bool: It will return True if success
        """        

        response = requests.post(
            f"{self.misp_url}/events/removeTag/{event_id}/{tag_id}",
            headers=self.headers,
            verify=self.verify_cert
        ).json()
        
        if response.get("success"):
            return True

    def add_new_tag(self, event_id: str, tag_id: str) -> bool:
        """Add a new tag to an event.

        Args:
            tag_name (str): tag to be a added.
            event_id (str): Misp event id

        Returns:
            bool: It will return True if success
        """        

        response = requests.post(
            f"{self.misp_url}/events/addTag/{event_id}/{tag_id}",
            headers=self.headers,
            verify=self.verify_cert
        ).json()

        if response.get("success"):
            return True

    def get_events_via_tag(self, tag: str, date_from: datetime):
        events = self.misp.search(controller="events", tag=tag, date_from=date_from)

        return events
    
    def get_events_via_attr(self, attr: str,):
        events = self.misp.search('attributes', value=attr)

        return events
    
    def add_galaxy_to_event(self, event_uuid: str, cluster_uuid: str):
        """
        Adiciona um cluster de galaxia a um evento.

        Args:
            event_uuid (str): UUID do evento.
            cluster_uuid (str): UUID do cluster de galaxia.

        Returns:
            dict: Resposta da API.
        """
        
        cluster = self.misp.get_galaxy_cluster(cluster_uuid)
        if 'GalaxyCluster' in cluster and 'tag_name' in cluster['GalaxyCluster']:
            tag = cluster['GalaxyCluster']['tag_name']
            response = self.misp.tag(event_uuid, tag)
            return response
        
    
    def add_event(self,data:dict):
        print(data, "\n\n\n\n\n")
        r = self.misp.add_event(data)
        if r is not None:
            return r
        
    def publish_event(self,event:str):
        r = self.misp.publish(event)
        if r is not None:
            return r
        
    def add_tag_event(self,event:str, tag:str):
        r = self.misp.tag(event,tag)
        if r is not None:
            return r
        
    def add_attribute_event(self, event:str ,data:dict, type:str = None, passport=False):
                
        if data.get('event_id', None) is not None:
            del data['event_id']
        
        if type is not None:
            if type == 'ip':
                passport = True
                data.update({
                    "type":"ip-src"
                })
            
            elif type == 'url':
                passport = True
                data.update({
                    "type":"url"
                })
            
            elif type == 'mail':
                passport = True
                data.update({
                    "type":"email-src"
                })
                
            elif type == 'sha256':
                passport = True
                data.update({
                    "type":"sha256"
                })
                
            elif type == 'text':
                passport = True
                data.update({
                    "type":"text"
                })
                
        if passport:
            r = self.misp.add_attribute(event, data)
            
            if r is not None:
                return r
                
                

    def search_by_tag(self, tag:str):
        r = self.misp.search_index(tags=tag)
        if r is not None:
            return r
        
        