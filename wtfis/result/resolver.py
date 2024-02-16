from typing import Optional, Union

from wtfis.clients.greynoise import GreynoiseClient
from wtfis.clients.ip2whois import Ip2WhoisClient
from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.passivetotal import PTClient
from wtfis.clients.shodan import ShodanClient
from wtfis.clients.virustotal import VTClient
from wtfis.config import Config
from wtfis.handlers.base import BaseHandler
from wtfis.handlers.domain import DomainHandler
from wtfis.handlers.ip import IpAddressHandler
from wtfis.models.virustotal import Domain, IpAddress
from wtfis.result.result import DomainResult, IpAddressResult
from wtfis.utils import is_ip


class Resolver:
    entity: BaseHandler

    __is_target_ip: bool

    def __init__(self, target: str, config: Config) -> None:
        self.entity = self.__generate_entity_handler(target=target, config=config)

    def __generate_entity_handler(self, target: str, config: Config) -> BaseHandler:

        self.__is_target_ip = is_ip(target=target)

        # Virustotal client
        vt_client = VTClient(config.vt_api_key)

        # IP enrichment client selector
        shodan_key = config.shodan_api_key
        enricher_client: Union[IpWhoisClient, ShodanClient] = (
            ShodanClient(shodan_key) if shodan_key
            else IpWhoisClient()
        )

        # Whois client selector
        # Order of use based on set envvars:
        #    1. Passivetotal
        #    2. IP2Whois (Domain only)
        #    2. Virustotal (fallback)
        if config.pt_api_user and config.pt_api_key:
            whois_client: Union[PTClient, Ip2WhoisClient, VTClient] = (
                PTClient(config.pt_api_user, config.pt_api_key)
            )
        elif config.ip2whois_api_key and not is_ip(target):
            whois_client = Ip2WhoisClient(config.ip2whois_api_key)
        else:
            whois_client = vt_client

        # Greynoise client (optional)
        greynoise_client: Optional[GreynoiseClient] = (
            GreynoiseClient(config.greynoise_api_key)
            if config.greynoise_api_key
            else None
        )

        if self.__is_target_ip:
            # IP address handler
            entity = IpAddressHandler(
                entity=target,
                vt_client=vt_client,
                ip_enricher_client=enricher_client,
                whois_client=whois_client,
                greynoise_client=greynoise_client
            )
        else:
            # Domain / FQDN handler
            entity: BaseHandler = DomainHandler(
                entity=target,
                vt_client=vt_client,
                ip_enricher_client=enricher_client,
                whois_client=whois_client,
                greynoise_client=greynoise_client
            )

        return entity

    def fetch(self) -> None:
        '''Initiates queries to configured APIs'''
        self.entity.fetch_data()

    def export(self) -> str:
        '''Exports the resolved data as a JSON string'''

        if self.__is_target_ip:
            return str(IpAddressResult(
               entity=self.entity.vt_info,  # type: ignore
               whois=self.entity.whois,
               ip_enrich=self.entity.ip_enrich,
               greynoise=self.entity.greynoise))  # type: ignore
        else:
            return str(DomainResult(
                entity=self.entity.vt_info,  # type: ignore
                resolutions=self.entity.resolutions,  # type: ignore
                whois=self.entity.whois,
                ip_enrich=self.entity.ip_enrich,
                greynoise=self.entity.greynoise))  # type: ignore
