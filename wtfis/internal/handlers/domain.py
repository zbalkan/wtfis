"""
Logic handler for domain and hostname inputs
"""
from typing import Optional, Union

from requests.exceptions import HTTPError

from wtfis.internal.clients.greynoise import GreynoiseClient
from wtfis.internal.clients.ip2whois import Ip2WhoisClient
from wtfis.internal.clients.ipwhois import IpWhoisClient
from wtfis.internal.clients.passivetotal import PTClient
from wtfis.internal.clients.shodan import ShodanClient
from wtfis.internal.clients.virustotal import VTClient
from wtfis.internal.handlers.base import BaseHandler, common_exception_handler
from wtfis.internal.models.virustotal import Resolutions


class DomainHandler(BaseHandler):
    def __init__(
        self,
        entity: str,
        vt_client: VTClient,
        ip_enricher_client: Union[IpWhoisClient, ShodanClient],
        whois_client: Union[Ip2WhoisClient, PTClient, VTClient],
        greynoise_client: Optional[GreynoiseClient]
    ) -> None:
        super().__init__(entity, vt_client, ip_enricher_client,
                         whois_client, greynoise_client)

        # Extended attributes
        self.resolutions: Optional[Resolutions] = None

    @common_exception_handler
    def _fetch_vt_domain(self) -> None:
        self.vt_info = self._vt.get_domain(self.entity)

    @common_exception_handler
    def _fetch_vt_resolutions(self) -> None:
        # Let continue if rate limited
        try:
            self.resolutions = self._vt.get_domain_resolutions(self.entity)
        except HTTPError as e:
            if e.response.status_code == 429:
                self.warnings.append(
                    f"Could not fetch Virustotal resolutions: {e}")
            else:
                raise

    def fetch_data(self) -> None:
        print("Fetching data from Virustotal")
        self._fetch_vt_domain()
        self._fetch_vt_resolutions()

        if self.resolutions and self.resolutions.data:
            print(f"Fetching IP enrichments from {self._enricher.name}")
            self._fetch_ip_enrichments(
                [rd.attributes.ip_address for rd in self.resolutions.data])

            if self._greynoise:
                print(f"Fetching IP enrichments from {self._greynoise.name}")
                self._fetch_greynoise(
                    [rd.attributes.ip_address for rd in self.resolutions.data])

        print(f"Fetching domain whois from {self._whois.name}")
        self._fetch_whois()
