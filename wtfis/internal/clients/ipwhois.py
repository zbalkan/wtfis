from typing import Optional

from wtfis.internal.clients.base import BaseIpEnricherClient, BaseRequestsClient
from wtfis.internal.models.ipwhois import IpWhois, IpWhoisMap


class IpWhoisClient(BaseRequestsClient, BaseIpEnricherClient):
    """
    IPWhois client
    """
    baseurl = "https://ipwho.is"

    @property
    def name(self) -> str:
        return "IPWhois"

    def _get_ipwhois(self, ip: str) -> Optional[IpWhois]:
        result = self._get(f"/{ip}")
        return IpWhois.model_validate(result) if result.get("success") is True else None

    def enrich_ips(self, ips: list[str]) -> IpWhoisMap:
        ipwhois_map = {}
        for ip in ips:
            ipwhois = self._get_ipwhois(ip)
            if ipwhois:
                ipwhois_map[ipwhois.ip] = ipwhois
        return IpWhoisMap.model_validate(ipwhois_map)
