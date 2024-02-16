import json
from datetime import datetime
from typing import Optional, Union

from wtfis.models.common import WhoisBase
from wtfis.models.greynoise import GreynoiseIpMap
from wtfis.models.ipwhois import IpWhois, IpWhoisMap
from wtfis.models.shodan import ShodanIpMap
from wtfis.models.virustotal import Domain, IpAddress, Resolutions
from wtfis.result.base import BaseResult


class DomainResult(BaseResult):
    """
    Handler for FQDN and domain lookup output
    """
    def __init__(
        self,
        entity: Domain,
        resolutions: Optional[Resolutions],
        whois: WhoisBase,
        ip_enrich: Union[IpWhoisMap, ShodanIpMap],
        greynoise: GreynoiseIpMap
        ) -> None:
        super().__init__( entity, whois, ip_enrich, greynoise)
        self.resolutions = resolutions

    def domain_panel(self) -> dict:
        return self._gen_vt_response()

    def resolutions_panel(self) -> Optional[dict]:
        # Skip if no resolutions data
        if not self.resolutions:
            return None

        resolutions:dict = {}
        resolutions["resolution_count"] = self.resolutions.meta.count
        resolutions["resolutions_link"] = f"{self.vt_gui_baseurl_domain}/{self.entity.data.id_}/relations"
        resolutions["resolution"] = []

        for _, ip in enumerate(self.resolutions.data):

            resolution:dict = {}
            attributes = ip.attributes

            # Analysis
            analysis = self._gen_vt_analysis_stats(attributes.ip_address_last_analysis_stats)
            resolution["analysis"] = analysis
            resolution["analysis_link"] = f"{self.vt_gui_baseurl_ip}/{attributes.ip_address}"

            # Content
            resolution["resolved_ip"] = attributes.ip_address
            resolution["resolved"] = datetime.fromtimestamp(attributes.date).isoformat()


            # IP Enrichment
            enrich = self._get_ip_enrichment(attributes.ip_address)

            if enrich:
                if isinstance(enrich, IpWhois):
                    # IPWhois
                    asn = self._gen_asn_text(enrich.connection.asn, enrich.connection.org)
                    resolution["asn"] = asn
                    resolution["isp"] = enrich.connection.isp
                    resolution["location"] = ", ".join([enrich.city, enrich.region, enrich.country])
                else:
                    # Shodan
                    asn = self._gen_asn_text(enrich.asn, enrich.org)
                    tags = ",".join(enrich.tags) if enrich.tags else None

                    resolution["asn"] = asn
                    resolution["isp"] = enrich.isp

                    location:str = enrich.country_name

                    if enrich.region_name:
                        location = enrich.region_name + ", " + location

                    if enrich.city:
                        location = enrich.city + ", " + location

                    resolution["location"] = location

                    resolution["os"] = enrich.os if enrich.os is not None else "Unknown"
                    services = self._gen_shodan_services(enrich)
                    if services:
                        resolution["services"] = services
                    resolution["services_link"] = f"{self.shodan_gui_baseurl}/{attributes.ip_address}"

                    tags = ", ".join(enrich.tags) if enrich.tags else None
                    if tags:
                        resolution["tags"] = tags
                    resolution["last_scan"] = f"{enrich.last_update}+00:00"

            # Greynoise
            greynoise = self._get_greynoise_enrichment(attributes.ip_address)

            if greynoise:
                resolution["greynoise"] = self._gen_greynoise_details(greynoise)

            resolutions["resolution"].append(resolution)

        return resolutions

    def __str__(self) -> str:
        return json.dumps(
            { "whois": self.whois_panel(), "domain":self.domain_panel(), "resolutions": self.resolutions_panel() },
            indent=4,
            sort_keys=True)


class IpAddressResult(BaseResult):
    """
    Handler for IP Address lookup output
    """
    def __init__(
        self,
        entity: IpAddress,
        whois: WhoisBase,
        ip_enrich: Union[IpWhoisMap, ShodanIpMap],
        greynoise: GreynoiseIpMap,
    ) -> None:
        super().__init__(entity, whois, ip_enrich, greynoise)

    def ip_panel(self) -> dict:

        ip:dict = {}
        # Virustotal section
        vt_section = self._gen_vt_response()
        ip["virustotal"] = vt_section

        # IP Enrichment section
        ip_enrich_section = self._gen_ip_enrich_response()
        if ip_enrich_section:
            ip["enrichment"] = ip_enrich_section

        # Other section
        other_section = self._gen_ip_other_response()
        if other_section:
            ip["other"] = other_section

        # Altogether now
        return ip

    def __str__(self) -> str:
        return json.dumps(
            { "whois": self.whois_panel(), "ip": self.ip_panel() },
            indent=4,
            sort_keys=True)