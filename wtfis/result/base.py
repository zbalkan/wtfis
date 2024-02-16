from datetime import datetime
from typing import Any, Final, Optional, Union

from wtfis.models.common import WhoisBase
from wtfis.models.greynoise import GreynoiseIp, GreynoiseIpMap
from wtfis.models.ipwhois import IpWhois, IpWhoisMap
from wtfis.models.shodan import ShodanIp, ShodanIpMap
from wtfis.models.virustotal import LastAnalysisStats, PopularityRanks
from wtfis.utils import is_ip


class BaseResult():
    """
    Handles the look of the output
    """
    vt_gui_baseurl_domain: Final[str] = "https://virustotal.com/gui/domain"
    vt_gui_baseurl_ip: Final[str] = "https://virustotal.com/gui/ip-address"
    pt_gui_baseurl: Final[str] = "https://community.riskiq.com/search"
    shodan_gui_baseurl: Final[str] = "https://www.shodan.io/host"

    def __init__(
        self,
        entity: Any,
        whois: Optional[WhoisBase],
        ip_enrich: Union[IpWhoisMap, ShodanIpMap],
        greynoise: GreynoiseIpMap,
        warnings: list[str]
    ) -> None:
        self.entity = entity
        self.whois = whois
        self.ip_enrich = ip_enrich
        self.greynoise = greynoise
        self.warnings = warnings

    def _vendors_who_flagged_malicious(self) -> list[str]:
        vendors = []
        for key, result in self.entity.data.attributes.last_analysis_results.root.items():
            if result.category == "malicious":
                vendors.append(key)
        return vendors

    def _gen_vt_analysis_stats(
        self,
        stats: LastAnalysisStats,
        vendors: Optional[list[str]] = None
    ) -> dict:
        # Total count
        total = stats.harmless + stats.malicious + stats.suspicious + stats.timeout + stats.undetected

        stats_dict: dict = {}
        stats_dict["vendors_who_flagged_malicious"] = f"{stats.malicious}/{total}"

        # Include list of vendors that flagged malicious
        if vendors:
            stats_dict["vendors"] = vendors

        return stats_dict

    def _gen_vt_popularity(self, popularity_ranks: PopularityRanks) -> Optional[dict]:
        if len(popularity_ranks.root) == 0:
            return None

        pop: dict = {}
        for source, popularity in popularity_ranks.root.items():
            pop["source"] = source
            pop["rank"] = popularity.rank
        return pop

    def _gen_shodan_services(self, ip: ShodanIp) -> Optional[dict]:
        if len(ip.data) == 0:
            return None

        # Styling for port/transport list
        def ports_stylized(ports: list) -> list[str]:
            temp: list[str] = []
            for port in ports:
                temp.append(f"{port.port}/{port.transport}")
            return temp

        # Grouped list
        grouped = ip.group_ports_by_product()

        services: dict = {}

        # Return a simple port list if no identified ports
        if (
            len(list(grouped.keys())) == 1 and
            list(grouped.keys())[0] == "Other"
        ):
            services["ports"] = ports_stylized(grouped["Other"])
        else:
            # Return grouped display of there are identified ports

            for product, ports in grouped.items():
                services["product"] = product
                services["ports"] = ports_stylized(ports)

        return services

    def _gen_greynoise_details(self, ip: GreynoiseIp) -> dict:

        greynoise: dict = {}
        greynoise["hyperlink"] = ip.link
        greynoise["riot"] = ip.riot
        greynoise["noise"] = ip.noise
        if ip.classification:
            greynoise["classification"] = ip.classification
        else:
            greynoise["classification"] = "?"

        return greynoise

    def _gen_asn_text(
        self,
        asn: Optional[str],
        org: Optional[str],
    ) -> Optional[str]:
        if not asn:
            return None
        return f"{asn} ({org})"

    def _get_ip_enrichment(self, ip: str) -> Optional[Union[IpWhois, ShodanIp]]:
        return self.ip_enrich.root[ip] if ip in self.ip_enrich.root.keys() else None

    def _get_greynoise_enrichment(self, ip: str) -> Optional[GreynoiseIp]:
        return self.greynoise.root[ip] if ip in self.greynoise.root.keys() else None

    def _gen_vt_response(self) -> dict:
        """ Virustotal section. Applies to both domain and IP views """
        attributes = self.entity.data.attributes
        baseurl = self.vt_gui_baseurl_ip if is_ip(self.entity.data.id_) else self.vt_gui_baseurl_domain

        vt: dict = {}
        # Analysis (IP and domain)
        analysis = self._gen_vt_analysis_stats(
            attributes.last_analysis_stats,
            self._vendors_who_flagged_malicious()
        )
        vt["analysis"] = analysis

        analysis_field = f"{baseurl}/{self.entity.data.id_}"
        vt["hyperlink"] = analysis_field

        # Reputation (IP and domain)
        vt["reputation"] = attributes.reputation

        # Popularity (Domain only)
        if hasattr(attributes, "popularity_ranks"):
            popularity = self._gen_vt_popularity(attributes.popularity_ranks)
            if popularity:
                vt["popularity"] = popularity

        # Categories (Domain only)
        if hasattr(attributes, "categories"):
            vt["categories"] = attributes.categories

        # Updated (IP and domain)
        vt["updated"] = datetime.fromtimestamp(attributes.last_modification_date).isoformat()

        # Last seen (Domain only)
        if hasattr(attributes, "last_dns_records_date"):
            vt["last_seen"] = datetime.fromtimestamp(attributes.last_dns_records_date).isoformat()

        return vt

    def _gen_ip_enrich_response(self) -> Optional[dict]:
        """ IP enrichment section. Applies to IP views only """

        enrich = self._get_ip_enrichment(self.entity.data.id_)

        if enrich is None:
            return None
        else:
            enrichment: dict = {}

            if isinstance(enrich, IpWhois):
                # IPWhois
                enrichment["source"] = "IPwhois"
                asn = self._gen_asn_text(enrich.connection.asn, enrich.connection.org)
                enrichment["asn"] = asn
                enrichment["isp"] = enrich.connection.isp
                enrichment["location"] = ", ".join([enrich.city, enrich.region, enrich.country])

            else:
                # Shodan
                enrichment["source"] = "Shodan"
                asn = self._gen_asn_text(enrich.asn, enrich.org)
                enrichment["asn"] = asn
                enrichment["isp"] = enrich.isp

                location: str = enrich.country_name

                if enrich.region_name:
                    location = enrich.region_name + ", " + location

                if enrich.city:
                    location = enrich.city + ", " + location

                enrichment["location"] = location
                enrichment["os"] = enrich.os if enrich.os is not None else "Unknown"
                services = self._gen_shodan_services(enrich)
                if services:
                    enrichment["services"] = services
                enrichment["services_link"] = f"{self.shodan_gui_baseurl}/{self.entity.data.id_}"

                tags = ", ".join(enrich.tags) if enrich.tags else None
                if tags:
                    enrichment["tags"] = tags
                enrichment["last_scan"] = f"{enrich.last_update}+00:00"

            return enrichment

    def _gen_ip_other_response(self) -> Optional[dict]:
        """ Other section for IP views """
        # Greynoise
        greynoise = self._get_greynoise_enrichment(self.entity.data.id_)
        if greynoise:
            other: dict = {}
            other["other"] = (self._gen_greynoise_details(greynoise))
            return other

        return None  # No other data

    def whois_section(self) -> Optional[dict]:
        # Do nothing if no whois
        if self.whois is None:
            return None

        whois: dict = {}
        if self.whois.source == "passivetotal":  # PT
            hyperlink = f"{self.pt_gui_baseurl}/{self.whois.domain}/whois"
            whois["hyperlink"] = hyperlink
        else:  # VT
            hyperlink = None

        if self.whois.domain:
            whois["domain"] = self.whois.domain

        if self.whois.organization:
            whois["org"] = self.whois.organization

        whois["registrar"] = self.whois.registrar
        whois["name"] = self.whois.name
        whois["email"] = self.whois.email
        whois["phone"] = self.whois.phone
        whois["street"] = self.whois.street
        whois["country"] = self.whois.country
        whois["postcode"] = self.whois.postal_code
        whois["nameservers"] = self.whois.name_servers
        whois["dnssec"] = self.whois.dnssec
        whois["registered"] = self.whois.date_created
        whois["updated"] = self.whois.date_changed
        whois["expires"] = self.whois.date_expires

        return whois

    def warnings_section(self) -> Optional[list[str]]:
        return self.warnings
