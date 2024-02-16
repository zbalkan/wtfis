"""
Logic handler for IP address inputs
"""
from wtfis.handlers.base import BaseHandler, common_exception_handler


class IpAddressHandler(BaseHandler):
    @common_exception_handler
    def _fetch_vt_ip_address(self) -> None:
        self.vt_info = self._vt.get_ip_address(self.entity)

    def fetch_data(self) -> None:
        print("Fetching data from Virustotal")
        self._fetch_vt_ip_address()

        print(f"Fetching IP enrichments from {self._enricher.name}")
        self._fetch_ip_enrichments(self.entity)

        if self._greynoise:
            print(f"Fetching IP enrichments from {self._greynoise.name}")
            self._fetch_greynoise(self.entity)

        print(f"Fetching IP whois from {self._whois.name}")
        self._fetch_whois()

