"""
Logic handler for IP address inputs
"""
from wtfis.internal.handlers.base import BaseHandler, common_exception_handler


class IpAddressHandler(BaseHandler):
    @common_exception_handler
    def _fetch_vt_ip_address(self) -> None:
        self.vt_info = self._vt.get_ip_address(self.entity)

    def fetch_data(self) -> None:
        self._fetch_vt_ip_address()

        if isinstance(self.entity, str):
            self._fetch_ip_enrichments([self.entity])
        elif isinstance(self.entity, list):
            self._fetch_ip_enrichments(self.entity)
        else:
            raise Exception("Unknown IP format")

        if self._greynoise:
            if isinstance(self.entity, str):
                self._fetch_greynoise([self.entity])
            elif isinstance(self.entity, list):
                self._fetch_greynoise(self.entity)
            else:
                raise Exception("Unknown IP format")

        self._fetch_whois()
