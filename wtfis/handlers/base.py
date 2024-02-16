import abc
from typing import Callable, List, Optional, Union

from pydantic import ValidationError
from requests.exceptions import (ConnectionError, HTTPError, JSONDecodeError,
                                 RequestException, Timeout)
from shodan.exception import APIError

from wtfis.clients.greynoise import GreynoiseClient
from wtfis.clients.ip2whois import Ip2WhoisClient
from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.passivetotal import PTClient
from wtfis.clients.shodan import ShodanClient
from wtfis.clients.virustotal import VTClient
from wtfis.models.common import WhoisBase
from wtfis.models.greynoise import GreynoiseIpMap
from wtfis.models.ipwhois import IpWhoisMap
from wtfis.models.shodan import ShodanIpMap
from wtfis.models.virustotal import Domain, IpAddress
from wtfis.utils import error_and_exit, refang


def common_exception_handler(func: Callable) -> Callable:
    """ Decorator for handling common fetch errors """
    def inner(*args, **kwargs) -> None:
        try:
            func(*args, **kwargs)
        except (APIError, ConnectionError, HTTPError, JSONDecodeError, Timeout) as e:
            error_and_exit(f"Error fetching data: {e}")
        except ValidationError as e:
            error_and_exit(f"Data model validation error: {e}")
    return inner


def failopen_exception_handler(client_attr_name: str) -> Callable:
    """ Decorator for handling calls that can fail open """
    def inner(func):
        def wrapper(*args, **kwargs) -> None:
            # Client obj who made the call
            client = getattr(args[0], client_attr_name)
            warnings: List[str] = args[0].warnings
            try:
                func(*args, **kwargs)
            except (APIError, RequestException) as e:
                # Add warning
                warnings.append(f"Could not fetch {client.name}: {e}")
        return wrapper
    return inner


class BaseHandler(abc.ABC):
    def __init__(
        self,
        entity: str,
        vt_client: VTClient,
        ip_enricher_client: Union[IpWhoisClient, ShodanClient],
        whois_client: Union[Ip2WhoisClient, PTClient, VTClient],
        greynoise_client: Optional[GreynoiseClient],
    ) -> None:
        # Process-specific
        self.entity = refang(entity)

        # Clients
        self._vt = vt_client
        self._enricher = ip_enricher_client
        self._whois = whois_client
        self._greynoise = greynoise_client

        # Dataset containers
        self.vt_info: Union[Domain, IpAddress]
        self.ip_enrich: Union[IpWhoisMap, ShodanIpMap] = IpWhoisMap.empty()
        self.whois: WhoisBase
        self.greynoise: GreynoiseIpMap = GreynoiseIpMap.empty()

        # Warning messages container
        self.warnings: List[str] = []

    @abc.abstractmethod
    def fetch_data(self) -> None:
        """ Main method that controls what get fetched """
        return NotImplemented  # type: ignore  # pragma: no coverage

    @common_exception_handler
    @failopen_exception_handler("_enricher")
    def _fetch_ip_enrichments(self, ips: list[str]) -> None:
        self.ip_enrich = self._enricher.enrich_ips(ips)

    @common_exception_handler
    @failopen_exception_handler("_greynoise")
    def _fetch_greynoise(self, ips: list[str]) -> None:
        # Let continue if rate limited
        try:
            if self._greynoise:
                self.greynoise = self._greynoise.enrich_ips(ips)
        except HTTPError as e:
            if e.response.status_code == 429:
                self.warnings.append(f"Could not fetch Greynoise: {e}")
            else:
                raise

    @common_exception_handler
    def _fetch_whois(self) -> None:
        # Let continue if rate limited
        try:
            self.whois = self._whois.get_whois(self.entity)
        except HTTPError as e:
            if e.response.status_code == 429:
                self.warnings.append(f"Could not fetch Whois: {e}")
            else:
                raise
