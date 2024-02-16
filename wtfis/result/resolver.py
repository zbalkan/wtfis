from wtfis.handlers.base import BaseHandler
from wtfis.handlers.domain import DomainHandler
from wtfis.handlers.ip import IpAddressHandler
from wtfis.models.virustotal import Domain, IpAddress
from wtfis.result.result import DomainResult, IpAddressResult


class Resolver:
    entity:BaseHandler

    def __init__(self, entity:BaseHandler) -> None:
        self.entity = entity

    def resolve(self) -> str:
        if isinstance(self.entity, DomainHandler) and isinstance(self.entity.vt_info, Domain):
           return str(DomainResult(
               entity=self.entity.vt_info,
               resolutions=self.entity.resolutions,
               whois=self.entity.whois,
               ip_enrich=self.entity.ip_enrich,
               greynoise=self.entity.greynoise))
        elif isinstance(self.entity, IpAddressHandler) and isinstance(self.entity.vt_info, IpAddress):
            return str(IpAddressResult(
               entity=self.entity.vt_info,
               whois=self.entity.whois,
               ip_enrich=self.entity.ip_enrich,
               greynoise=self.entity.greynoise))
        else:
            return ""