from typing import Optional


class Config:
    vt_api_key: str
    shodan_api_key: Optional[str]
    pt_api_user: Optional[str]
    pt_api_key: Optional[str]
    ip2whois_api_key: Optional[str]
    greynoise_api_key: Optional[str]

    def __init__(self, vt_api_key: str,
                 shodan_api_key: Optional[str] = None,
                 pt_api_user: Optional[str] = None,
                 pt_api_key: Optional[str] = None,
                 ip2whois_api_key: Optional[str] = None,
                 greynoise_api_key: Optional[str] = None) -> None:

        self.vt_api_key = vt_api_key
        self.shodan_api_key = shodan_api_key
        self.pt_api_user = pt_api_user
        self.pt_api_key = pt_api_key
        self.ip2whois_api_key = ip2whois_api_key
        self.greynoise_api_key = greynoise_api_key
