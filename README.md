# wtfis

`wtfis` is a passive hostname, domain and IP lookup tool for non-robots. With the proper changes, we used `wtfis` as a Python library for integration with Wazuh.

All UI related code is removed from the code to convert this into a library with minimal configuration.

## WTF is it?

**wtfis** is a commandline tool that gathers information about a domain, FQDN or IP address using various OSINT services. Unlike other tools of its kind, it's built specifically for human consumption, providing results that are pretty (YMMV) and easy to read and understand.

This tool assumes that you are using free tier / community level accounts, and so makes as few API calls as possible to minimize hitting quotas and rate limits.

The project name is a play on "whois".

## Data Sources

| Service | Used in lookup | Required | Free Tier |
| --- | --- | --- | --- |
| [Virustotal](https://virustotal.com) | All | Yes | [Yes](https://www.virustotal.com/gui/join-us) |
| [Passivetotal](https://community.riskiq.com) | All | No | [Yes](https://community.riskiq.com/registration/) |
| [IP2Whois](https://www.ip2whois.com) | Domain/FQDN | No | [Yes](https://www.ip2location.io/pricing#ip2whois) |
| [IPWhois](https://ipwhois.io) | IP address | No | Yes (no signup) |
| [Shodan](https://shodan.io) | IP address | No | [No](https://account.shodan.io/billing) |
| [Greynoise](https://greynoise.io) | IP address | No | [Yes](https://www.greynoise.io/plans/community) |

### Virustotal

The primary source of information. Retrieves:

* [Hostname (FQDN), domain or IP](https://developers.virustotal.com/reference/domains-1)
  * Latest analysis stats with vendor detail
  * Reputation score (based on VT community votes)
  * Popularity ranks (Alexa, Cisco Umbrella, etc.) (FQDN and domain only)
  * Categories (assigned by different vendors)
* [Resolutions](https://developers.virustotal.com/reference/domain-resolutions) (FQDN and domain only)
  * Last n IP addresses (default: 3, max: 10)
  * Latest analysis stats of each IP above
* [Whois](https://developers.virustotal.com/reference/whois)
  * Fallback only: if Passivetotal creds are not available
  * Various whois data about the domain itself

### Passivetotal (RiskIQ)

Optionally used if creds are provided. Retrieves:

* [Whois](https://api.riskiq.net/api/whois_pt/)
  * Various whois data about the domain itself

Passivetotal is recommended over Virustotal for whois data for a couple of reasons:

* VT whois data format is less consistent
* PT whois data tends to be of better quality than VT. Also, VT's registrant data is apparently [anonymized](https://developers.virustotal.com/reference/whois).
* You can save one VT API call by offloading to PT

### IP2Whois

Optionally used if creds are provided and Passivetotal creds are not supplied. (i.e. second in line for Whois information)

* [Whois](https://www.ip2location.io/ip2whois-documentation)
  * Various whois data about the domain itself

As above, IP2Whois is recommended over Virustotal if a Passivetotal account cannot be obtained.

### IPWhois

Default enrichment for IP addresses. Retrieves:

* ASN, Org, ISP and Geolocation

IPWhois should not be confused with IP2Whois, which provides domain Whois data.

### Shodan

Alternative IP address enrichment source. GETs data from the `/shodan/host/{ip}` endpoint (see [doc](https://developer.shodan.io/api)). For each IP, retrieves:

* ASN, Org, ISP and Geolocation
* List of open ports and services
* Operating system (if available)
* Tags (assigned by Shodan)

### Greynoise

Supplementary IP address enrichment source. Using its [community API](https://docs.greynoise.io/docs/using-the-greynoise-community-api), wtfis will show whether an IP is in one of Greynoise's datasets:

* **Noise**: IP has been seen regularly scanning the Internet
* **RIOT**: IP belongs to a common business application (e.g. Microsoft O365, Google Workspace, Slack)

More information about the datasets [here](https://docs.greynoise.io/docs/understanding-greynoise-data-sets).

In addition, the API also returns Greynoise's [classification](https://docs.greynoise.io/docs/understanding-greynoise-classifications) of an IP (if available). Possible values are **benign**, **malicious**, and **unknown**.

## Install

Download the repostiory, and move the `wtfis` directory to somewhere importable from your project.

## Usage

wtfis uses these variables for integration:

* Virustotal API key (required)
* Passivetotal API key (optional)
* Passivetotal API user (optional)
* IP2WHOIS API key (optional)
* Shodan API key (optional)
* Greynoise API key (optional)
* Default arguments (optional)

First, populate the `Config` instance. Sample code uses environment variables, but you can use any method you would like.

```python
    # Populate configuration from envronment variables
    config: Config = Config(
        vt_api_key=os.environ["VT_API_KEY"],
        shodan_api_key=os.environ.get("SHODAN_API_KEY"),
        pt_api_user=os.environ.get("PT_API_USER"),
        pt_api_key=os.environ.get("PT_API_KEY"),
        ip2whois_api_key=os.environ.get("IP2WHOIS_API_KEY"),
        greynoise_api_key=os.environ.get("GREYNOISE_API_KEY"))
```

Then, pass the configuration and target FQDN, domain or IP to `Resolver`:

```python
    # Initiate resolver
    resolver = Resolver(target, config)

    # Fetch data
    resolver.fetch()

    # Get result as a formatted, indented JSON string
    result = resolver.export()
```

Defanged input is accepted (e.g. `api[.]google[.]com`).

Sample response for target IP address 185.56.83.82:

```json
{
    "ip": {
        "enrichment": {
            "asn": "AS211720 (Datashield, Inc.)",
            "isp": "Datashield, Inc.",
            "last_scan": "2024-01-22T22:31:01.667263+00:00",
            "location": "Zürich, Switzerland",
            "os": "Unknown",
            "services": {
                "ports": [
                    "443/tcp"
                ]
            },
            "shodan_link": "https://www.shodan.io/host/185.56.83.82",
            "source": "Shodan"
        },
        "other": {
            "greynoise_enrichment": {
                "classification": "unknown",
                "hyperlink": "https://viz.greynoise.io/ip/185.56.83.82",
                "noise": true,
                "riot": false
            }
        },
        "virustotal": {
            "analysis": {
                "vendors": [
                    "Antiy-AVL",
                    "BitDefender",
                    "Fortinet",
                    "G-Data",
                    "Lionic",
                    "MalwareURL",
                    "SOCRadar",
                    "Webroot"
                ],
                "vendors_who_flagged_malicious": "8/90"
            },
            "hyperlink": "https://virustotal.com/gui/ip-address/185.56.83.82",
            "reputation": -1,
            "updated": "2024-02-19T03:47:52"
        }
    },
    "warnings": [],
    "whois": {
        "country": null,
        "dnssec": null,
        "domain": "185.56.83.0",
        "email": "abuse@xor.sc",
        "expires": null,
        "hyperlink": "https://community.riskiq.com/search/185.56.83.0/whois",
        "name": "DATASHIELD-MNT",
        "org": "DATASHIELD-MNT",
        "phone": null,
        "postcode": null,
        "registered": "2021-02-27T00:41:04.000-08:00",
        "registrar": "RIPE",
        "street": null,
        "updated": "2021-03-30T14:36:49.000-07:00"
    }
}
```

### Shodan enrichment

Shodan can be used to enrich the IP addresses (instead of IPWhois) when a Shodan API key is provided.

### Greynoise enrichment

To enable Greynoise, provide a Greynoise API key. Because the API quota is quite low (50 requests per week as of March 2023), this lookup is off by default.

## Notes

When automated, the requests for the same FQDN, domain name or IP address can be sent multiple times which will fill the daily quota earlier than expected. It is suggested to use a persistent, disk-based cache to preserve known results.

## Demo

The demo project shows how to use `wtfis` as a library with `diskcache` for persistent cache.
