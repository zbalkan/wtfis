#!/usr/bin/env python3

import json
import os
import sys
import time
from socket import AF_UNIX, SOCK_DGRAM, socket
from typing import Optional

ENCODING: str = "utf-8"
CACHE_PATH: str = "/tmp/wtfis"


# Global vars
debug_enabled = False
ossec_dir: str = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert: dict = {}
now: str = time.strftime("%a %b %d %H:%M:%S %Z %Y")

# Set paths
log_file = '{0}/logs/integrations.log'.format(ossec_dir)
socket_addr = '{0}/queue/sockets/queue'.format(ossec_dir)

# Change working directory
os.chdir('/var/ossec/integrations')


def __debug(msg: str) -> None:
    # if debug_enabled:
    debug_log: str = f"{now}: {msg}\n"
    print(debug_log)
    with open(log_file, "a", encoding=ENCODING) as log_file_stream:
        log_file_stream.write(debug_log)


try:
    import diskcache
except ImportError:
    __debug("No module 'diskcache' found. Install: pip install diskcache")
    sys.exit(1)

try:
    __debug(f"working_dir: {os.getcwd()}")
    __debug(f"ossec_dir: {ossec_dir}")

    from wtfis.config import Config
    from wtfis.internal.utils import is_private
    from wtfis.resolver import Resolver
except ImportError:
    __debug("No module 'wtfis' found. Solve the dependency issues first.")
    sys.exit(1)


def __send_event(msg: str, agent: Optional[dict] = None) -> None:
    if not agent or agent["id"] == "000":
        string = '1:wtfis:{0}'.format(msg)
    else:
        string = '1:[{0}] ({1}) {2}->wtfis:{3}'.format(agent["id"], agent["name"],
                                                       agent["ip"] if "ip" in agent else "any", msg)
    __debug(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()


def __query_with_cache(target: str, config: Config, cache_dir: str = './') -> Optional[dict]:

    # Check if private IP or not
    if is_private(target=target):
        __debug(f"The target IP is in private range: {target}")
        return None

    # Create path for cache if not exists
    if os.path.exists(cache_dir) is False:
        os.makedirs(cache_dir, 0o700)

    __debug("Opening cache")
    with diskcache.Cache(directory=cache_dir) as cache:

        # Enable stats if not enabled on the first run
        cache.stats(enable=True)
        # Expire old items first
        cache.expire()

        __debug("Checking cache")
        cache_result: Optional[str] = cache.get(target)  # type: ignore

        if cache_result:
            __debug("Found the value in cache")
            return dict(json.loads(cache_result))

        else:
            __debug("Cache miss. Querying APIs...")

            # Initiate resolver
            resolver = Resolver(target, config)

            # Fetch data
            resolver.fetch()

            # Get result
            export = resolver.export()

            if export:
                __debug("Adding the response to cache")
                cache.add(target, json.dumps(export, sort_keys=True))
            else:
                return None


def __parse_api_keys(apikeys: str) -> dict[str, tuple[str, str]]:
    ''' Parse single line API keys variable into a dict per provider'''
    keys: list[str] = apikeys.split('|')
    key_store: dict[str, tuple[str, str]] = {}
    for k in keys:
        values: list[str] = k.split(':')
        provider: str = values[0]
        user: str = values[1]
        apikey: str = values[2]
        key_store[provider] = user, apikey
    return key_store


def main(args) -> None:
    __debug("# Starting")
    # Read args
    alert_file_location = args[1]
    api_keys = str(args[2])
    __debug(
        "# API Keys: the format is <provider 1>:<user>:<api key>|<provider 2>:<user>:<api key>")
    __debug("# The user field can be empty but should not be skipped.")
    __debug(api_keys)

    __debug("# File location")
    __debug(alert_file_location)
    # Load alert. Parse JSON object.
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)
    __debug("# Processing alert")

    __debug(json.dumps(json_alert,
                       indent=4,
                       sort_keys=True,
                       ensure_ascii=False).encode('utf8').decode())

    # We get the data from firewall and it is always Layer 3: IP Address
    target: str = json_alert["data"]["srcip"]

    # Fill in the config:
    key_store: dict[str, tuple[str, str]] = __parse_api_keys(api_keys)

    if key_store.get('vt', None) is None:
        __debug("Virustotal API key does not exist. Exiting...")
        exit(1)

    config = Config(key_store['vt'][1],
                    key_store['shodan'][1] if key_store.get(
                        'shodan') is not None else None,
                    key_store['pt'][0] if key_store.get(
                        'pt') is not None else None,
                    key_store['pt'][1] if key_store.get(
                        'pt') is not None else None,
                    key_store['ip2w'][1] if key_store.get(
                        'ip2w') is not None else None,
                    key_store['greynoise'][1] if key_store.get('greynoise') is not None else None)

    # Query
    __debug("# Querying...")
    response: Optional[dict] = __query_with_cache(target, config, CACHE_PATH)

    # If positive match, send event to Wazuh Manager
    if response:
        __debug("# Result found.")

        response["wtfis"]["ip"]["address"] = json_alert["data"]["srcip"]
        response["wtfis"]["triggered_by"] = json_alert["rule"]["description"]

        json_str: str = json.dumps(response,
                                   indent=4,
                                   sort_keys=True,
                                   ensure_ascii=False).encode('utf8').decode()

        __send_event(json_str, json_alert["agent"])
        __debug(json_str)
    else:
        __debug("# No response.")


if __name__ == "__main__":
    try:
        # Read arguments
        bad_arguments = False
        if len(sys.argv) >= 4:
            log_msg = '{0} {1} {2} {3} {4}'.format(
                now,
                sys.argv[1],
                sys.argv[2],
                sys.argv[3],
                sys.argv[4] if len(sys.argv) > 4 else ''
            )
            debug_enabled = (len(sys.argv) > 4 and sys.argv[4] == 'debug')
        else:
            log_msg = '{0} Wrong arguments'.format(now)
            bad_arguments = True

        # Logging the call
        with open(log_file, 'a', encoding=ENCODING) as f:
            f.write(log_msg + '\n')

        if bad_arguments:
            __debug("# Exiting: Bad arguments.")
            sys.exit(1)

        # Main function
        main(sys.argv)
    except Exception as e:
        __debug(str(e))
        raise
