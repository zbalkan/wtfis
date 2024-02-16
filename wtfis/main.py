#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import sys
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

from wtfis.internal.config import Config
from wtfis.internal.resolver import Resolver
from wtfis.internal.utils import error_and_exit, is_private

try:
    import diskcache
except Exception as e:
    print("No module 'diskcache' found. Install: pip3 install diskcache")
    sys.exit(1)

APP_NAME: str = 'wtfis'
APP_VERSION: str = '0.7.1'


def parse_env() -> None:
    DEFAULT_ENV_FILE = Path().home() / ".env.wtfis"

    # Load the file
    load_dotenv(DEFAULT_ENV_FILE)

    # Exit if required environment variables don't exist
    for envvar in (
        "VT_API_KEY",
    ):
        if not os.environ.get(envvar):
            error = f"Error: Environment variable {envvar} not set"
            if not DEFAULT_ENV_FILE.exists():
                error = error + \
                    f"\nEnv file {DEFAULT_ENV_FILE} was not found either. Did you forget?"
            error_and_exit(error)


def query_with_cache(target: str, config: Config, cache_dir: str = './') -> str:
    logging.debug("Opening cache")
    with diskcache.Cache(directory=cache_dir) as cache:

        # Enable stats if not enabled on the first run
        cache.stats(enable=True)
        # Expire old items first
        cache.expire()

        logging.debug("Checking cache")
        result: Optional[str] = cache.get(target)  # type: ignore

        if result:
            logging.debug("Found the value in cache")
        else:
            logging.debug("Cache miss. Querying APIs...")

            # Initiate resolver
            resolver = Resolver(target, config)

            # Fetch data
            resolver.fetch()

            # Get result
            result = resolver.export()

            if result:
                logging.debug("Adding the response to cache")
                cache.add(target, result)
            else:
                result = "No result"
        return result


def main() -> None:

    # Pass the IP address
    # target: str = "118.43.68.218"
    # target: str = "trivat.fun"
    target: str = "192.168.0.25"

    # Check if private IP or not
    if is_private(target=target):
        logging.info(f"The target IP is in private range: {target}")
        return

    # Load environment variables
    parse_env()

    # Populate configuration
    config: Config = Config(
        vt_api_key=os.environ["VT_API_KEY"],
        shodan_api_key=os.environ.get("SHODAN_API_KEY"),
        pt_api_user=os.environ.get("PT_API_USER"),
        pt_api_key=os.environ.get("PT_API_KEY"),
        ip2whois_api_key=os.environ.get("IP2WHOIS_API_KEY"),
        greynoise_api_key=os.environ.get("GREYNOISE_API_KEY"))

    logging.info("Querying..")
    result: str = query_with_cache(
        target=target, config=config, cache_dir=get_root_dir())

    logging.info("Printing the result...")
    print(result)

    print("Completed.")


def get_root_dir() -> str:
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    elif __file__:
        return os.path.dirname(__file__)
    else:
        return './'


if __name__ == "__main__":
    try:
        logging.basicConfig(filename=os.path.join(get_root_dir(), f'{APP_NAME}.log'),
                            encoding='utf-8',
                            format='%(asctime)s:%(levelname)s:%(message)s',
                            datefmt="%Y-%m-%dT%H:%M:%S%z",
                            level=logging.DEBUG)

        excepthook = logging.error
        logging.info('Starting')
        main()
        logging.info('Exiting.')
    except KeyboardInterrupt:
        logging.warning('Cancelled by user.')
        logging.info('Exiting.')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
    except Exception as ex:
        logging.error('ERROR: ' + str(ex))
        logging.info('Exiting.')
        try:
            sys.exit(1)
        except SystemExit:
            os._exit(1)
