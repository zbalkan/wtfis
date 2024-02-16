#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from wtfis.config import Config
from wtfis.result.resolver import Resolver
from wtfis.utils import error_and_exit

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
                error = error + f"\nEnv file {DEFAULT_ENV_FILE} was not found either. Did you forget?"
            error_and_exit(error)


def main() -> None:

    # Pass the IP address
    target:str = "142.171.193.6"
    # target: str = "indyjoy.com"
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

    # Initiate resolver
    resolver = Resolver(target, config)

    # Fetch data
    resolver.fetch()

    # Get result
    result: str = resolver.export()
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
                            level=logging.INFO)

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
