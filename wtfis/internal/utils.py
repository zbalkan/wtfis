import sys
from ipaddress import ip_address
from typing import NoReturn


def error_and_exit(message: str, status: int = 1) -> NoReturn:
    print(message, file=sys.stderr)
    raise SystemExit(status)


def refang(text: str) -> str:
    """ Strip []s out of text """
    return text.replace("[", "").replace("]", "")


def is_ip(target: str) -> bool:
    """ Detect whether text is IPv4 or not """
    try:
        return ip_address(refang(target)).is_global
    except ValueError:
        return False


def is_private(target: str) -> bool:
    """ Detect whether text is private IPv4 address or not """
    try:
        return ip_address(target).is_private
    except ValueError:
        return False
