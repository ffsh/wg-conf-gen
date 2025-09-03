#!/usr/bin/env python3
"""
WireGuard configuration generator for Mullvad VPN.

This module provides functionality to create and recreate WireGuard configurations
using Mullvad's API to select random gateways for improved privacy.
"""
import configparser
import logging
import random
import sys
from urllib3.util.retry import Retry

import click
import requests
from requests.adapters import HTTPAdapter

LOG_FORMAT = "%(asctime)s %(levelname)-8s %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
logging.basicConfig(
    stream=sys.stdout, level=logging.INFO, format=LOG_FORMAT, datefmt=DATE_FORMAT
)
logger = logging.getLogger(__name__)

retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET"],
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session = requests.Session()
session.mount("http://", adapter)
session.mount("https://", adapter)


def ask_mullvad(requested_country, requested_city):
    """Call api for available wireguard gateways with automatic retries"""
    try:
        response = session.get("https://api.mullvad.net/public/relays/wireguard/v1/")
    except requests.RequestException as exception:
        logger.error("Oh no we encountered an error while calling the mullvad api")
        logger.error("This was the error:\n\n %s\n\n", exception)
        logger.error(
            "Try to run `curl https://api.mullvad.net/public/relays/wireguard/v1/`"
        )
        sys.exit(2)
    mullvad_gateways = response.json()
    for country in mullvad_gateways["countries"]:
        if country["name"] == requested_country:
            for city in country["cities"]:
                if city["name"] == requested_city:
                    return city["relays"]
    return None


def get_random_gateway(available_relays):
    """Get random gateway from list"""
    max_len = len(available_relays)
    relay_number = random.randrange(0, max_len, 1)
    return available_relays[relay_number]


@click.group()
def cli():
    """WireGuard configuration generator CLI."""


@cli.command()
@click.option("--pk", help="Your private key.", required=True)
@click.option("--address", help="Your VPN address", required=True)
@click.option(
    "--country", default="Netherlands", help="Location: country, Default: Netherlands"
)
@click.option("--city", default="Amsterdam", help="Location: city, Default: Amsterdam")
@click.option(
    "--file",
    default="/etc/wireguard/exit.conf",
    help="The config file, Default: /etc/wireguard/exit.conf",
)
@click.option(
    "--device", default="Unknown", help="You may provide a device name (from mullvad)"
)
def create(**kwargs):
    """Creates wireguard config, you need to provide your private key and address string"""
    country = kwargs['country']
    city = kwargs['city']
    private_key = kwargs['pk']
    address = kwargs['address']
    config_file = kwargs['file']
    device = kwargs['device']

    available_relays = ask_mullvad(country, city)
    if available_relays is None:
        logger.error(
            "Oops could not find any gateway for country: %s and city: %s",
            country, city
        )
        logger.error("Are you sure this combination is valid?")
        sys.exit(1)
    gateway = get_random_gateway(available_relays)
    public_key = gateway["public_key"]
    ipv4_addr = gateway["ipv4_addr_in"]
    hostname = gateway["hostname"]

    config = configparser.ConfigParser(comment_prefixes=None)
    config.optionxform = str
    config["Interface"] = {
        "# Device": device,
        "PrivateKey": private_key,
        "Address": address,
        "DNS": "10.64.0.1",
        "Table": "42",
        "PostUp": "ip -4 route add 10.64.0.1 dev exit & ip -4 route add 193.138.218.74 dev exit",
    }
    config["Peer"] = {
        "# Country": country,
        "# City": city,
        "# Hostname": hostname,
        "PublicKey": public_key,
        "AllowedIPs": "0.0.0.0/0,::0/0",
        "Endpoint": f"{ipv4_addr}:51820",
    }

    with open(config_file, "w", encoding="utf-8") as config_file_handle:
        config.write(config_file_handle)


@cli.command()
@click.option(
    "--file",
    default="/etc/wireguard/exit.conf",
    help="The config file, Default: /etc/wireguard/exit.conf",
)
def recreate(file):
    """Regenerates config based on existing config, you only need to provide the config file"""
    logger.info("Regenerating %s", file)
    config = configparser.ConfigParser(comment_prefixes=None)
    config.optionxform = str

    config.read(file)

    country = config.get("Peer", "# Country")
    city = config.get("Peer", "# City")
    old_hostname = config.get("Peer", "# Hostname")

    logger.info("Old connection was: %s", old_hostname)

    available_relays = ask_mullvad(country, city)
    gateway = get_random_gateway(available_relays)

    public_key = gateway["public_key"]
    ipv4_addr = gateway["ipv4_addr_in"]

    config.set("Peer", "# Hostname", gateway["hostname"])
    config.set("Peer", "PublicKey", public_key)
    config.set("Peer", "Endpoint", f"{ipv4_addr}:51820")

    with open(file, "w", encoding="utf-8") as config_file:
        config.write(config_file)

    logger.info(
        "Done! Regenerated %s established connection to %s",
        file, gateway['hostname']
    )

    logger.info(
        "Please restart the wireguard service to apply changes: "
        "`systemctl restart wg-quick@exit`"
    )


if __name__ == "__main__":
    cli()
