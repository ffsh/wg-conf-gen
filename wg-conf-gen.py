#!/usr/bin/env python3
import random
import sys
import configparser
import logging
from urllib3.util.retry import Retry

import requests
from requests.adapters import HTTPAdapter
import click

log_format = "%(asctime)s %(levelname)-8s %(message)s"
date_format = "%Y-%m-%d %H:%M:%S"
logging.basicConfig(
    stream=sys.stdout, level=logging.INFO, format=log_format, datefmt=date_format
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

relay_list = []


def ask_mullvad(requested_country, requested_city):
    """Call api for available wireguard gateways with automatic retries"""
    try:
        r = session.get("https://api.mullvad.net/public/relays/wireguard/v1/")
    except Exception as e:
        logger.error("Oh no we encountered an error while calling the mullvad api")
        logger.error(f"This was the error:\n\n {e}\n\n")
        logger.error(
            "Try to run `curl https://api.mullvad.net/public/relays/wireguard/v1/`"
        )
        sys.exit(2)
    mullvad_gateways = r.json()
    for country in mullvad_gateways["countries"]:
        if country["name"] == requested_country:
            for city in country["cities"]:
                if city["name"] == requested_city:
                    return city["relays"]


def get_random_gateway(relay_list):
    """Get randmon gateway from list"""
    max_len = len(relay_list)
    releay_number = random.randrange(0, max_len, 1)
    return relay_list[releay_number]


@click.group()
def cli():
    pass


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
    "--device", default="Unkown", help="You may provide a device name (from mullvad)"
)
def create(country, city, pk, address, file, device):
    """Creates wireguard config, you need to provide your private key and address string"""
    relay_list = ask_mullvad(country, city)
    if relay_list is None:
        logger.error(
            f"Oops could not find any gateway for country: {country} and city: {city}"
        )
        logger.error("Are you sure this combination is valid?")
        sys.exit(1)
    gateway = get_random_gateway(relay_list)
    public_key = gateway["public_key"]
    ipv4_addr = gateway["ipv4_addr_in"]
    hostname = gateway["hostname"]

    config = configparser.ConfigParser(comment_prefixes=None)
    config.optionxform = str
    config["Interface"] = {
        "# Device": device,
        "PrivateKey": pk,
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

    with open(file, "w") as config_file:
        config.write(config_file)


@cli.command()
@click.option(
    "--file",
    default="/etc/wireguard/exit.conf",
    help="The config file, Default: /etc/wireguard/exit.conf",
)
def recreate(file):
    """Regenerates config based on existing config, you only need to provide the config file"""
    logger.info(f"Regenerating {file}")
    config = configparser.ConfigParser(comment_prefixes=None)
    config.optionxform = str

    config.read(file)

    country = config.get("Peer", "# Country")
    city = config.get("Peer", "# City")
    old_hostname = config.get("Peer", "# Hostname")
    
    logger.info(f"Old connection was: {old_hostname}")

    relay_list = ask_mullvad(country, city)
    gateway = get_random_gateway(relay_list)

    public_key = gateway["public_key"]
    ipv4_addr = gateway["ipv4_addr_in"]

    config.set("Peer", "# Hostname", gateway["hostname"])
    config.set("Peer", "PublicKey", public_key)
    config.set("Peer", "Endpoint", f"{ipv4_addr}:51820")

    with open(file, "w") as config_file:
        config.write(config_file)

    logger.info(
        f"Done! Regenerated {file} established connection to {gateway['hostname']}"
    )

    logger.info(
        f"Please restart the wireguard service to apply changes: `systemctl restart wg-quick@exit`"
    )


if __name__ == "__main__":
    cli()
