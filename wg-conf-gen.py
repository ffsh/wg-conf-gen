import requests
import pprint
import random
import click

relay_list = []

def ask_mullvad(requested_country, requested_city):
    """Call api for available wireguard gateways"""
    r = requests.get("https://api.mullvad.net/public/relays/wireguard/v1/")
    mullvad_gateways = r.json()
    for country in mullvad_gateways["countries"]:
        if country["name"] == requested_country:
            for city in country["cities"]:
                if city["name"] == requested_city:
                    return city["relays"]

def get_random_gateway(relay_list):
    """Get randmon gateway from list"""
    max_len = len(relay_list)
    releay_number = random.randrange(0,max_len,1)
    return relay_list[releay_number]

@click.command()
@click.option('--pk', help='Your private key.', required=True)
@click.option('--address', help='Your VPN address', required=True)
@click.option('--country', default="Netherlands", help='Location: country, Default: Netherlands')
@click.option('--city', default="Amsterdam", help='Location: city, Default: Amsterdam')
@click.option('--file', default="/etc/wireguard/exit.conf", help='The config file, Default: /etc/wireguard/exit.conf')
@click.option('--device', default="Unkown", help='You may provide a device name (from mullvad)')
def create(country, city, pk, address, file, device):
    """Creates wireguard config, you need to provide your private key and address string"""
    relay_list = ask_mullvad(country, city)
    gateway = get_random_gateway(relay_list)
    public_key = gateway["public_key"]
    ipv4_addr = gateway["ipv4_addr_in"]
    config = f"""[Interface]
# Device: {device}
PrivateKey = {pk}
Address = {address}
DNS = 10.64.0.1
Table = 42
PostUp = ip -4 route add 10.64.0.1 dev exit & ip -4 route add 193.138.218.74 dev exit

[Peer]
PublicKey = {public_key}
AllowedIPs = 0.0.0.0/0,::0/0
Endpoint = {ipv4_addr}:51820
"""
    with open(file, "w") as config_file:
        config_file.write(config)

if __name__ == '__main__':
    create()