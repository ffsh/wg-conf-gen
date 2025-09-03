#!/usr/bin/env python3
"""
Tests for WireGuard configuration generator.
"""
import configparser
import importlib.util
import os
import tempfile
from unittest.mock import Mock, patch

import pytest
import requests
from click.testing import CliRunner

# Import the module under test
spec = importlib.util.spec_from_file_location("wg_conf_gen", "wg-conf-gen.py")
wg_conf_gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wg_conf_gen)

# Extract the functions we need to test
ask_mullvad = wg_conf_gen.ask_mullvad
get_random_gateway = wg_conf_gen.get_random_gateway
cli = wg_conf_gen.cli


class TestAskMullvad:
    """Tests for the ask_mullvad function."""

    def test_ask_mullvad_success(self):
        """Test successful API call and gateway retrieval."""
        # Mock API response
        mock_response = Mock()
        mock_response.json.return_value = {
            "countries": [
                {
                    "name": "Netherlands",
                    "cities": [
                        {
                            "name": "Amsterdam",
                            "relays": [
                                {
                                    "hostname": "nl-ams-wg-001",
                                    "public_key": "test_public_key_1",
                                    "ipv4_addr_in": "185.213.154.68"
                                },
                                {
                                    "hostname": "nl-ams-wg-002",
                                    "public_key": "test_public_key_2",
                                    "ipv4_addr_in": "185.213.154.69"
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        with patch.object(wg_conf_gen.session, 'get', return_value=mock_response):
            # Test the function
            result = ask_mullvad("Netherlands", "Amsterdam")

            # Assertions
            assert result is not None
            assert len(result) == 2
            assert result[0]["hostname"] == "nl-ams-wg-001"

    def test_ask_mullvad_country_not_found(self):
        """Test when requested country is not found."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "countries": [
                {
                    "name": "Germany",
                    "cities": [{"name": "Berlin", "relays": []}]
                }
            ]
        }

        with patch.object(wg_conf_gen.session, 'get', return_value=mock_response):
            result = ask_mullvad("Netherlands", "Amsterdam")
            assert result is None

    def test_ask_mullvad_city_not_found(self):
        """Test when requested city is not found."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "countries": [
                {
                    "name": "Netherlands",
                    "cities": [{"name": "Rotterdam", "relays": []}]
                }
            ]
        }

        with patch.object(wg_conf_gen.session, 'get', return_value=mock_response):
            result = ask_mullvad("Netherlands", "Amsterdam")
            assert result is None

    def test_ask_mullvad_request_exception(self):
        """Test handling of request exceptions."""
        with patch.object(wg_conf_gen.session, 'get',
                         side_effect=requests.RequestException("Connection error")):
            with pytest.raises(SystemExit) as exc_info:
                ask_mullvad("Netherlands", "Amsterdam")
            assert exc_info.value.code == 2


class TestGetRandomGateway:
    """Tests for the get_random_gateway function."""

    def test_get_random_gateway_single_relay(self):
        """Test selecting from a single relay."""
        relays = [
            {
                "hostname": "nl-ams-wg-001",
                "public_key": "test_key",
                "ipv4_addr_in": "185.213.154.68"
            }
        ]

        result = get_random_gateway(relays)
        assert result == relays[0]

    def test_get_random_gateway_multiple_relays(self):
        """Test selecting from multiple relays."""
        relays = [
            {"hostname": "nl-ams-wg-001", "public_key": "key1", "ipv4_addr_in": "1.1.1.1"},
            {"hostname": "nl-ams-wg-002", "public_key": "key2", "ipv4_addr_in": "2.2.2.2"},
            {"hostname": "nl-ams-wg-003", "public_key": "key3", "ipv4_addr_in": "3.3.3.3"}
        ]

        # Mock random to return index 1
        with patch.object(wg_conf_gen.random, 'randrange', return_value=1):
            result = get_random_gateway(relays)
            assert result == relays[1]

    def test_get_random_gateway_empty_list(self):
        """Test handling of empty relay list."""
        with pytest.raises(ValueError):
            get_random_gateway([])


class TestCreateCommand:
    """Tests for the create CLI command."""

    def test_create_command_success(self):
        """Test successful config creation."""
        mock_relays = [
            {
                "hostname": "nl-ams-wg-001",
                "public_key": "test_public_key",
                "ipv4_addr_in": "185.213.154.68"
            }
        ]

        # Setup mocks
        with patch.object(wg_conf_gen, 'ask_mullvad', return_value=mock_relays):
            with patch.object(wg_conf_gen, 'get_random_gateway', return_value=mock_relays[0]):
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                    temp_path = temp_file.name

                try:
                    runner = CliRunner()
                    result = runner.invoke(cli, [
                        'create',
                        '--pk', 'test_private_key',
                        '--address', '10.65.123.45/32',
                        '--country', 'Netherlands',
                        '--city', 'Amsterdam',
                        '--file', temp_path,
                        '--device', 'TestDevice'
                    ])

                    assert result.exit_code == 0

                    # Verify config file was created and has correct content
                    config = configparser.ConfigParser(comment_prefixes=None)
                    config.optionxform = str
                    config.read(temp_path)

                    assert config.get('Interface', 'PrivateKey') == 'test_private_key'
                    assert config.get('Interface', 'Address') == '10.65.123.45/32'
                    assert config.get('Interface', '# Device') == 'TestDevice'
                    assert config.get('Peer', 'PublicKey') == 'test_public_key'
                    assert config.get('Peer', '# Country') == 'Netherlands'
                    assert config.get('Peer', '# City') == 'Amsterdam'
                    assert config.get('Peer', '# Hostname') == 'nl-ams-wg-001'
                    assert config.get('Peer', 'Endpoint') == '185.213.154.68:51820'

                finally:
                    os.unlink(temp_path)

    def test_create_command_no_relays_found(self):
        """Test create command when no relays are found."""
        with patch.object(wg_conf_gen, 'ask_mullvad', return_value=None):
            runner = CliRunner()
            result = runner.invoke(cli, [
                'create',
                '--pk', 'test_private_key',
                '--address', '10.65.123.45/32',
                '--country', 'InvalidCountry',
                '--city', 'InvalidCity'
            ])

            # Click catches the sys.exit and converts it to the exit code
            assert result.exit_code == 1


class TestRecreateCommand:
    """Tests for the recreate CLI command."""

    def create_test_config(self, file_path):
        """Helper to create a test config file."""
        config = configparser.ConfigParser(comment_prefixes=None)
        config.optionxform = str
        config['Interface'] = {
            '# Device': 'TestDevice',
            'PrivateKey': 'test_private_key',
            'Address': '10.65.123.45/32',
            'DNS': '10.64.0.1',
            'Table': '42',
            'PostUp': 'ip -4 route add 10.64.0.1 dev exit & ip -4 route add 193.138.218.74 dev exit'
        }
        config['Peer'] = {
            '# Country': 'Netherlands',
            '# City': 'Amsterdam',
            '# Hostname': 'old-hostname',
            'PublicKey': 'old_public_key',
            'AllowedIPs': '0.0.0.0/0,::0/0',
            'Endpoint': '1.2.3.4:51820'
        }

        with open(file_path, 'w', encoding='utf-8') as config_file:
            config.write(config_file)

    def test_recreate_command_success(self):
        """Test successful config recreation."""
        mock_relays = [
            {
                "hostname": "nl-ams-wg-002",
                "public_key": "new_public_key",
                "ipv4_addr_in": "185.213.154.69"
            }
        ]

        with patch.object(wg_conf_gen, 'ask_mullvad', return_value=mock_relays):
            with patch.object(wg_conf_gen, 'get_random_gateway', return_value=mock_relays[0]):
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                    temp_path = temp_file.name

                try:
                    # Create initial config
                    self.create_test_config(temp_path)

                    runner = CliRunner()
                    result = runner.invoke(cli, ['recreate', '--file', temp_path])

                    assert result.exit_code == 0

                    # Verify config was updated
                    config = configparser.ConfigParser(comment_prefixes=None)
                    config.optionxform = str
                    config.read(temp_path)

                    # Check that values were updated
                    assert config.get('Peer', 'PublicKey') == 'new_public_key'
                    assert config.get('Peer', '# Hostname') == 'nl-ams-wg-002'
                    assert config.get('Peer', 'Endpoint') == '185.213.154.69:51820'

                    # Check that other values remained the same
                    assert config.get('Interface', 'PrivateKey') == 'test_private_key'
                    assert config.get('Peer', '# Country') == 'Netherlands'
                    assert config.get('Peer', '# City') == 'Amsterdam'

                finally:
                    os.unlink(temp_path)

    def test_recreate_command_missing_file(self):
        """Test recreate command with missing config file."""
        runner = CliRunner()
        result = runner.invoke(cli, ['recreate', '--file', '/nonexistent/path'])

        # The command should fail when the config file doesn't exist
        assert result.exit_code != 0
        assert "No section: 'Peer'" in str(result.exception)


class TestCLI:
    """Tests for the CLI interface."""

    def test_cli_help(self):
        """Test CLI help output."""
        runner = CliRunner()
        result = runner.invoke(cli, ['--help'])

        assert result.exit_code == 0
        assert 'WireGuard configuration generator CLI' in result.output

    def test_create_help(self):
        """Test create command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ['create', '--help'])

        assert result.exit_code == 0
        assert 'Creates wireguard config' in result.output

    def test_recreate_help(self):
        """Test recreate command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ['recreate', '--help'])

        assert result.exit_code == 0
        assert 'Regenerates config' in result.output


if __name__ == '__main__':
    pytest.main([__file__])
